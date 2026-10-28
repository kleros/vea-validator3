"""Command-line interface.

    vea-challenger run                     # the long-running watcher/challenger
    vea-challenger status                  # tracked claims + balances
    vea-challenger scan                    # one detection pass, no txs
    vea-challenger challenge --epoch N     # manual challenge (after your own check!)
    vea-challenger resolve --epoch N       # push a challenged epoch forward
    vea-challenger withdraw --epoch N      # withdraw a won deposit
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import time
import sys

from .chain import install_log_redaction, redact
from .config import BUILTIN_ROUTES, Settings
from .notify import CRITICAL
from .store import CHALLENGED, L1_EXECUTED, RESOLVED, SNAPSHOT_SENT
from .verdict import Verdict
from .watcher import (
    App,
    bridge_countdown,
    build_app,
    check_route,
    last_claim_ts,
    providers_path,
    run_loop,
    startup_checks,
)


def _setup_logging(json_mode: bool) -> None:
    fmt = (
        '{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}'
        if json_mode
        else "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
    )
    logging.basicConfig(level=logging.INFO, format=fmt, stream=sys.stdout)
    logging.getLogger("web3").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def cmd_run(app: App, _args: argparse.Namespace) -> int:
    run_loop(app)
    return 0


def _print_provider_health(app: App) -> None:
    """Provider counters live in the `run` process; it publishes them to a file."""
    try:
        data = json.loads(providers_path(app.settings).read_text())
        age = max(0, int(time.time() - float(data["ts"])))
        groups = data["providers"]
    except (OSError, ValueError, KeyError, TypeError):
        print("\nno provider stats yet (is run active?)")
        return
    print(f"\nprovider health (from run, {age} s ago):")
    for name, stats in groups.items():
        for st in stats:
            print(
                f"  {name} {st['label']}: failures={st['failures']} "
                f"quorum_disagreements={st['quorum_disagreements']} "
                f"last_error_ts={st['last_error_ts']}"
            )


def cmd_status(app: App, _args: argparse.Namespace) -> int:
    rows = app.store.all_claims()
    if not rows:
        print("no claims tracked yet")
    for r in rows:
        print(
            f"epoch {r.epoch}: {r.status}"
            f"  root=0x{r.claim.state_root.hex()[:16]}…"
            f"  claimer={r.claim.claimer}"
            + (f"  challenger={r.claim.challenger}" if r.claim.challenger != "0x" + "0" * 40 else "")
            + (f"  true={r.true_root[:18]}…" if r.true_root else "")
            + (f"  note={redact(r.note)}" if r.note else "")
        )
    _print_provider_health(app)
    try:
        since, timeout, period = bridge_countdown(app)
        print(
            f"\nbridge: {since} of {timeout} epochs since last verified claim "
            f"(~{max(0, timeout - since) * period}s to shutdown)"
        )
        last = last_claim_ts(app)
        print(f"last claim seen at: {last if last is not None else 'unknown'}")
    except Exception as exc:  # noqa: BLE001 - status must work with a flaky RPC
        print(f"\nbridge liveness unavailable: {type(exc).__name__}")
    if app.challenger is not None:
        addr = app.challenger.sender.address
        bal = app.outbox.client.with_failover(lambda w3: w3.eth.get_balance(addr))
        print(f"\nchallenge account {addr}: {bal / 10**18:.6f} native on {app.outbox.client.name}")
        if app.challenger.weth is not None:
            wbal = app.challenger.weth.balance_of(addr)
            print(f"  WETH: {wbal / 10**18:.6f}")
        print(f"deposit required: {app.challenger.params.deposit / 10**18:.6f}")
    return 0


def cmd_scan(app: App, _args: argparse.Namespace) -> int:
    startup_checks(app, read_only=True)
    app.detector.sync_events()
    for row in app.store.active_claims():
        row = app.detector.reconcile(row) or row
        if row.status in ("SEEN", "UNDECIDED"):
            verdict = app.detector.evaluate(row)
            print(f"epoch {row.epoch}: verdict={verdict.value}")
    return cmd_status(app, _args)


def _load_row(app: App, epoch: int):
    row = app.store.get_claim(epoch)
    if row is None:
        raise SystemExit(f"epoch {epoch} is not tracked (run `scan` first)")
    row = app.detector.reconcile(row)
    if row is None:
        raise SystemExit(f"epoch {epoch}: claim hash gone (already withdrawn)")
    return row


def cmd_challenge(app: App, args: argparse.Namespace) -> int:
    if app.challenger is None:
        raise SystemExit("no private key configured")
    check_route(app)
    row = _load_row(app, args.epoch)
    verdict = app.detector.evaluate(row)
    if verdict != Verdict.CHALLENGE and not args.force:
        raise SystemExit(
            f"verdict for epoch {args.epoch} is {verdict.value!r}, not challengeable "
            "(use --force only if you know better than the verdict logic)"
        )
    ok = app.challenger.challenge(row)
    print("challenged" if ok else "challenge not sent (see logs)")
    return 0 if ok else 1


def cmd_resolve(app: App, args: argparse.Namespace) -> int:
    if app.resolver is None:
        raise SystemExit("no private key configured")
    check_route(app)
    row = _load_row(app, args.epoch)
    if row.status not in (CHALLENGED, SNAPSHOT_SENT, L1_EXECUTED):
        raise SystemExit(f"epoch {args.epoch} is {row.status}; nothing to resolve")
    app.resolver.tick([row])
    print(f"epoch {args.epoch}: now {app.store.get_claim(args.epoch).status}")
    return 0


def cmd_withdraw(app: App, args: argparse.Namespace) -> int:
    if app.resolver is None:
        raise SystemExit("no private key configured")
    check_route(app)
    row = _load_row(app, args.epoch)
    if row.status != RESOLVED:
        raise SystemExit(f"epoch {args.epoch} is {row.status}, not RESOLVED")
    app.resolver.withdraw(row)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vea-challenger",
        description="Independent challenger bot for the Vea optimistic bridge.",
    )
    parser.add_argument(
        "--route",
        help=f"route name ({', '.join(sorted(BUILTIN_ROUTES))}) or set VEA_ROUTE",
    )
    parser.add_argument("--dry-run", action="store_true", help="never send transactions")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("run", help="run the watcher/challenger loop")
    sub.add_parser("status", help="print tracked claims and balances")
    sub.add_parser("scan", help="one detection pass (no transactions)")
    p = sub.add_parser("challenge", help="manually challenge an epoch")
    p.add_argument("--epoch", type=int, required=True)
    p.add_argument("--force", action="store_true")
    p = sub.add_parser("resolve", help="advance resolution for an epoch")
    p.add_argument("--epoch", type=int, required=True)
    p = sub.add_parser("withdraw", help="withdraw a won challenge deposit")
    p.add_argument("--epoch", type=int, required=True)

    args = parser.parse_args(argv)

    overrides = {}
    if args.route:
        overrides["route"] = args.route
    if args.dry_run:
        overrides["dry_run"] = True
    settings = Settings(**overrides)
    _setup_logging(settings.log_json)
    install_log_redaction()

    app = build_app(settings)

    if args.command == "run":
        # Only `run` checks app.stop; the one-shot commands keep the default
        # SIGTERM action (terminate) so a hung RPC call cannot ignore it.
        def _on_sigterm(_signum, _frame) -> None:
            # Only flag the request: the loop checks it between ticks and rows,
            # so a tx is never cut off between journaling and broadcast.
            app.stop_reason = "SIGTERM"
            app.stop.set()

        signal.signal(signal.SIGTERM, _on_sigterm)
    try:
        handler = {
            "run": cmd_run,
            "status": cmd_status,
            "scan": cmd_scan,
            "challenge": cmd_challenge,
            "resolve": cmd_resolve,
            "withdraw": cmd_withdraw,
        }[args.command]
        return handler(app, args)
    except KeyboardInterrupt:
        return 130
    finally:
        app.store.close()


if __name__ == "__main__":
    raise SystemExit(main())
