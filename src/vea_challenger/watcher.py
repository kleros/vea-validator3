"""Main orchestration: wiring, startup self-checks, and the polling loop."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field

from eth_account import Account

from .arbitrum import ArbOutboxExecutor
from .chain import ChainClient, redact
from .challenger import Challenger
from .claims import Claim, ZERO_ADDRESS
from .config import RouteCfg, Settings
from .contracts import InboxContract, OutboxContract, RouterContract, WethToken
from .detector import Detector
from .notify import CRITICAL, INFO, WARNING, Notifier
from .resolver import Resolver
from .store import (
    CHALLENGE_PENDING,
    CHALLENGED,
    L1_EXECUTED,
    RESOLVED,
    SEEN,
    SNAPSHOT_SENT,
    UNDECIDED,
    Store,
)
from .txsender import TxSender
from .verdict import Verdict, earliest_verification_ts

log = logging.getLogger(__name__)


@dataclass
class App:
    settings: Settings
    route: RouteCfg
    store: Store
    notifier: Notifier
    outbox: OutboxContract
    inbox: InboxContract
    detector: Detector
    challenger: Challenger | None
    resolver: Resolver | None
    # The L1 (rollup) chain client, only when it differs from the outbox chain
    # (arb_to_gnosis); startup_checks verifies its chain id and the router.
    l1_client: ChainClient | None = None
    # Set by the SIGTERM handler (or any stop request); checked between ticks
    # and between rows, never inside a journal-to-broadcast window.
    stop: threading.Event = field(default_factory=threading.Event)
    stop_reason: str = "SIGTERM"


def build_app(settings: Settings) -> App:
    route = settings.resolve_route()
    store = Store(settings.resolve_db_path())
    notifier = Notifier(settings.webhook_url, route.name)

    outbox_client = ChainClient(route.outbox_chain)
    inbox_client = ChainClient(route.inbox_chain)
    l1_client = (
        outbox_client if route.kind == "arb_to_eth" else ChainClient(route.l1_chain)
    )

    outbox = OutboxContract(outbox_client, route)
    inbox = InboxContract(inbox_client, route)
    params = outbox.params()

    challenge_account = ops_account = None
    if settings.challenge_private_key is not None:
        challenge_account = Account.from_key(
            settings.challenge_private_key.get_secret_value()
        )
        ops_account = challenge_account
    if settings.ops_private_key is not None:
        ops_account = Account.from_key(settings.ops_private_key.get_secret_value())
        if challenge_account is None:
            challenge_account = ops_account
    if (
        challenge_account is not None
        and ops_account is not None
        and challenge_account.address == ops_account.address
    ):
        log.warning(
            "single key configured: slow resolution txs share a nonce lane with "
            "deadline-critical challenges. Set both VEA_CHALLENGE_PRIVATE_KEY and "
            "VEA_OPS_PRIVATE_KEY (different keys) for separate lanes."
        )

    detector = Detector(
        store,
        outbox,
        inbox,
        params,
        notifier,
        challenge_account.address if challenge_account else None,
        route.devnet,
        settings.log_scan_chunk,
        settings.genesis_lookback_blocks,
        settings.min_challenge_agreement,
        settings.challenge_on_ambiguity,
    )

    challenger = resolver = None
    if challenge_account is not None:
        weth = (
            WethToken(outbox_client, route.weth_address)
            if route.weth_address
            else None
        )
        challenger = Challenger(
            store,
            outbox,
            params,
            TxSender(store, outbox_client, challenge_account),
            notifier,
            weth,
            settings.gas_reserve_wei,
            route.devnet,
            settings.dry_run,
        )
        executor = ArbOutboxExecutor(
            l1_client, inbox_client, route.arb_bridge_address, route.arb_outbox_address
        )
        resolver = Resolver(
            store,
            outbox,
            inbox,
            params,
            executor,
            TxSender(store, inbox_client, ops_account),
            TxSender(store, l1_client, ops_account),
            TxSender(store, outbox_client, ops_account),
            notifier,
            challenge_account.address,
            settings.dry_run,
        )

    return App(
        settings=settings,
        route=route,
        store=store,
        notifier=notifier,
        outbox=outbox,
        inbox=inbox,
        detector=detector,
        challenger=challenger,
        resolver=resolver,
        l1_client=l1_client if route.kind == "arb_to_gnosis" else None,
    )


def check_route(app: App) -> None:
    """Chain ids and on-chain pairing of the route's contracts. Every command
    that sends a transaction runs it (startup_checks for run, cli for the
    manual commands), so a mis-paired route can never spend."""
    route = app.route
    for client, label in ((app.inbox.client, "inbox"), (app.outbox.client, "outbox")):
        cid = client.with_failover(lambda w3: w3.eth.chain_id)
        expected = route.inbox_chain.chain_id if label == "inbox" else route.outbox_chain.chain_id
        if cid != expected:
            raise SystemExit(f"{label} RPC chain id {cid} != configured {expected}")
    if app.l1_client is not None:
        cid = app.l1_client.with_failover(lambda w3: w3.eth.chain_id)
        if cid != route.l1_chain.chain_id:
            raise SystemExit(
                f"l1 RPC chain id {cid} != configured {route.l1_chain.chain_id}"
            )
    _check_pairing(app)


def startup_checks(app: App, *, read_only: bool = False) -> None:
    """Fail fast on anything that would silently corrupt verdicts later.

    read_only (`scan`): run every check but never send a transaction.
    """
    route = app.route

    if len(route.inbox_chain.rpc_urls) < 2:
        raise SystemExit(
            "verdicts require at least 2 independent inbox-chain RPCs "
            "(set VEA_INBOX_RPC_URLS with two or more providers)"
        )

    agreement = app.settings.min_challenge_agreement
    if agreement < 1 or agreement > len(route.inbox_chain.rpc_urls):
        raise SystemExit(
            f"min_challenge_agreement={agreement} must be between 1 and the number "
            f"of configured inbox RPCs ({len(route.inbox_chain.rpc_urls)})"
        )

    check_route(app)

    if not app.inbox.client.supports_finalized():
        raise SystemExit(
            "inbox chain RPC does not serve a genuine 'finalized' tag; "
            "verdicts would be unsafe. Configure an RPC with finality support."
        )

    # hashClaim parity: local implementation vs contract, on a synthetic struct.
    probe = Claim(
        state_root=b"\x11" * 32,
        claimer="0x00000000000000000000000000000000000000A1",
        timestamp_claimed=1_700_000_001,
        timestamp_verification=1_700_000_002,
        blocknumber_verification=12_345,
        honest=1,
        challenger="0x00000000000000000000000000000000000000B2",
    )
    onchain = app.outbox.hash_claim_onchain(probe)
    if onchain != probe.hash():
        raise SystemExit(
            "hashClaim parity check FAILED: local packed encoding differs from the "
            f"contract ({onchain.hex()} != {probe.hash().hex()})"
        )

    params = app.outbox.params()
    log.info(
        "route %s: deposit=%s wei epochPeriod=%ss minChallengePeriod=%ss "
        "sequencerDelayLimit=%ss devnet=%s",
        route.name,
        params.deposit,
        params.epoch_period,
        params.min_challenge_period,
        app.outbox.sequencer_delay_limit(),
        route.devnet,
    )

    if app.challenger is None:
        app.notifier.send(
            WARNING, "no private key configured: watch-only mode (detect + alert)"
        )
    elif not app.settings.dry_run:
        if not app.challenger.can_fund_challenge():
            app.notifier.send(
                CRITICAL,
                "challenge account cannot fund a single deposit + gas reserve; "
                "the bot can only alert until funded",
            )
        if not read_only:
            app.challenger.ensure_allowance()


def _same(a: str | None, b: str | None) -> bool:
    return a is not None and b is not None and a.lower() == b.lower()


def _check_pairing(app: App) -> None:
    """The route's inbox, outbox (and router) must name each other on-chain and
    share one epochPeriod; else verdicts would come from the wrong inbox/epoch."""
    route = app.route
    gnosis = route.kind == "arb_to_gnosis"
    # The inbox's L1 destination: the outbox (ArbToEth) or the router (ArbToGnosis).
    target, target_label = (
        (route.router_address, "router") if gnosis else (route.outbox_address, "outbox")
    )
    if target is None:
        raise SystemExit(f"route {route.name}: {target_label} address is not configured")
    dest = app.inbox.destination()
    if not _same(dest, target):
        raise SystemExit(
            f"route mismatch: inbox {route.inbox_address} sends to {dest}, "
            f"not the configured {target_label} {target}"
        )
    upstream = app.outbox.upstream_address()
    expected = route.router_address if gnosis else route.inbox_address
    if not _same(upstream, expected):
        raise SystemExit(
            f"route mismatch: outbox {route.outbox_address} trusts {upstream}, "
            f"not the configured {'router' if gnosis else 'inbox'} {expected}"
        )
    if gnosis:
        r_inbox, r_outbox = RouterContract(app.l1_client, route.router_address).endpoints()
        if not (_same(r_inbox, route.inbox_address) and _same(r_outbox, route.outbox_address)):
            raise SystemExit(
                f"route mismatch: router {route.router_address} pairs inbox {r_inbox} "
                f"/ outbox {r_outbox}, not the configured {route.inbox_address} "
                f"/ {route.outbox_address}"
            )
    inbox_period = app.inbox.epoch_period()
    outbox_period = app.outbox.params().epoch_period
    if inbox_period != outbox_period:
        raise SystemExit(
            f"route mismatch: inbox epochPeriod {inbox_period}s != outbox "
            f"epochPeriod {outbox_period}s"
        )


DEADLINE_WARN_SECS = 4 * 3600
DEADLINE_CRIT_SECS = 3600
ROW_ERROR_INTERVAL = 3600
ALERT_INTERVAL = 3600  # a page that could repeat every tick is sent hourly at most
LIVENESS_INTERVAL = 24 * 3600
SHUTDOWN_PCTS = (50, 75, 90)


def _fmt_secs(secs: int) -> str:
    secs = int(secs)
    if abs(secs) >= 86_400:
        return f"{secs / 86_400:.1f} days"
    if abs(secs) >= 3_600:
        return f"{secs / 3_600:.1f} h"
    return f"{secs} s"


def alert_hourly(app: App, key: str, level: str, message: str) -> None:
    """Send `message` unless `key` was already sent within ALERT_INTERVAL."""
    now = int(time.time())
    sent = app.store.alert_sent(key)
    if sent is not None and now - sent < ALERT_INTERVAL:
        return
    app.store.mark_alert(key, now)
    app.notifier.send(level, message)


def check_deadlines(app: App, rows) -> None:
    """PRD 1.1: warn before an undecided or not-yet-challenged fraud claim can be
    verified (non-devnet only). CHALLENGE_PENDING rows are detected frauds whose
    challenge has not landed (failing or stuck sends)."""
    if app.route.devnet:
        return
    undecided = [r for r in rows if r.status in (SEEN, UNDECIDED, CHALLENGE_PENDING)]
    if not undecided:
        return
    now = app.outbox.now()
    params = app.detector.params
    seq_delay = app.outbox.sequencer_delay_limit()
    for row in undecided:
        deadline = earliest_verification_ts(
            row.claim.timestamp_claimed,
            params.epoch_period,
            seq_delay,
            params.min_challenge_period,
            app.route.devnet,
        )
        left = deadline - now
        reason = row.note or "undecided: no reason recorded"
        if row.status == CHALLENGE_PENDING:
            text = (
                f"FRAUD for epoch {row.epoch} not challenged yet (challenge pending): "
                f"{row.note or 'no attempt recorded'}; {left} s left"
            )
        elif reason.startswith("fraud:"):
            text = f"FRAUD for epoch {row.epoch} not challenged yet: {reason}; {left} s left"
        else:
            text = (
                f"epoch {row.epoch} is still undecided {left} s "
                f"({_fmt_secs(left)}) before it can be verified: {reason}"
            )
        for level, window, tag in (
            (WARNING, DEADLINE_WARN_SECS, "4h"),
            (CRITICAL, DEADLINE_CRIT_SECS, "1h"),
        ):
            key = f"deadline:{row.epoch}:{tag}"
            if left <= window and app.store.alert_sent(key) is None:
                app.store.mark_alert(key, now)
                app.notifier.send(level, text)


def bridge_countdown(app: App) -> tuple[int, int, int]:
    """(epochs_since_verified, timeout_epochs, epoch_period) from the outbox clock."""
    params = app.detector.params
    since = app.outbox.now() // params.epoch_period - app.outbox.latest_verified_epoch()
    return since, params.timeout_epochs, params.epoch_period


def check_shutdown_countdown(app: App) -> None:
    """PRD 3.3: warn as the bridge nears its timeout shutdown (every mode)."""
    since, timeout, period = bridge_countdown(app)
    latest = app.outbox.latest_verified_epoch()
    if app.store.alert_sent("shutdown:lve") != latest:
        app.store.clear_alerts("shutdown:")
        app.store.mark_alert("shutdown:lve", latest)
    for pct in SHUTDOWN_PCTS:
        key = f"shutdown:{latest}:{pct}"
        if since * 100 >= timeout * pct and app.store.alert_sent(key) is None:
            app.store.mark_alert(key, app.outbox.now())
            left = max(0, timeout - since)
            app.notifier.send(
                WARNING if pct == 50 else CRITICAL,
                f"bridge shutdown countdown at {pct}%: {since} of {timeout} epochs "
                f"since the last verified claim (epoch {latest}); {left} epochs "
                f"(~{_fmt_secs(left * period)}) left. A claim must be made and "
                "verified before then",
            )


def last_claim_ts(app: App) -> int | None:
    """Newest tracked timestamp_claimed, else the first tick's time (liveness:start)."""
    claims = [r.claim.timestamp_claimed for r in app.store.all_claims()]
    if claims:
        return max(claims)
    return app.store.alert_sent("liveness:start")


def check_liveness(app: App) -> None:
    """PRD 3.3: warn when no claim was seen for liveness_epochs (never on devnet)."""
    n = app.settings.liveness_epochs
    if not n or app.route.devnet:
        return
    now = app.outbox.now()
    if app.store.alert_sent("liveness:start") is None:
        app.store.mark_alert("liveness:start", now)
    last = last_claim_ts(app)
    if last is None:
        return
    if now - last < n * app.detector.params.epoch_period:
        return
    sent = app.store.alert_sent("liveness:no-claim")
    if sent is not None and now - sent < LIVENESS_INTERVAL:
        return
    app.store.mark_alert("liveness:no-claim", now)
    app.notifier.send(
        WARNING,
        f"no claim for {n} epochs — quiet bridge, stale address or wrong route",
    )


def _row_error(app: App, row, exc: Exception) -> None:
    log.exception("epoch %s: processing failed", row.epoch)
    key = f"row-error:{row.epoch}"
    now = int(time.time())
    sent = app.store.alert_sent(key)
    if sent is None or now - sent >= ROW_ERROR_INTERVAL:
        app.store.mark_alert(key, now)
        app.notifier.send(
            CRITICAL,
            f"epoch {row.epoch}: processing failed ({type(exc).__name__}: {exc}); "
            "other claims continue",
        )


def _process_row(app: App, row) -> None:
    reconciled = app.detector.reconcile(row)
    if reconciled is None:
        return
    row = reconciled
    if row.status in (SEEN, UNDECIDED):
        verdict = app.detector.evaluate(row)
        if verdict == Verdict.CHALLENGE:
            alert_hourly(
                app,
                f"fraud:{row.epoch}",
                CRITICAL,
                f"FRAUDULENT CLAIM epoch {row.epoch}: claimed "
                f"0x{row.claim.state_root.hex()} true {row.true_root}",
            )
            if app.challenger is not None:
                app.challenger.challenge(row)
            else:
                alert_hourly(
                    app,
                    f"watch-only:{row.epoch}",
                    CRITICAL,
                    f"watch-only mode: CANNOT challenge epoch {row.epoch} — intervene now",
                )
    elif row.status == CHALLENGE_PENDING and app.challenger is not None:
        # A previous attempt failed or is stuck: retry every tick (with
        # same-nonce fee replacement) until Challenged lands or the
        # detector moves the row (front-run, verified, ...).
        app.challenger.challenge(row)


def _guarded(name: str, fn, *args) -> None:
    try:
        fn(*args)
    except Exception:  # noqa: BLE001 - a monitor must not stop the tick
        log.exception("%s failed", name)


def tick(app: App) -> None:
    try:
        app.detector.sync_events()
    except Exception as exc:  # noqa: BLE001 - tracked rows and monitors still run
        log.exception("event scan failed")
        alert_hourly(
            app,
            "sync-failed",
            CRITICAL,
            f"event scan failing: {redact(f'{type(exc).__name__}: {exc}')}",
        )

    rows = app.store.active_claims()
    for row in rows:
        if app.stop.is_set():
            return
        try:
            _process_row(app, row)
        except Exception as exc:  # noqa: BLE001 - one row must not block the rest
            _row_error(app, row, exc)

    _guarded("deadline alerts", check_deadlines, app, app.store.active_claims())
    _guarded("shutdown countdown", check_shutdown_countdown, app)
    _guarded("liveness check", check_liveness, app)

    if app.resolver is not None and not app.stop.is_set():
        active = [
            r
            for r in app.store.active_claims()
            if r.status in (CHALLENGED, SNAPSHOT_SENT, L1_EXECUTED, RESOLVED)
        ]
        if active and app.resolver.bridge_shutdown():
            for row in active:
                if app.stop.is_set():
                    break
                try:
                    if row.status == RESOLVED:
                        # Already ruled in our favor: withdrawChallengeDeposit
                        # has no OnlyBridgeRunning guard and pays the reward.
                        app.resolver.withdraw(row)
                    else:
                        app.resolver.escape_hatch(row)
                except Exception:  # noqa: BLE001 - one row must not block the rest
                    log.exception("shutdown handling failed for epoch %s", row.epoch)
        else:
            app.resolver.tick(active)


def providers_path(settings: Settings):
    """Where `run` publishes provider health for `status`: <db path>.providers.json."""
    db = settings.resolve_db_path()
    return db.with_name(db.name + ".providers.json")


def write_provider_stats(app: App) -> None:
    """Atomically publish the inbox and outbox clients' provider counters."""
    data = {
        "ts": time.time(),
        "providers": {
            name: [
                {
                    "label": st.label,
                    "failures": st.failures,
                    "quorum_disagreements": st.quorum_disagreements,
                    "last_error_ts": st.last_error_ts,
                }
                for st in client.provider_stats()
            ]
            for name, client in (("inbox", app.inbox.client), ("outbox", app.outbox.client))
        },
    }
    path = providers_path(app.settings)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, path)


def run_loop(app: App) -> None:
    startup_checks(app)
    app.notifier.send(
        INFO,
        f"watcher started (route={app.route.name}, dry_run={app.settings.dry_run})",
    )
    while not app.stop.is_set():
        started = time.monotonic()
        try:
            tick(app)
        except Exception:  # noqa: BLE001 - the loop must survive anything transient
            log.exception("tick failed")
        else:
            log.info(
                "tick complete in %.1fs: %d active claim(s), outbox cursor at block %s",
                time.monotonic() - started,
                len(app.store.active_claims()),
                app.store.get_cursor("outbox_events"),
            )
        _guarded("provider stats", write_provider_stats, app)
        elapsed = time.monotonic() - started
        app.stop.wait(max(1.0, app.settings.poll_interval - elapsed))
    app.notifier.send(INFO, f"watcher stopping ({app.stop_reason})")
