"""CLI: SIGTERM shutdown through main(), status output."""

import logging
import os
import signal
import subprocess
import sys
import textwrap
import time
from types import SimpleNamespace

import json

import pytest

from vea_challenger import cli, watcher
from vea_challenger.chain import ChainClient, ProviderStats
from vea_challenger.chain import RedactingFilter
from vea_challenger.claims import Claim
from vea_challenger.config import ChainCfg, Settings
from vea_challenger.store import UNDECIDED, ClaimRow

CHILD = textwrap.dedent(
    """
    import sys
    from pathlib import Path
    from vea_challenger import cli, watcher
    from vea_challenger.config import BUILTIN_ROUTES
    from vea_challenger.notify import Notifier
    from vea_challenger.store import Store
    from vea_challenger.watcher import App

    marker = Path(sys.argv[1])

    def fake_build_app(settings):
        store = Store(settings.resolve_db_path())
        orig = store.close
        def close():
            marker.write_text("closed")
            orig()
        store.close = close
        return App(settings=settings, route=BUILTIN_ROUTES[settings.route],
                   store=store, notifier=Notifier(None, "t"), outbox=None,
                   inbox=None, detector=None, challenger=None, resolver=None)

    def fake_tick(app):
        print("TICK", flush=True)

    cli.build_app = fake_build_app
    watcher.startup_checks = lambda app: None
    watcher.tick = fake_tick
    raise SystemExit(cli.main(["run"]))
    """
)


def test_sigterm_stops_run_cleanly(tmp_path):
    marker = tmp_path / "closed"
    env = dict(
        os.environ,
        VEA_DB_PATH=str(tmp_path / "x.db"),
        VEA_POLL_INTERVAL="30",
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", CHILD, str(marker)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env,
        cwd=tmp_path,
    )
    try:
        lines = []
        for line in proc.stdout:
            lines.append(line)
            if line.startswith("TICK"):
                break
        else:
            raise AssertionError("child never ticked: " + "".join(lines))
        start = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        rest, _ = proc.communicate(timeout=15)
        assert time.monotonic() - start < 30
        assert proc.returncode == 0, "".join(lines) + rest
    finally:
        if proc.poll() is None:
            proc.kill()
    assert marker.read_text() == "closed"
    assert "watcher stopping (SIGTERM)" in rest


def test_status_prints_provider_labels(capsys, tmp_path):
    def client(name):
        c = ChainClient(ChainCfg(name=name, chain_id=1, rpc_urls=["https://h1.example/KEY123456", "https://h2.example/KEY654321"]))
        c._stats[1] = ProviderStats(label=c.labels[1], failures=3, quorum_disagreements=1, last_error_ts=42.0)
        return c

    inbox, outbox = client("arb"), client("eth")
    app = SimpleNamespace(
        settings=Settings(db_path=tmp_path / "x.db"),
        store=SimpleNamespace(all_claims=lambda: [], alert_sent=lambda k: None),
        challenger=None,
        inbox=SimpleNamespace(client=inbox),
        outbox=SimpleNamespace(client=outbox, now=lambda: 7_200 * 30, latest_verified_epoch=lambda: 10),
        detector=SimpleNamespace(params=SimpleNamespace(epoch_period=7_200, timeout_epochs=100)),
    )
    assert cli.cmd_status(app, None) == 0
    out = capsys.readouterr().out
    assert "no provider stats yet (is run active?)" in out
    assert "failures=3" not in out  # this process's counters are not the run process's
    assert "last claim seen at: unknown" in out

    watcher.write_provider_stats(app)  # what `run` does each tick
    assert cli.cmd_status(app, None) == 0
    out = capsys.readouterr().out
    assert "provider health (from run, " in out and " s ago)" in out
    for label in inbox.labels + outbox.labels:
        assert label in out
    assert "failures=3" in out and "quorum_disagreements=1" in out and "last_error_ts=42.0" in out
    assert "20 of 100 epochs" in out
    assert "KEY123456" not in out


def _app(tmp_path, rows=(), **kw):
    c = ChainClient(ChainCfg(name="eth", chain_id=1, rpc_urls=["https://h1.example/KEY123456"]))
    return SimpleNamespace(
        settings=Settings(db_path=tmp_path / "x.db"),
        store=SimpleNamespace(
            all_claims=lambda: list(rows), alert_sent=lambda k: None, close=lambda: None
        ),
        challenger=None,
        inbox=SimpleNamespace(client=c),
        outbox=SimpleNamespace(
            client=c, now=lambda: 7_200 * 30, latest_verified_epoch=lambda: 10
        ),
        detector=SimpleNamespace(params=SimpleNamespace(epoch_period=7_200, timeout_epochs=100)),
        stop=SimpleNamespace(set=lambda: None, is_set=lambda: True),
        **kw,
    )


def test_status_prints_the_liveness_line(capsys, tmp_path):
    claim = Claim(state_root=b"\xaa" * 32, claimer="0x" + "11" * 20, timestamp_claimed=123_456)
    app = _app(tmp_path, rows=[ClaimRow(epoch=1, status=UNDECIDED, claim=claim)])
    app.store.alert_sent = lambda k: None
    assert cli.cmd_status(app, None) == 0
    out = capsys.readouterr().out
    assert "last claim seen at: 123456" in out


def test_status_redacts_notes(capsys, tmp_path):
    claim = Claim(state_root=b"\xaa" * 32, claimer="0x" + "11" * 20, timestamp_claimed=1)
    row = ClaimRow(
        epoch=1, status=UNDECIDED, claim=claim,
        note="challenge attempt failed: 429 for url: https://h1.example/KEY123456",
    )
    app = _app(tmp_path, rows=[row])
    cli.cmd_status(app, None)
    out = capsys.readouterr().out
    assert "KEY123456" not in out and "note=challenge attempt failed" in out
    assert app.inbox.client.labels[0] in out


def test_run_loop_publishes_provider_stats_each_tick(tmp_path, monkeypatch):
    app = _app(tmp_path)
    app.notifier = SimpleNamespace(send=lambda *a: None)
    app.route = SimpleNamespace(name="t")
    app.settings = Settings(db_path=tmp_path / "x.db", poll_interval=0.01)
    app.stop = __import__("threading").Event()
    app.stop_reason = "test"
    app.store.get_cursor = lambda n: None
    app.store.active_claims = lambda: []
    monkeypatch.setattr(watcher, "startup_checks", lambda a: None)
    monkeypatch.setattr(watcher, "tick", lambda a: a.stop.set())
    watcher.run_loop(app)
    path = tmp_path / "x.db.providers.json"
    data = json.loads(path.read_text())
    assert data["ts"] > 0
    assert data["providers"]["inbox"][0]["label"] == app.inbox.client.labels[0]
    assert not (tmp_path / "x.db.providers.json.tmp").exists()


@pytest.mark.parametrize("command, installed", [("run", True), ("status", False), ("scan", False)])
def test_sigterm_handler_is_installed_for_run_only(monkeypatch, tmp_path, command, installed):
    seen = {}
    previous = signal.getsignal(signal.SIGTERM)

    def handler(app, args):
        seen["handler"] = signal.getsignal(signal.SIGTERM)
        return 0

    monkeypatch.setattr(cli, "build_app", lambda settings: _app(tmp_path))
    monkeypatch.setattr(cli, {"run": "cmd_run", "status": "cmd_status", "scan": "cmd_scan"}[command], handler)
    monkeypatch.setenv("VEA_DB_PATH", str(tmp_path / "x.db"))
    try:
        assert cli.main([command]) == 0
    finally:
        signal.signal(signal.SIGTERM, previous)
    if installed:
        assert seen["handler"] not in (signal.SIG_DFL, previous)
    else:
        assert seen["handler"] == previous  # untouched: the default action stays


def test_main_installs_the_redacting_filter_on_root_handlers(monkeypatch, tmp_path):
    root = logging.getLogger()
    handlers = list(root.handlers)
    for h in handlers:
        h.filters = [f for f in h.filters if not isinstance(f, RedactingFilter)]
    monkeypatch.setattr(cli, "build_app", lambda settings: _app(tmp_path))
    monkeypatch.setattr(cli, "cmd_status", lambda app, args: 0)
    monkeypatch.setenv("VEA_DB_PATH", str(tmp_path / "x.db"))
    assert cli.main(["status"]) == 0
    assert root.handlers
    assert all(any(isinstance(f, RedactingFilter) for f in h.filters) for h in root.handlers)
