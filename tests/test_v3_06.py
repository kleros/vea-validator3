"""V3-06: `scan` is read-only; its startup checks must never send a tx."""

from types import SimpleNamespace

from vea_challenger import cli
from vea_challenger.watcher import startup_checks

from test_v3_05 import make


class RecordingChallenger:
    """A funded key on a Gnosis (WETH) route whose allowance is too low."""

    def __init__(self):
        self.sent = []

    def can_fund_challenge(self):
        return True

    def ensure_allowance(self):
        self.sent.append("weth_approve")


def gnosis_app(monkeypatch):
    app = make("arb-sepolia-to-chiado-testnet", monkeypatch)
    app.challenger = RecordingChallenger()
    return app


def test_scan_never_sends_an_approve(monkeypatch):
    app = gnosis_app(monkeypatch)
    app.detector = SimpleNamespace(sync_events=lambda: None)
    app.store = SimpleNamespace(active_claims=lambda: [])
    monkeypatch.setattr(cli, "cmd_status", lambda a, args: 0)
    assert cli.cmd_scan(app, SimpleNamespace()) == 0
    assert app.challenger.sent == []


def test_read_only_startup_checks_skip_allowance(monkeypatch):
    app = gnosis_app(monkeypatch)
    startup_checks(app, read_only=True)
    assert app.challenger.sent == []


def test_run_startup_checks_still_approve(monkeypatch):
    app = gnosis_app(monkeypatch)
    startup_checks(app)
    assert app.challenger.sent == ["weth_approve"]
