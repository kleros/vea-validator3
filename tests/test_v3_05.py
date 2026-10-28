"""V3-05: startup refuses a route whose inbox, outbox (or router) and L1 don't pair."""

from types import SimpleNamespace

import pytest

from vea_challenger import watcher
from vea_challenger.config import BUILTIN_ROUTES, Settings
from vea_challenger.contracts import OutboxParams
from vea_challenger.watcher import startup_checks

from conftest import FakeNotifier

OTHER = "0x00000000000000000000000000000000000000Ee"
PERIOD = 7_200


class FakeClient:
    def __init__(self, chain_id):
        self.chain_id = chain_id

    def with_failover(self, fn):
        return fn(SimpleNamespace(eth=SimpleNamespace(chain_id=self.chain_id)))

    def supports_finalized(self):
        return True


class PairedOutbox:
    def __init__(self, route):
        self.client = FakeClient(route.outbox_chain.chain_id)
        self.upstream = (
            route.router_address if route.kind == "arb_to_gnosis" else route.inbox_address
        )
        self.epoch_period = PERIOD

    def hash_claim_onchain(self, claim):
        return claim.hash()

    def params(self):
        return OutboxParams(deposit=10**18, epoch_period=self.epoch_period,
                            min_challenge_period=10_800, timeout_epochs=100)

    def sequencer_delay_limit(self):
        return 86_400

    def upstream_address(self):
        return self.upstream


class PairedInbox:
    def __init__(self, route):
        self.client = FakeClient(route.inbox_chain.chain_id)
        self.dest = (
            route.router_address if route.kind == "arb_to_gnosis" else route.outbox_address
        )
        self.period = PERIOD

    def destination(self):
        return self.dest

    def epoch_period(self):
        return self.period


class PairedRouter:
    inbox = outbox = None

    def __init__(self, client, address):
        self.client = client

    def endpoints(self):
        return PairedRouter.inbox, PairedRouter.outbox


def make(route_name, monkeypatch):
    route = BUILTIN_ROUTES[route_name].model_copy(deep=True)
    gnosis = route.kind == "arb_to_gnosis"
    PairedRouter.inbox, PairedRouter.outbox = route.inbox_address, route.outbox_address
    monkeypatch.setattr(watcher, "RouterContract", PairedRouter, raising=False)
    return SimpleNamespace(
        route=route,
        settings=Settings(min_challenge_agreement=1),
        notifier=FakeNotifier(),
        outbox=PairedOutbox(route),
        inbox=PairedInbox(route),
        l1_client=FakeClient(route.l1_chain.chain_id) if gnosis else None,
        challenger=None,
    )


ROUTES = ["arb-sepolia-to-sepolia-testnet", "arb-sepolia-to-chiado-testnet"]


@pytest.mark.parametrize("name", ROUTES)
def test_paired_route_passes(name, monkeypatch):
    startup_checks(make(name, monkeypatch))


@pytest.mark.parametrize("name", ROUTES)
def test_wrong_inbox_destination_refused(name, monkeypatch):
    app = make(name, monkeypatch)
    app.inbox.dest = OTHER
    with pytest.raises(SystemExit, match="inbox"):
        startup_checks(app)


@pytest.mark.parametrize("name", ROUTES)
def test_outbox_upstream_mismatch_refused(name, monkeypatch):
    app = make(name, monkeypatch)
    app.outbox.upstream = OTHER
    with pytest.raises(SystemExit, match="outbox"):
        startup_checks(app)


def test_router_pointing_elsewhere_refused(monkeypatch):
    app = make("arb-sepolia-to-chiado-testnet", monkeypatch)
    PairedRouter.inbox = OTHER
    with pytest.raises(SystemExit, match="router"):
        startup_checks(app)
    PairedRouter.inbox, PairedRouter.outbox = app.route.inbox_address, OTHER
    with pytest.raises(SystemExit, match="router"):
        startup_checks(app)


@pytest.mark.parametrize("name", ROUTES)
def test_epoch_period_mismatch_refused(name, monkeypatch):
    app = make(name, monkeypatch)
    app.inbox.period = PERIOD * 2
    with pytest.raises(SystemExit, match="epochPeriod"):
        startup_checks(app)


def test_l1_chain_id_mismatch_refused(monkeypatch):
    app = make("arb-sepolia-to-chiado-testnet", monkeypatch)
    app.l1_client = FakeClient(1)
    with pytest.raises(SystemExit, match="l1 RPC chain id"):
        startup_checks(app)


class _Unreachable:
    """Any use means a manual command got past the route check."""

    def __getattr__(self, name):
        raise AssertionError(f"manual command reached {name} on a mis-paired route")


@pytest.mark.parametrize("command", ["cmd_challenge", "cmd_resolve", "cmd_withdraw"])
def test_manual_commands_refuse_a_mis_paired_route(command, monkeypatch):
    """Panel F3: the one-shot commands that send also run the pairing check."""
    from vea_challenger import cli

    app = make("arb-sepolia-to-sepolia-testnet", monkeypatch)
    app.inbox.dest = OTHER
    app.challenger = app.resolver = _Unreachable()
    app.store = app.detector = _Unreachable()
    with pytest.raises(SystemExit, match="route mismatch"):
        getattr(cli, command)(app, SimpleNamespace(epoch=100, force=True))
