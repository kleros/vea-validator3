"""Resolver: --dry-run sends nothing on the manual lifecycle commands."""

from types import SimpleNamespace

from vea_challenger.claims import Claim, Party
from vea_challenger.config import BUILTIN_ROUTES
from vea_challenger.resolver import Resolver
from vea_challenger.store import RESOLVED, ClaimRow, Store

from conftest import FakeNotifier

CLAIMER = "0x00000000000000000000000000000000000000A1"
US = "0x00000000000000000000000000000000000000C3"
EPOCH = 100


class RecordingSender:
    def __init__(self):
        self.sent: list[str] = []

    def send(self, fn, *, epoch, action, **_):
        self.sent.append(action)
        return {"transactionHash": SimpleNamespace(to_0x_hex=lambda: "0xw")}


def test_dry_run_withdraw_sends_nothing(tmp_path):
    store = Store(tmp_path / "t.db")
    fns = SimpleNamespace(withdrawChallengeDeposit=lambda epoch, tup: ("withdraw", epoch, tup))
    outbox = SimpleNamespace(contract=lambda: SimpleNamespace(functions=fns))
    sender = RecordingSender()
    resolver = Resolver(
        store=store, outbox=outbox,
        inbox=SimpleNamespace(route=BUILTIN_ROUTES["arb-sepolia-to-sepolia-testnet"]),
        params=None, executor=None, l2_sender=None, l1_sender=None, outbox_sender=sender,
        notifier=FakeNotifier(), challenge_address=US, dry_run=True,
    )
    won = Claim(b"\xaa" * 32, CLAIMER, 1_000, 2_000, 50, Party.CHALLENGER, US)
    row = ClaimRow(epoch=EPOCH, status=RESOLVED, claim=won)
    store.upsert_claim(row)
    resolver.withdraw(row)
    assert sender.sent == []
    got = store.get_claim(EPOCH)
    assert got.status == RESOLVED and got.withdraw_tx is None
