"""V3-03: replacing a stuck challenge tx (same nonce, fees bumped past the original)."""

import sqlite3
from types import SimpleNamespace

from vea_challenger.chain import Eip1559Fees
from vea_challenger.challenger import Challenger
from vea_challenger.claims import Claim
from vea_challenger.store import CHALLENGE_PENDING, ClaimRow, Store
from vea_challenger.txsender import TxSender

from conftest import FakeNotifier, FakeOutbox

US = "0x00000000000000000000000000000000000000C3"
CLAIMER = "0x00000000000000000000000000000000000000A1"
EPOCH = 100
TS = (EPOCH + 1) * 7_200 + 60
FLOOR = 50_000_000  # the 0.05 gwei priority-fee floor in ChainClient.fees


class GethLikeChain:
    """ChainClient stand-in whose mempool applies geth's replacement rule: a tx at
    a pending nonce is replaced only if both fee caps rise by at least 10%."""

    name = "outbox"
    cfg = SimpleNamespace(chain_id=11155111)

    def __init__(self, nonce=7):
        self.confirmed = nonce  # mined nonce: nothing of ours has been mined yet
        self.pending = nonce
        self.mempool: dict[int, dict] = {}
        self.attempts: list[dict] = []  # every signed tx handed to send_signed
        self.broadcast_error: Exception | None = None
        self.fees_error: Exception | None = None
        self.market = 1  # fee level multiplier
        self.lose_response = False  # accept into the mempool, then fail the request

    def fees(self, urgency=1.0):
        if self.fees_error is not None:
            raise self.fees_error
        # Flat market: the priority fee sits on the floor whatever the urgency.
        return Eip1559Fees(max_fee_per_gas=(int(1_000_000_000 * urgency) + FLOOR) * self.market,
                           max_priority_fee_per_gas=FLOOR * self.market)

    def pending_nonce(self, address):
        return self.pending

    def send_signed(self, account, tx):
        self.attempts.append(tx)
        if self.broadcast_error is not None:
            raise self.broadcast_error
        old = self.mempool.get(tx["nonce"])
        if old is not None and any(
            tx[k] * 100 < old[k] * 110 for k in ("maxFeePerGas", "maxPriorityFeePerGas")
        ):
            raise ValueError("replacement transaction underpriced")
        self.mempool[tx["nonce"]] = tx
        self.pending = max(self.pending, tx["nonce"] + 1)
        if self.lose_response:
            raise TimeoutError("request timed out after the node accepted it")
        return "0x%064x" % len(self.attempts)

    def wait_receipt(self, tx_hash, timeout=300.0):
        raise TimeoutError("not mined")  # fees stay high: every tx is stuck

    def receipt_or_none(self, tx_hash):
        return None

    def with_failover(self, fn):
        eth = SimpleNamespace(
            get_balance=lambda a: 10**30,
            get_transaction_count=lambda a, *_: self.confirmed,
        )
        return fn(SimpleNamespace(eth=eth))


class ChallengeOutbox(FakeOutbox):
    address = "0xOutbox"

    def contract(self):
        fn = SimpleNamespace(call=lambda p: None,
                             build_transaction=lambda p: dict(p, gas=100_000))
        return SimpleNamespace(functions=SimpleNamespace(challenge=lambda e, t: fn))


def _rig(tmp_path, params):
    store = Store(tmp_path / "t.db")
    outbox = ChallengeOutbox()
    claim = Claim(state_root=b"\xaa" * 32, claimer=CLAIMER, timestamp_claimed=TS)
    outbox.claim_hashes[EPOCH] = claim.hash()
    outbox._now = TS + 10**6  # past the deadline: urgency is already at its max
    chain = GethLikeChain()
    sender = TxSender(store, chain, SimpleNamespace(address=US))
    ch = Challenger(store, outbox, params, sender, FakeNotifier(), weth=None,
                    gas_reserve_wei=1, devnet=False, dry_run=False)
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=CHALLENGE_PENDING, claim=claim))
    return store, chain, ch


def test_failed_replacement_keeps_the_stuck_nonce(tmp_path, params):
    store, chain, ch = _rig(tmp_path, params)
    assert ch.challenge(store.get_claim(EPOCH)) is False  # nonce 7 broadcast, stuck
    chain.broadcast_error = ConnectionError("rpc dropped the request")
    assert ch.challenge(store.get_claim(EPOCH)) is False  # replacement never broadcast
    chain.broadcast_error = None
    ch.challenge(store.get_claim(EPOCH))
    # The next attempt replaces nonce 7 again instead of queueing behind it at 8.
    assert [tx["nonce"] for tx in chain.attempts] == [7, 7, 7]


def test_replacement_bumps_both_fee_caps_past_the_original(tmp_path, params):
    store, chain, ch = _rig(tmp_path, params)
    ch.challenge(store.get_claim(EPOCH))
    ch.challenge(store.get_claim(EPOCH))
    first, second = chain.attempts
    assert second["nonce"] == first["nonce"] == 7
    for k in ("maxFeePerGas", "maxPriorityFeePerGas"):
        assert second[k] * 100 >= first[k] * 110, k
    assert chain.mempool[7] is second  # accepted, not "replacement transaction underpriced"
    # A third replacement bumps again, over the second.
    ch.challenge(store.get_claim(EPOCH))
    assert chain.mempool[7] is chain.attempts[2]


def test_store_adds_fee_columns_to_an_old_journal(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE tx_journal (id INTEGER PRIMARY KEY AUTOINCREMENT, epoch INTEGER NOT NULL, "
        "action TEXT NOT NULL, chain TEXT NOT NULL, sender TEXT NOT NULL, nonce INTEGER, "
        "tx_hash TEXT, status TEXT NOT NULL, created_at INTEGER NOT NULL)"
    )
    conn.execute(
        "INSERT INTO tx_journal (epoch, action, chain, sender, nonce, status, created_at) "
        "VALUES (1, 'challenge', 'outbox', ?, 7, 'SENT', 0)", (US,)
    )
    conn.commit()
    conn.close()
    store = Store(path)
    assert store.journal_fees("outbox", US, 7) == []  # pre-migration row: no fees
    store.journal_intent(1, "challenge", "outbox", US, 7, fees=(30, 20))
    assert store.journal_fees("outbox", US, 7) == [(30, 20, False)]


def test_failed_broadcasts_do_not_compound_fees(tmp_path, params):
    """An RPC outage fails every broadcast: the replacement stays within one bump
    of the last tx that was broadcast, instead of +10% per failed tick."""
    store, chain, ch = _rig(tmp_path, params)
    ch.challenge(store.get_claim(EPOCH))  # broadcast at nonce 7, stuck
    first = chain.attempts[0]
    chain.broadcast_error = ConnectionError("rpc down")
    for _ in range(20):
        ch.challenge(store.get_claim(EPOCH))
    chain.broadcast_error = None
    ch.challenge(store.get_claim(EPOCH))
    last = chain.attempts[-1]
    assert last["nonce"] == 7
    assert chain.mempool[7] is last  # still outbids the stuck original
    for k in ("maxFeePerGas", "maxPriorityFeePerGas"):
        assert last[k] <= first[k] * 13 // 10 + 3, k


def test_replacement_failing_before_its_journal_keeps_the_stuck_nonce(tmp_path, params):
    """Panel F1: a replacement that fails before TxSender journals it (fee quote
    or simulation) must not drop the stuck nonce."""
    store, chain, ch = _rig(tmp_path, params)
    assert ch.challenge(store.get_claim(EPOCH)) is False  # nonce 7 broadcast, stuck
    chain.fees_error = ConnectionError("fee history unavailable")
    assert ch.challenge(store.get_claim(EPOCH)) is False  # fails before journal_intent
    chain.fees_error = None
    ch.challenge(store.get_claim(EPOCH))
    assert [tx["nonce"] for tx in chain.attempts] == [7, 7]
    assert chain.mempool[7] is chain.attempts[1]  # replaced, not queued at 8


def test_replacement_outbids_an_accepted_broadcast_whose_response_was_lost(tmp_path, params):
    """Panel F4: fees doubled, a replacement priced at market reached the node but
    its response was lost; the next one must still outbid it."""
    store, chain, ch = _rig(tmp_path, params)
    ch.challenge(store.get_claim(EPOCH))  # broadcast at nonce 7, stuck
    chain.market = 2
    chain.lose_response = True
    ch.challenge(store.get_claim(EPOCH))  # accepted, journaled without a tx hash
    lost = chain.mempool[7]
    assert lost is chain.attempts[1]
    chain.lose_response = False
    ch.challenge(store.get_claim(EPOCH))
    assert chain.mempool[7] is chain.attempts[2]  # not "replacement transaction underpriced"
    for k in ("maxFeePerGas", "maxPriorityFeePerGas"):
        assert chain.attempts[2][k] * 100 >= lost[k] * 110, k
