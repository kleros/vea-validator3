"""reconcile: reorged-out challenges (2.1) and third-party challenges (2.2)."""

from types import SimpleNamespace

import pytest

from vea_challenger import watcher
from vea_challenger.challenger import Challenger
from vea_challenger.chain import AllProvidersFailed
from vea_challenger.claims import ZERO_ADDRESS, Claim, Party
from vea_challenger.contracts import L2View
from vea_challenger.detector import FRAUD_NOT_LANDED, Detector
from vea_challenger.store import (
    CHALLENGE_PENDING,
    CHALLENGED,
    CHALLENGED_BY_OTHER,
    HONEST,
    L1_EXECUTED,
    LOST,
    MISSED,
    RESOLVED,
    SEEN,
    SNAPSHOT_SENT,
    UNDECIDED,
    VERIFIED_UNDECIDED,
    WITHDRAWN,
    ClaimRow,
    Store,
)
from vea_challenger.verdict import Verdict

from conftest import FakeInbox, FakeNotifier
from conftest import FakeOutbox as _BaseOutbox

CLAIMER = "0x00000000000000000000000000000000000000A1"
US = "0x00000000000000000000000000000000000000C3"
OTHER = "0x00000000000000000000000000000000000000D4"
ROOT_A = b"\xaa" * 32
ROOT_B = b"\xbb" * 32
EPOCH = 100
PERIOD = 7_200
EPOCH_END = (EPOCH + 1) * PERIOD
TS = EPOCH_END + 60


class FakeOutbox(_BaseOutbox):
    """Block-aware claim_hash plus a receipt client (conftest's fake has neither).

    A pinned read answers ``at[(epoch, block)]``, else ``pinned[epoch]`` (the
    hash at the confirmed height), else the latest hash. Pinned reads below
    ``min_block`` raise ``state_error``, like a non-archive node.
    """

    def __init__(self):
        super().__init__()
        self.pinned: dict[int, bytes] = {}
        self.at: dict[tuple[int, int], bytes] = {}
        self.pinned_reads: list[tuple[int, int]] = []
        self.min_block: int | None = None
        self.state_error: type[Exception] = RuntimeError
        self.latest_error: Exception | None = None
        self.receipts: dict = {}
        self.client = SimpleNamespace(receipt_or_none=lambda h: self.receipts.get(h))

    def claim_hash(self, epoch, block=None):
        if block is None:
            if self.latest_error is not None:
                raise self.latest_error
            return super().claim_hash(epoch)
        self.pinned_reads.append((epoch, block))
        if self.min_block is not None and block < self.min_block:
            raise self.state_error("missing trie node")
        if (epoch, block) in self.at:
            return self.at[(epoch, block)]
        return self.pinned.get(epoch, super().claim_hash(epoch))


@pytest.fixture
def rig(tmp_path, params):
    store = Store(tmp_path / "t.db")
    outbox = FakeOutbox()
    inbox = FakeInbox()
    notifier = FakeNotifier()
    detector = Detector(store, outbox, inbox, params, notifier, US, devnet=False)
    return store, outbox, inbox, notifier, detector


def _base(**kw):
    return Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=TS, **kw)


def _critical(notifier):
    return [m for l, m in notifier.messages if l == "CRITICAL"]


# -- fakes for Challenger ----------------------------------------------------------


class FakeClient:
    def __init__(self, confirmed_nonce=5):
        self.confirmed_nonce = confirmed_nonce
        self.receipts: dict = {}

    def with_failover(self, fn):
        w3 = SimpleNamespace(
            eth=SimpleNamespace(
                get_balance=lambda a: 10**30, get_transaction_count=lambda a: self.confirmed_nonce
            )
        )
        return fn(w3)

    def receipt_or_none(self, h):
        return self.receipts.get(h)


class FakeSender:
    def __init__(self, store, client):
        self.store = store
        self.client = client
        self.address = US
        self.sent: list[dict] = []

    def send(self, fn, *, epoch, action, value=0, urgency=1.0, nonce_override=None, **_):
        self.sent.append({"epoch": epoch, "nonce_override": nonce_override})
        return {"transactionHash": SimpleNamespace(to_0x_hex=lambda: "0xnewtx")}


class ChallengeOutbox(FakeOutbox):
    address = "0xOutbox"

    def contract(self):
        fns = SimpleNamespace(challenge=lambda epoch, tup: ("challenge", epoch, tup))
        return SimpleNamespace(functions=fns)


def _challenger(store, outbox, params, notifier, client=None):
    client = client or FakeClient()
    sender = FakeSender(store, client)
    ch = Challenger(
        store, outbox, params, sender, notifier, weth=None, gas_reserve_wei=1,
        devnet=False, dry_run=False,
    )
    return ch, sender


class FailingSender(FakeSender):
    def send(self, fn, **kw):
        raise RuntimeError("nonce too low")


def test_failed_challenge_attempt_pages_hourly_per_epoch(tmp_path, params, monkeypatch):
    store = Store(tmp_path / "t.db")
    outbox = ChallengeOutbox()
    notifier = FakeNotifier()
    outbox.claim_hashes[EPOCH] = _base().hash()
    outbox._now = TS + 10
    ch = Challenger(
        store, outbox, params, FailingSender(store, FakeClient()), notifier, weth=None,
        gas_reserve_wei=1, devnet=False, dry_run=False,
    )
    now = [50_000.0]
    monkeypatch.setattr("vea_challenger.challenger.time.time", lambda: now[0])
    row = ClaimRow(epoch=EPOCH, status=SEEN, claim=_base(), true_root="0x" + ROOT_B.hex())
    for _ in range(3):
        assert ch.challenge(row) is False
    pages = [m for m in _critical(notifier) if m.startswith("CHALLENGE FAILED")]
    assert len(pages) == 1
    assert f"epoch {EPOCH}" in pages[0] and "nonce too low" in pages[0]
    got = store.get_claim(EPOCH)
    assert got.status == CHALLENGE_PENDING and got.note.startswith("challenge attempt failed")
    now[0] += 3_601
    ch.challenge(row)
    assert sum(m.startswith("CHALLENGE FAILED") for m in _critical(notifier)) == 2
    assert store.alert_sent(f"challenge-failed:{EPOCH}") is not None


# -- 2.1 -----------------------------------------------------------------------------


def test_reorged_out_challenge_goes_back_to_pending_and_rechallenges(tmp_path, params):
    store = Store(tmp_path / "t.db")
    outbox = ChallengeOutbox()
    notifier = FakeNotifier()
    detector = Detector(store, outbox, FakeInbox(), params, notifier, US, devnet=False)
    ours = _base(challenger=US)
    store.upsert_claim(
        ClaimRow(epoch=EPOCH, status=CHALLENGED, claim=ours, challenge_tx="0xlost",
                 true_root="0x" + ROOT_B.hex())
    )
    # The lost tx's journal entry is still open (broadcast, never mined).
    jid = store.journal_intent(EPOCH, "challenge", "outbox", US, 7)
    store.journal_sent(jid, "0xlost")
    outbox.claim_hashes[EPOCH] = _base().hash()  # challenger back to zero
    outbox._now = TS + 10
    outbox.latest_verified = outbox._now // PERIOD

    row = detector.reconcile(store.get_claim(EPOCH))

    assert row.status == CHALLENGE_PENDING
    got = store.get_claim(EPOCH)
    assert got.status == CHALLENGE_PENDING and got.challenge_tx is None and got.note
    assert _critical(notifier) == [f"our challenge for epoch {EPOCH} was reorged out; re-challenging"]

    # Same tick: the CHALLENGE_PENDING path sends a fresh tx, replacing the stuck one.
    challenger, sender = _challenger(store, outbox, params, notifier, FakeClient(confirmed_nonce=7))
    assert challenger.challenge(got) is True
    assert len(sender.sent) == 1 and sender.sent[0]["nonce_override"] == 7
    after = store.get_claim(EPOCH)
    assert after.status == CHALLENGED and after.challenge_tx == "0xnewtx"
    assert after.claim.challenger == US


def test_reorged_out_challenge_does_not_block_on_consumed_nonce(tmp_path, params):
    store = Store(tmp_path / "t.db")
    outbox = ChallengeOutbox()
    notifier = FakeNotifier()
    detector = Detector(store, outbox, FakeInbox(), params, notifier, US, devnet=False)
    store.upsert_claim(
        ClaimRow(epoch=EPOCH, status=CHALLENGED, claim=_base(challenger=US), challenge_tx="0xlost")
    )
    jid = store.journal_intent(EPOCH, "challenge", "outbox", US, 3)
    store.journal_sent(jid, "0xlost")
    outbox.claim_hashes[EPOCH] = _base().hash()
    outbox._now = TS + 10
    outbox.latest_verified = outbox._now // PERIOD
    detector.reconcile(store.get_claim(EPOCH))
    challenger, sender = _challenger(store, outbox, params, notifier, FakeClient(confirmed_nonce=9))
    assert challenger.challenge(store.get_claim(EPOCH)) is True
    assert sender.sent[0]["nonce_override"] is None  # nonce 3 already consumed: fresh nonce
    assert store.open_intents("challenge") == []


def test_escape_hatch_after_shutdown_is_not_a_reorg(rig, params):
    store, outbox, _, notifier, detector = rig
    store.upsert_claim(
        ClaimRow(epoch=EPOCH, status=CHALLENGED, claim=_base(challenger=US), challenge_tx="0xc")
    )
    outbox.claim_hashes[EPOCH] = _base().hash()  # escape hatch zeroed the challenger
    outbox._now = (params.timeout_epochs + 5) * params.epoch_period + params.epoch_period * 50
    outbox.latest_verified = 0
    detector.reconcile(store.get_claim(EPOCH))
    got = store.get_claim(EPOCH)
    assert got.status == WITHDRAWN and "escape hatch" in got.note
    assert _critical(notifier) == []


# -- 2.2 -----------------------------------------------------------------------------


def _other_row(store, **kw):
    store.upsert_claim(
        ClaimRow(epoch=EPOCH, status=CHALLENGED_BY_OTHER, claim=_base(challenger=OTHER), **kw)
    )


def test_third_party_challenge_reverted_is_reevaluated_and_challenged(rig):
    store, outbox, inbox, notifier, detector = rig
    _other_row(store)
    outbox.claim_hashes[EPOCH] = _base().hash()
    outbox._now = TS + 10
    outbox.latest_verified = outbox._now // PERIOD

    row = detector.reconcile(store.get_claim(EPOCH))
    assert row.status == UNDECIDED
    assert notifier.has("WARNING", f"epoch {EPOCH}")

    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1))
    assert detector.evaluate(store.get_claim(EPOCH)) == Verdict.CHALLENGE
    assert store.get_claim(EPOCH).true_root == "0x" + ROOT_B.hex()


def test_third_party_verified_challenger_won_is_missed(rig):
    store, outbox, _, _, detector = rig
    _other_row(store)
    won = _base(challenger=OTHER, honest=Party.CHALLENGER)
    outbox.claim_hashes[EPOCH] = won.hash()
    detector.reconcile(store.get_claim(EPOCH))
    assert store.get_claim(EPOCH).status == MISSED


def test_third_party_verified_claimer_won_without_our_verdict(rig):
    store, outbox, _, notifier, detector = rig
    _other_row(store)
    outbox.claim_hashes[EPOCH] = _base(challenger=OTHER, honest=Party.CLAIMER).hash()
    detector.reconcile(store.get_claim(EPOCH))
    assert store.get_claim(EPOCH).status == VERIFIED_UNDECIDED
    assert len(_critical(notifier)) == 1


def test_third_party_verified_claimer_won_we_judged_honest(rig):
    store, outbox, _, notifier, detector = rig
    _other_row(store, true_root="0x" + ROOT_A.hex())
    outbox.claim_hashes[EPOCH] = _base(challenger=OTHER, honest=Party.CLAIMER).hash()
    detector.reconcile(store.get_claim(EPOCH))
    assert store.get_claim(EPOCH).status == HONEST
    assert _critical(notifier) == []


def test_third_party_deleted_hash_is_missed(rig):
    store, outbox, _, _, detector = rig
    _other_row(store)
    # claimHashes[EPOCH] is zero: deleted by a withdrawal
    assert detector.reconcile(store.get_claim(EPOCH)) is None
    got = store.get_claim(EPOCH)
    assert got.status == MISSED and got.note


# -- L5/L6: confirmed-height reads, the receipt gate, the state window -----------------

CURSOR = 990  # the event scan has reached this block (confirmed head is 997)


def _at_cursor(store):
    store.set_cursor("outbox_events", CURSOR)


def _ours_row(store, status=CHALLENGED, **kw):
    kw.setdefault("challenge_tx", "0xlost")
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=status, claim=_base(challenger=US), **kw))


def _no_shutdown(outbox):
    outbox._now = TS + 10
    outbox.latest_verified = outbox._now // PERIOD


def test_revert_at_the_confirmed_height_acts_on_the_same_tick(rig):
    store, outbox, _, notifier, detector = rig
    _at_cursor(store)
    _ours_row(store)
    _no_shutdown(outbox)
    outbox.pinned[EPOCH] = _base().hash()  # zero challenger at the scan height
    outbox.claim_hashes[EPOCH] = _base(challenger=US).hash()  # latest still has ours
    row = detector.reconcile(store.get_claim(EPOCH))
    assert row.status == CHALLENGE_PENDING
    assert store.get_claim(EPOCH).claim.challenger == ZERO_ADDRESS
    assert outbox.pinned_reads == [(EPOCH, CURSOR)]
    assert len(_critical(notifier)) == 1


def test_zero_variant_only_at_latest_does_nothing(rig):
    store, outbox, _, notifier, detector = rig
    _at_cursor(store)
    _ours_row(store)
    outbox.pinned[EPOCH] = _base(challenger=US).hash()
    outbox.claim_hashes[EPOCH] = _base().hash()  # reverted above the cursor only
    row = detector.reconcile(store.get_claim(EPOCH))
    got = store.get_claim(EPOCH)
    assert row.status == got.status == CHALLENGED
    assert got.claim.challenger == US
    assert notifier.messages == []


def test_third_party_events_above_the_cursor_leave_an_undecided_row_alone(rig):
    store, outbox, _, notifier, detector = rig
    _at_cursor(store)
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=UNDECIDED, claim=_base(), note="undecided: x"))
    outbox.pinned[EPOCH] = _base().hash()
    # a Challenged and a startVerification, both above the cursor, changed latest
    outbox.claim_hashes[EPOCH] = _base(
        challenger=OTHER, timestamp_verification=TS + 5, blocknumber_verification=995
    ).hash()
    row = detector.reconcile(store.get_claim(EPOCH))
    assert row is not None and row.status == UNDECIDED
    got = store.get_claim(EPOCH)
    assert got.status == UNDECIDED and got.claim == _base() and got.note == "undecided: x"
    assert notifier.messages == []
    assert store.active_claims()[0].epoch == EPOCH


def test_receipt_holds_the_transition_and_pages_once_after_ten_minutes(rig, monkeypatch):
    store, outbox, _, notifier, detector = rig
    _at_cursor(store)
    _ours_row(store)
    _no_shutdown(outbox)
    outbox.pinned[EPOCH] = _base().hash()
    outbox.receipts["0xlost"] = {"status": 1, "blockNumber": 900}
    now = [1_000_000]
    monkeypatch.setattr("vea_challenger.detector.time.time", lambda: now[0])

    detector.reconcile(store.get_claim(EPOCH))  # first sighting: timer only
    assert store.alert_sent(f"reorg-suspect:{EPOCH}") == 1_000_000
    now[0] += 599
    detector.reconcile(store.get_claim(EPOCH))
    assert _critical(notifier) == []
    now[0] += 2  # 601 s
    detector.reconcile(store.get_claim(EPOCH))
    detector.reconcile(store.get_claim(EPOCH))
    stuck = _critical(notifier)
    assert len(stuck) == 1 and "receipt gate" in stuck[0]
    assert store.alert_sent(f"reorg-stuck:{EPOCH}") is not None
    got = store.get_claim(EPOCH)
    assert got.status == CHALLENGED and got.claim.challenger == US  # nothing overwritten
    now[0] += 3_601  # hourly
    detector.reconcile(store.get_claim(EPOCH))
    assert len(_critical(notifier)) == 2

    # the hash matches the stored struct again: the suspicion is forgotten
    outbox.pinned[EPOCH] = _base(challenger=US).hash()
    detector.reconcile(store.get_claim(EPOCH))
    assert store.alert_sent(f"reorg-suspect:{EPOCH}") is None


def test_receipt_above_the_scan_block_is_not_scanned_yet(rig, monkeypatch):
    store, outbox, _, notifier, detector = rig
    _at_cursor(store)
    _ours_row(store)
    _no_shutdown(outbox)
    outbox.pinned[EPOCH] = _base().hash()
    outbox.receipts["0xlost"] = {"status": 1, "blockNumber": CURSOR + 3}
    now = [1_000_000]
    monkeypatch.setattr("vea_challenger.detector.time.time", lambda: now[0])
    detector.reconcile(store.get_claim(EPOCH))
    now[0] += 11 * 60
    detector.reconcile(store.get_claim(EPOCH))
    assert notifier.messages == []
    assert store.alert_sent(f"reorg-suspect:{EPOCH}") is None
    assert store.get_claim(EPOCH).status == CHALLENGED


def test_failed_receipt_does_not_hold_the_transition(rig):
    store, outbox, _, _, detector = rig
    _at_cursor(store)
    _ours_row(store)
    _no_shutdown(outbox)
    outbox.pinned[EPOCH] = _base().hash()
    outbox.receipts["0xlost"] = {"status": 0, "blockNumber": 900}
    assert detector.reconcile(store.get_claim(EPOCH)).status == CHALLENGE_PENDING


def test_raising_bridge_shutdown_changes_nothing_then_recovers(rig, monkeypatch):
    store, outbox, _, notifier, detector = rig
    _at_cursor(store)
    _ours_row(store)
    _no_shutdown(outbox)
    outbox.pinned[EPOCH] = _base().hash()
    real = detector._bridge_shutdown
    monkeypatch.setattr(detector, "_bridge_shutdown", lambda: 1 / 0)
    with pytest.raises(ZeroDivisionError):
        detector.reconcile(store.get_claim(EPOCH))
    got = store.get_claim(EPOCH)
    assert got.status == CHALLENGED and got.claim.challenger == US and got.challenge_tx == "0xlost"
    monkeypatch.setattr(detector, "_bridge_shutdown", real)
    assert detector.reconcile(store.get_claim(EPOCH)).status == CHALLENGE_PENDING
    assert len(_critical(notifier)) == 1


@pytest.mark.parametrize("status", [SNAPSHOT_SENT, L1_EXECUTED])
def test_recovery_from_snapshot_sent_and_l1_executed(rig, status):
    store, outbox, _, notifier, detector = rig
    _at_cursor(store)
    _ours_row(
        store, status, snapshot_tx="0xs", l2tol1_json="{}", execute_tx="0xe"
    )
    _no_shutdown(outbox)
    outbox.pinned[EPOCH] = _base().hash()
    detector.reconcile(store.get_claim(EPOCH))
    got = store.get_claim(EPOCH)
    assert got.status == CHALLENGE_PENDING
    assert (got.snapshot_tx, got.l2tol1_json, got.execute_tx, got.challenge_tx) == (None,) * 4
    assert got.claim.challenger == ZERO_ADDRESS
    assert len(_critical(notifier)) == 1


def test_escape_hatched_snapshot_sent_with_receipt_is_withdrawn_at_once(rig, params):
    store, outbox, _, notifier, detector = rig
    _at_cursor(store)
    _ours_row(store, SNAPSHOT_SENT, snapshot_tx="0xs")
    outbox.pinned[EPOCH] = _base().hash()
    outbox.receipts["0xlost"] = {"status": 1, "blockNumber": 900}
    outbox._now = (params.timeout_epochs + 5) * params.epoch_period + params.epoch_period * 50
    outbox.latest_verified = 0
    detector.reconcile(store.get_claim(EPOCH))
    got = store.get_claim(EPOCH)
    assert got.status == WITHDRAWN and "escape hatch" in got.note
    assert got.claim.challenger == ZERO_ADDRESS
    assert _critical(notifier) == []


def test_challenge_sent_in_a_shutdown_and_mined_above_the_scan_block_is_not_withdrawn(rig, params):
    """The outbox's challenge() works during a shutdown too. Until the scan reaches
    our receipt's block, a zero challenger there is our own challenge not scanned
    yet, not the escape hatch."""
    store, outbox, _, notifier, detector = rig
    _at_cursor(store)
    _ours_row(store)
    outbox.pinned[EPOCH] = _base().hash()  # the scan block predates our challenge
    outbox.claim_hashes[EPOCH] = _base(challenger=US).hash()
    outbox.receipts["0xlost"] = {"status": 1, "blockNumber": CURSOR + 3}
    outbox._now = (params.timeout_epochs + 5) * params.epoch_period + params.epoch_period * 50
    outbox.latest_verified = 0
    detector.reconcile(store.get_claim(EPOCH))
    got = store.get_claim(EPOCH)
    assert got.status == CHALLENGED and got.claim.challenger == US and got.challenge_tx == "0xlost"
    assert notifier.messages == []


def test_third_party_revert_needs_no_receipt_gate(rig):
    store, outbox, _, _, detector = rig
    _at_cursor(store)
    _other_row(store, challenge_tx="0xwhatever")
    _no_shutdown(outbox)
    outbox.pinned[EPOCH] = _base().hash()
    outbox.receipts["0xwhatever"] = {"status": 1, "blockNumber": 900}
    assert detector.reconcile(store.get_claim(EPOCH)).status == UNDECIDED


# -- the state window (L6) ---------------------------------------------------------------


def _verified_claimer_hash():
    return _base(honest=Party.CLAIMER).hash()


def test_first_run_replay_through_an_old_verified_advances_the_cursor(rig):
    store, outbox, _, notifier, detector = rig
    outbox.min_block = 900  # nothing older is served
    outbox.events = [
        {
            "name": "Claimed",
            "args": {"_claimer": CLAIMER, "_epoch": EPOCH, "_stateRoot": ROOT_A},
            "block_number": 100, "log_index": 0, "tx_hash": "0xc",
        },
        {"name": "Verified", "args": {"_epoch": EPOCH}, "block_number": 120, "log_index": 0, "tx_hash": "0xv"},
    ]
    outbox.block_timestamps.update({1: 1_000, 997: 1_000 + 996 * 12})  # lookback sample
    outbox.block_timestamps[100] = TS
    outbox.claim_hashes[EPOCH] = _verified_claimer_hash()
    detector.sync_events()
    assert store.get_cursor("outbox_events") == outbox.confirmed_head()
    assert store.get_claim(EPOCH).status == VERIFIED_UNDECIDED
    assert outbox.pinned_reads == []  # out of window: read at latest
    assert len(_critical(notifier)) == 1


def test_old_verified_with_a_deleted_hash_maps_by_status(rig):
    store, outbox, _, notifier, detector = rig
    outbox.min_block = 900
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=UNDECIDED, claim=_base()))
    outbox.events = [
        {"name": "Verified", "args": {"_epoch": EPOCH}, "block_number": 120, "log_index": 0, "tx_hash": "0xv"},
    ]
    store.set_cursor("outbox_events", 50)
    detector.sync_events()
    assert store.get_cursor("outbox_events") == outbox.confirmed_head()
    assert store.get_claim(EPOCH).status == VERIFIED_UNDECIDED


def test_cursor_far_behind_leaves_the_row_alone_and_evaluate_still_runs(rig):
    store, outbox, inbox, notifier, detector = rig
    store.set_cursor("outbox_events", 797)  # 200 blocks behind the confirmed head
    outbox.min_block = 900
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=UNDECIDED, claim=_base()))
    # latest differs (e.g. a verification started): reconcile must not DESYNC on it
    outbox.claim_hashes[EPOCH] = _base(timestamp_verification=TS + 9).hash()
    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1))
    app = SimpleNamespace(detector=detector, challenger=None, notifier=notifier, store=store)
    row = store.get_claim(EPOCH)
    assert detector.reconcile(row) is row
    assert store.get_claim(EPOCH).status == UNDECIDED and store.get_claim(EPOCH).claim == _base()
    assert outbox.pinned_reads == []
    watcher._process_row(app, store.get_claim(EPOCH))
    assert store.get_claim(EPOCH).true_root == "0x" + ROOT_B.hex()  # evaluate ran
    assert store.get_claim(EPOCH).note.startswith("fraud:")


def test_pinned_read_failing_everywhere_counts_as_out_of_window(rig):
    store, outbox, _, _, detector = rig
    _at_cursor(store)
    outbox.min_block = 10_000
    outbox.state_error = AllProvidersFailed
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=UNDECIDED, claim=_base()))
    outbox.claim_hashes[EPOCH] = b"\xee" * 32  # would be DESYNC if it were read
    row = detector.reconcile(store.get_claim(EPOCH))
    assert row.status == UNDECIDED and store.get_claim(EPOCH).status == UNDECIDED
    assert outbox.pinned_reads == [(EPOCH, CURSOR)]


def test_out_of_window_log_is_hourly_per_epoch(rig, caplog, monkeypatch):
    store, outbox, _, _, detector = rig
    store.set_cursor("outbox_events", 500)
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=UNDECIDED, claim=_base()))
    now = [1_000.0]
    monkeypatch.setattr("vea_challenger.detector.time.time", lambda: now[0])
    with caplog.at_level("WARNING"):
        for _ in range(3):
            detector.reconcile(store.get_claim(EPOCH))
        assert caplog.text.count("reconcile takes no transition") == 1
        now[0] += 3_601
        detector.reconcile(store.get_claim(EPOCH))
        assert caplog.text.count("reconcile takes no transition") == 2


def test_in_window_pinned_read_is_used(rig):
    store, outbox, _, _, detector = rig
    outbox.min_block = 900
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=UNDECIDED, claim=_base()))
    outbox.claim_hashes[EPOCH] = _base().hash()
    outbox.events = [
        {"name": "Verified", "args": {"_epoch": EPOCH}, "block_number": 950, "log_index": 0, "tx_hash": "0xv"},
    ]
    outbox.at[(EPOCH, 950)] = _verified_claimer_hash()
    store.set_cursor("outbox_events", 940)
    detector.sync_events()
    assert (EPOCH, 950) in outbox.pinned_reads
    assert store.get_claim(EPOCH).status == VERIFIED_UNDECIDED


def test_verified_is_judged_at_the_events_block_not_latest(rig):
    """Verified, then withdrawn in later blocks: the verified struct decides."""
    store, outbox, _, notifier, detector = rig
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=CHALLENGED_BY_OTHER, claim=_base(challenger=OTHER)))
    outbox.at[(EPOCH, 950)] = _base(challenger=OTHER, honest=Party.CHALLENGER).hash()
    # latest: withdrawn (zero)
    outbox.events = [
        {"name": "Verified", "args": {"_epoch": EPOCH}, "block_number": 950, "log_index": 0, "tx_hash": "0xv"},
    ]
    store.set_cursor("outbox_events", 940)
    detector.sync_events()
    got = store.get_claim(EPOCH)
    assert got.status == MISSED and got.note == "fraud defeated by another challenger"
    assert got.claim.honest == Party.CHALLENGER


def test_verify_and_withdraw_in_one_block_falls_back_to_the_deleted_mapping(rig):
    store, outbox, _, _, detector = rig
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=CHALLENGED, claim=_base(challenger=US)))
    outbox.at[(EPOCH, 950)] = b"\x00" * 32
    outbox.events = [
        {"name": "Verified", "args": {"_epoch": EPOCH}, "block_number": 950, "log_index": 0, "tx_hash": "0xv"},
    ]
    store.set_cursor("outbox_events", 940)
    detector.sync_events()
    assert store.get_claim(EPOCH).status == WITHDRAWN


def test_reconcile_passes_its_read_block_into_apply_verified(rig):
    store, outbox, _, _, detector = rig
    _at_cursor(store)
    _other_row(store)
    won = _base(challenger=OTHER, honest=Party.CHALLENGER)
    outbox.pinned[EPOCH] = won.hash()
    # the hash was deleted only above the cursor
    detector.reconcile(store.get_claim(EPOCH))
    got = store.get_claim(EPOCH)
    assert got.status == MISSED and got.note == "fraud defeated by another challenger"
    assert outbox.pinned_reads == [(EPOCH, CURSOR)]  # its own read, no second one


def test_latest_read_failure_in_apply_verified_never_stalls_the_scan(rig):
    """A failed pinned and latest read never raises into sync_events."""
    store, outbox, _, notifier, detector = rig
    store.upsert_claim(
        ClaimRow(epoch=EPOCH, status=L1_EXECUTED, claim=_base(challenger=US), execute_tx="0xe")
    )
    won = _base(challenger=US, honest=Party.CHALLENGER)
    outbox.at[(EPOCH, 990)] = won.hash()
    outbox.claim_hashes[EPOCH] = won.hash()
    outbox.min_block = 10_000
    outbox.state_error = AllProvidersFailed  # the pinned read fails on every provider
    outbox.latest_error = AllProvidersFailed("outage")
    outbox.events = [
        {"name": "Verified", "args": {"_epoch": EPOCH}, "block_number": 990, "log_index": 0, "tx_hash": "0xv"},
    ]
    store.set_cursor("outbox_events", 980)
    detector.sync_events()
    assert store.get_cursor("outbox_events") == outbox.confirmed_head()
    assert store.get_claim(EPOCH).status == L1_EXECUTED
    assert not notifier.has("CRITICAL", "retry next tick")
    # the outage ends: reconcile applies the consumed Verified
    outbox.min_block = None
    outbox.latest_error = None
    detector.reconcile(store.get_claim(EPOCH))
    assert store.get_claim(EPOCH).status == RESOLVED


class _SecondPinnedReadFails(FakeOutbox):
    """The first pinned read answers; every later one fails on every provider."""

    def claim_hash(self, epoch, block=None):
        if block is not None and self.pinned_reads:
            self.pinned_reads.append((epoch, block))
            raise AllProvidersFailed("outage")
        return super().claim_hash(epoch, block)


@pytest.fixture
def flaky_rig(tmp_path, params):
    store = Store(tmp_path / "t.db")
    outbox = _SecondPinnedReadFails()
    notifier = FakeNotifier()
    detector = Detector(store, outbox, FakeInbox(), params, notifier, US, devnet=False)
    return store, outbox, notifier, detector


def test_reconcile_applies_its_confirmed_verified_struct_not_latest(flaky_rig):
    """A consumed Verified (we won) is applied from reconcile's own read; an
    unconfirmed withdrawal at latest must not make the row WITHDRAWN."""
    store, outbox, notifier, detector = flaky_rig
    _at_cursor(store)
    _ours_row(store, status=L1_EXECUTED, execute_tx="0xe")
    _no_shutdown(outbox)
    outbox.pinned[EPOCH] = _base(challenger=US, honest=Party.CHALLENGER).hash()
    # latest: withdrawn above the cursor (zero hash), not confirmed yet
    detector.reconcile(store.get_claim(EPOCH))
    got = store.get_claim(EPOCH)
    assert got.status == RESOLVED
    assert got.claim.honest == Party.CHALLENGER
    assert outbox.pinned_reads == [(EPOCH, CURSOR)]


def test_reconcile_verified_for_claimer_ignores_a_withdrawal_at_latest(flaky_rig):
    store, outbox, notifier, detector = flaky_rig
    _at_cursor(store)
    _other_row(store)
    outbox.pinned[EPOCH] = _base(challenger=OTHER, honest=Party.CLAIMER).hash()
    detector.reconcile(store.get_claim(EPOCH))
    assert store.get_claim(EPOCH).status == VERIFIED_UNDECIDED
    assert len(_critical(notifier)) == 1


# -- a scan that stopped mid-block takes no transition at all -------------------------------


def _challenged_then_failing_events(block=995):
    return [
        {
            "name": "Challenged", "args": {"_epoch": EPOCH, "_challenger": OTHER},
            "block_number": block, "log_index": 0, "tx_hash": "0xc",
        },
        {  # no block timestamp known for this block: the handler raises
            "name": "Claimed",
            "args": {"_claimer": CLAIMER, "_epoch": EPOCH + 1, "_stateRoot": ROOT_A},
            "block_number": block, "log_index": 1, "tx_hash": "0xc2",
        },
    ]


def test_scan_stopped_mid_block_makes_no_revert_transition(rig):
    store, outbox, _, _, detector = rig
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=CHALLENGE_PENDING, claim=_base()))
    store.set_cursor("outbox_events", 980)
    outbox.events = _challenged_then_failing_events()
    outbox.pinned[EPOCH] = _base().hash()  # at the rewound cursor: still unchallenged
    _no_shutdown(outbox)
    detector.sync_events()
    assert store.get_cursor("outbox_events") == 994
    assert store.get_claim(EPOCH).status == CHALLENGED_BY_OTHER  # first event applied
    row = detector.reconcile(store.get_claim(EPOCH))
    got = store.get_claim(EPOCH)
    assert row.status == got.status == CHALLENGED_BY_OTHER
    assert got.claim.challenger == OTHER

    # the retry completes the block: reconcile works again, from a consistent state
    outbox.block_timestamps[995] = TS
    outbox.pinned[EPOCH] = _base(challenger=OTHER).hash()
    detector.sync_events()
    assert detector.reconcile(store.get_claim(EPOCH)).status == CHALLENGED_BY_OTHER


def test_scan_stopped_mid_block_does_not_desync_an_undecided_row(rig):
    store, outbox, _, _, detector = rig
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=UNDECIDED, claim=_base()))
    store.set_cursor("outbox_events", 980)
    outbox.events = [
        {"name": "VerificationStarted", "args": {"_epoch": EPOCH}, "block_number": 995, "log_index": 0, "tx_hash": "0xv"},
        _challenged_then_failing_events()[1],
    ]
    calls = {"n": 0}
    real = outbox.block_timestamp

    def flaky(n):  # the first lookup works (VerificationStarted), the second fails
        calls["n"] += 1
        if calls["n"] == 1:
            return TS + 30
        return real(n)

    outbox.block_timestamp = flaky
    outbox.pinned[EPOCH] = _base().hash()  # no verification yet at block 994
    detector.sync_events()
    assert store.get_claim(EPOCH).claim.timestamp_verification == TS + 30  # row ahead of chain
    row = detector.reconcile(store.get_claim(EPOCH))
    assert row.status == UNDECIDED
    assert store.get_claim(EPOCH).status == UNDECIDED
    assert [r.epoch for r in store.active_claims()] == [EPOCH]


def test_partial_flag_is_cleared_by_a_failure_at_a_later_block(rig):
    store, outbox, _, _, detector = rig
    store.set_cursor("outbox_events", 980)
    store.mark_alert("scan-partial", 995)  # set by an earlier tick; block 995 now completes
    claimed = lambda b, i: {  # noqa: E731
        "name": "Claimed",
        "args": {"_claimer": CLAIMER, "_epoch": EPOCH + 5, "_stateRoot": ROOT_A},
        "block_number": b, "log_index": i, "tx_hash": "0xc",
    }
    outbox.block_timestamps[995] = TS
    outbox.events = [claimed(995, 0), claimed(996, 0)]  # 996 has no timestamp: fails
    detector.sync_events()
    assert store.get_cursor("outbox_events") == 995
    assert store.alert_sent("scan-partial") is None
    # a failure at a block <= the flag keeps it
    store.mark_alert("scan-partial", 995)
    outbox.block_timestamps.pop(995, None)
    outbox.events = [claimed(995, 0)]
    store.set_cursor("outbox_events", 980)
    detector.sync_events()
    assert store.alert_sent("scan-partial") == 995


# -- a Verified consumed during an outage is applied by reconcile, for every row kind ------


def _consume_verified_during_outage(store, outbox, detector, verified_hash):
    """sync_events consumes a Verified whose pinned and latest reads both fail
    (the row is left as it was), then the outage ends."""
    outbox.at[(EPOCH, 990)] = verified_hash
    outbox.claim_hashes[EPOCH] = verified_hash
    outbox.min_block = 10_000
    outbox.state_error = AllProvidersFailed
    outbox.latest_error = AllProvidersFailed("outage")
    outbox.events = [
        {"name": "Verified", "args": {"_epoch": EPOCH}, "block_number": 990, "log_index": 0, "tx_hash": "0xv"},
    ]
    store.set_cursor("outbox_events", 980)
    before = store.get_claim(EPOCH)
    detector.sync_events()
    assert store.get_cursor("outbox_events") == outbox.confirmed_head()
    after = store.get_claim(EPOCH)
    assert (after.status, after.claim, after.note) == (before.status, before.claim, before.note)
    outbox.min_block = None
    outbox.latest_error = None


@pytest.mark.parametrize(
    "status, claim, note, verified, expected, page",
    [
        (SEEN, _base(), None, _base(honest=Party.CLAIMER), VERIFIED_UNDECIDED,
         "verified as honest but we never judged it honest"),
        (UNDECIDED, _base(), "undecided: quorum split on finalized", _base(honest=Party.CLAIMER),
         VERIFIED_UNDECIDED, "verified as honest but we never judged it honest"),
        (CHALLENGE_PENDING, _base(), "fraud: root mismatch", _base(honest=Party.CLAIMER),
         MISSED, FRAUD_NOT_LANDED),
        (SEEN, _base(), "fraud: root mismatch", _base(honest=Party.CLAIMER), MISSED,
         FRAUD_NOT_LANDED),
        (UNDECIDED, _base(), "fraud: root mismatch", _base(honest=Party.CLAIMER), MISSED,
         FRAUD_NOT_LANDED),
        (CHALLENGED, _base(challenger=US), None, _base(challenger=US, honest=Party.CLAIMER),
         LOST, "our challenge LOST"),
    ],
    ids=["seen-verified", "undecided-verified", "pending-not-ours", "seen-fraud",
         "undecided-fraud", "ours-lost"],
)
def test_reconcile_applies_a_consumed_verified_for_every_row_kind(
    rig, status, claim, note, verified, expected, page
):
    store, outbox, _, notifier, detector = rig
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=status, claim=claim, note=note))
    _no_shutdown(outbox)
    _consume_verified_during_outage(store, outbox, detector, verified.hash())
    assert _critical(notifier) == []
    # the outage ends: reconcile reads the verified variant at the scan block
    row = detector.reconcile(store.get_claim(EPOCH))
    got = store.get_claim(EPOCH)
    assert row.status == got.status == expected
    assert got.claim == verified
    pages = _critical(notifier)
    assert len(pages) == 1 and page in pages[0] and f"epoch {EPOCH}" in pages[0]
    if expected == MISSED:
        assert got.note.startswith(FRAUD_NOT_LANDED)
    assert outbox.pinned_reads[-1] == (EPOCH, outbox.confirmed_head())


def test_revert_takes_effect_on_the_tick_after_a_later_block_failure_clears_the_flag(rig):
    store, outbox, _, notifier, detector = rig
    _ours_row(store)  # CHALLENGED, challenge_tx 0xlost with no receipt
    _no_shutdown(outbox)
    outbox.pinned[EPOCH] = _base().hash()  # confirmed height: challenger zero, honest NONE
    store.set_cursor("outbox_events", 980)
    store.mark_alert("scan-partial", 995)  # an earlier tick applied part of block 995
    # while the flag is set, reconcile takes no transition
    assert detector.reconcile(store.get_claim(EPOCH)).status == CHALLENGED
    assert notifier.messages == []
    claimed = lambda b, i: {  # noqa: E731
        "name": "Claimed",
        "args": {"_claimer": CLAIMER, "_epoch": EPOCH + 5, "_stateRoot": ROOT_A},
        "block_number": b, "log_index": i, "tx_hash": "0xc",
    }
    outbox.block_timestamps[995] = TS
    outbox.events = [claimed(995, 0), claimed(996, 0)]  # 996 has no timestamp: fails
    detector.sync_events()
    assert store.get_cursor("outbox_events") == 995
    assert store.alert_sent("scan-partial") is None
    row = detector.reconcile(store.get_claim(EPOCH))
    got = store.get_claim(EPOCH)
    assert row.status == got.status == CHALLENGE_PENDING
    assert got.challenge_tx is None and got.claim.challenger == ZERO_ADDRESS
    assert outbox.pinned_reads[-1] == (EPOCH, 995)
    pages = [m for m in _critical(notifier) if not m.startswith("event processing failed")]
    assert pages == [f"our challenge for epoch {EPOCH} was reorged out; re-challenging"]


# -- a restart in the middle of a partial scan keeps the no-transition rule -------------------


def test_restart_mid_partial_scan_makes_no_revert_transition(tmp_path, params):
    path = tmp_path / "restart.db"
    store = Store(path)
    outbox = FakeOutbox()
    notifier = FakeNotifier()
    detector = Detector(store, outbox, FakeInbox(), params, notifier, US, devnet=False)
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=CHALLENGE_PENDING, claim=_base()))
    store.set_cursor("outbox_events", 980)
    outbox.events = _challenged_then_failing_events()
    outbox.pinned[EPOCH] = _base().hash()  # at the rewound cursor: still unchallenged
    _no_shutdown(outbox)
    detector.sync_events()
    assert store.get_cursor("outbox_events") == 994
    assert store.get_claim(EPOCH).status == CHALLENGED_BY_OTHER  # first event applied
    store.close()

    # restart: a fresh Store from the same path and a fresh Detector
    store2 = Store(path)
    notifier2 = FakeNotifier()
    detector2 = Detector(store2, outbox, FakeInbox(), params, notifier2, US, devnet=False)
    assert store2.alert_sent("scan-partial") == 995
    row = detector2.reconcile(store2.get_claim(EPOCH))
    got = store2.get_claim(EPOCH)
    assert row.status == got.status == CHALLENGED_BY_OTHER
    assert got.claim.challenger == OTHER
    assert notifier2.messages == []
    store2.close()


def test_restart_mid_partial_scan_does_not_desync_an_undecided_row(tmp_path, params):
    path = tmp_path / "restart.db"
    store = Store(path)
    outbox = FakeOutbox()
    detector = Detector(store, outbox, FakeInbox(), params, FakeNotifier(), US, devnet=False)
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=UNDECIDED, claim=_base()))
    store.set_cursor("outbox_events", 980)
    outbox.events = [
        {"name": "VerificationStarted", "args": {"_epoch": EPOCH}, "block_number": 995, "log_index": 0, "tx_hash": "0xv"},
        _challenged_then_failing_events()[1],
    ]
    calls = {"n": 0}
    real = outbox.block_timestamp

    def flaky(n):  # the first lookup works (VerificationStarted), the second fails
        calls["n"] += 1
        return TS + 30 if calls["n"] == 1 else real(n)

    outbox.block_timestamp = flaky
    outbox.pinned[EPOCH] = _base().hash()  # no verification yet at block 994
    detector.sync_events()
    assert store.get_claim(EPOCH).claim.timestamp_verification == TS + 30  # row ahead of chain
    store.close()

    store2 = Store(path)
    notifier2 = FakeNotifier()
    detector2 = Detector(store2, outbox, FakeInbox(), params, notifier2, US, devnet=False)
    row = detector2.reconcile(store2.get_claim(EPOCH))
    assert row.status == UNDECIDED and store2.get_claim(EPOCH).status == UNDECIDED
    assert [r.epoch for r in store2.active_claims()] == [EPOCH]
    assert notifier2.messages == []
    store2.close()


# -- C4: a reverted third-party challenge is re-challenged ------------------------------------


def test_reverted_third_party_challenge_is_challenged_end_to_end(tmp_path, params):
    store = Store(tmp_path / "t.db")
    outbox = ChallengeOutbox()
    notifier = FakeNotifier()
    inbox = FakeInbox()
    detector = Detector(store, outbox, inbox, params, notifier, US, devnet=False)
    _other_row(store)
    outbox.claim_hashes[EPOCH] = _base().hash()
    _no_shutdown(outbox)
    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1))
    challenger, sender = _challenger(store, outbox, params, notifier)

    row = detector.reconcile(store.get_claim(EPOCH))
    assert row.status == UNDECIDED
    assert detector.evaluate(row) == Verdict.CHALLENGE
    assert challenger.challenge(store.get_claim(EPOCH)) is True
    assert len(sender.sent) == 1 and sender.sent[0]["epoch"] == EPOCH
    after = store.get_claim(EPOCH)
    assert after.status == CHALLENGED and after.claim.challenger == US


# -- G8: a failed-send note is redacted ----------------------------------------------------


def test_challenge_failure_note_is_redacted(tmp_path, params):
    from vea_challenger.chain import register_endpoint

    url = "https://rpc.example.org/v2/NOTESECRET12345"
    register_endpoint(url, "eth#0 (rpc.example.org)", hide_host=False)
    store = Store(tmp_path / "t.db")
    outbox = ChallengeOutbox()
    notifier = FakeNotifier()
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=UNDECIDED, claim=_base()))
    outbox.claim_hashes[EPOCH] = _base().hash()
    outbox._now = TS + 10
    challenger, sender = _challenger(store, outbox, params, notifier)

    def boom(*a, **k):
        raise RuntimeError(f"429 Client Error for url: {url}")

    sender.send = boom
    assert challenger.challenge(store.get_claim(EPOCH)) is False
    note = store.get_claim(EPOCH).note
    assert note.startswith("challenge attempt failed: ")
    assert "NOTESECRET12345" not in note and "eth#0 (rpc.example.org)" in note
    assert store.get_claim(EPOCH).status == CHALLENGE_PENDING
