"""Regression tests for the implementation red-team findings."""

from types import SimpleNamespace

import pytest

from vea_challenger.claims import Claim, Party
import vea_challenger.detector as detector_mod
from vea_challenger.contracts import L2View, QuorumRead
from vea_challenger.detector import Detector
from vea_challenger.store import (
    CHALLENGE_PENDING,
    CHALLENGED,
    CHALLENGED_BY_OTHER,
    SNAPSHOT_SENT,
    UNDECIDED,
    WITHDRAWN,
    ClaimRow,
    Store,
)
from vea_challenger.verdict import Decision, ProviderRoot, Verdict, VerdictInputs

from conftest import FakeInbox, FakeNotifier
from conftest import FakeOutbox as _BaseOutbox



class FakeOutbox(_BaseOutbox):
    """Block-aware: a pinned claim_hash read sees the same hashes as latest."""

    def __init__(self):
        super().__init__()
        self.client = SimpleNamespace(receipt_or_none=lambda h: None)

    def claim_hash(self, epoch, block=None):
        return super().claim_hash(epoch)


CLAIMER = "0x00000000000000000000000000000000000000A1"
US = "0x00000000000000000000000000000000000000C3"
OTHER = "0x00000000000000000000000000000000000000D4"
ROOT_A = b"\xaa" * 32
ROOT_B = b"\xbb" * 32
EPOCH = 100
PERIOD = 7_200
EPOCH_END = (EPOCH + 1) * PERIOD


@pytest.fixture
def rig(tmp_path, params):
    store = Store(tmp_path / "t.db")
    outbox = FakeOutbox()
    inbox = FakeInbox()
    notifier = FakeNotifier()
    detector = Detector(
        store, outbox, inbox, params, notifier, US, devnet=False,
        log_scan_chunk=5_000, genesis_lookback_blocks=1_000,
    )
    # block-time sample for the first-run lookback (12 s blocks)
    outbox.block_timestamps.update({1: 1_000, 997: 1_000 + 996 * 12})
    return store, outbox, inbox, notifier, detector


def _claimed_event(epoch=EPOCH, block=500):
    return {
        "name": "Claimed",
        "args": {"_claimer": CLAIMER, "_epoch": epoch, "_stateRoot": ROOT_A},
        "block_number": block,
        "log_index": 0,
        "tx_hash": "0xclaimtx",
    }


def test_cursor_rewinds_on_failed_event(rig):
    """Finding 3: a dropped Claimed must be rescanned, not skipped."""
    store, outbox, _, notifier, detector = rig
    outbox.events = [_claimed_event(block=500)]
    # block_timestamps missing -> handler raises KeyError
    detector.sync_events()
    assert store.get_claim(EPOCH) is None
    assert store.get_cursor("outbox_events") == 499  # rewound, not head
    assert notifier.has("CRITICAL", "retry next tick")

    # data becomes available -> retry succeeds from the rewound cursor
    outbox.block_timestamps[500] = EPOCH_END + 60
    detector.sync_events()
    assert store.get_claim(EPOCH) is not None
    assert store.get_cursor("outbox_events") == outbox.confirmed_head()


def test_failed_event_pages_once_and_boundary_failure_sets_no_partial_flag(rig):
    store, outbox, _, notifier, detector = rig
    outbox.events = [_claimed_event(block=500)]
    for _ in range(3):
        detector.sync_events()
    assert sum(1 for m in notifier.messages if "retry next tick" in str(m)) == 1
    assert store.alert_sent(detector_mod._PARTIAL_SCAN) is None


def test_first_event_failure_keeps_an_earlier_partial_flag(rig):
    store, outbox, _, _, detector = rig
    store.mark_alert(detector_mod._PARTIAL_SCAN, 500)
    outbox.events = [_claimed_event(block=500)]  # block 500 has no timestamp: fails
    detector.sync_events()
    assert store.alert_sent(detector_mod._PARTIAL_SCAN) is not None


def test_honest_verdict_withheld_without_full_quorum(rig):
    """Finding 2: terminal HONEST needs every configured RPC, not just reachable ones."""
    store, _, inbox, notifier, detector = rig
    row = ClaimRow(
        epoch=EPOCH,
        status=UNDECIDED,
        claim=Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60),
    )
    store.upsert_claim(row)
    inbox.finalized = (ROOT_A, L2View(timestamp=EPOCH_END + 10, number=1))
    inbox.complete = False
    assert detector.evaluate(row) == Verdict.WAIT
    assert store.get_claim(EPOCH).status == UNDECIDED
    assert notifier.has("WARNING", "withholding")
    assert store.get_claim(EPOCH).note == "undecided: incomplete: 1 of 2 providers answered"

    inbox.complete = True
    row = store.get_claim(EPOCH)
    assert detector.evaluate(row) == Verdict.HONEST


def _row_and_inputs(store):
    row = ClaimRow(
        epoch=EPOCH,
        status=UNDECIDED,
        claim=Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60),
    )
    store.upsert_claim(row)
    return row


def test_single_answering_provider_mismatch_waits(rig):
    """1.2: one answering provider cannot trigger a challenge."""
    store, _, inbox, notifier, detector = rig
    detector.min_challenge_agreement = 2
    row = _row_and_inputs(store)
    inbox.reads["finalized"] = QuorumRead(
        ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1),
        (ProviderRoot("inbox#0", ROOT_B),), ("inbox#1",),
    )
    assert detector.evaluate(row) == Verdict.WAIT
    assert store.get_claim(EPOCH).status == UNDECIDED
    assert notifier.has("WARNING", "insufficient agreement")
    assert "insufficient agreement" in store.get_claim(EPOCH).note


def test_two_agreeing_providers_challenge(rig):
    store, _, inbox, _, detector = rig
    detector.min_challenge_agreement = 2
    row = _row_and_inputs(store)
    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1))
    assert detector.evaluate(row) == Verdict.CHALLENGE
    assert store.get_claim(EPOCH).true_root == "0x" + ROOT_B.hex()


def test_override_challenges_on_single_source(rig, monkeypatch):
    """The 1.1 override (stubbed decision) may challenge on fewer answers."""
    store, _, inbox, notifier, detector = rig
    detector.min_challenge_agreement = 2
    detector.challenge_on_ambiguity = True
    row = _row_and_inputs(store)
    inbox.reads["finalized"] = QuorumRead(
        ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1),
        (ProviderRoot("inbox#0", ROOT_B),), ("inbox#1",),
    )
    monkeypatch.setattr(
        detector_mod, "decide_detail", lambda v: Decision(Verdict.CHALLENGE, ROOT_B, "override")
    )
    assert detector.evaluate(row) == Verdict.CHALLENGE
    assert notifier.has("CRITICAL", "override")


def test_frontrun_while_challenge_pending(rig):
    """Finding 8: third-party Challenged while CHALLENGE_PENDING -> stand down."""
    store, outbox, _, _, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60)
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=CHALLENGE_PENDING, claim=base))
    outbox.events = [
        {
            "name": "Challenged",
            "args": {"_epoch": EPOCH, "_challenger": OTHER},
            "block_number": 510,
            "log_index": 0,
            "tx_hash": "0xc",
        }
    ]
    detector.sync_events()
    assert store.get_claim(EPOCH).status == CHALLENGED_BY_OTHER


def test_rescan_of_our_challenged_does_not_regress_snapshot_sent(rig):
    """Rescans must never drag an advanced row back to CHALLENGED."""
    store, outbox, _, _, detector = rig
    base = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60, challenger=US
    )
    store.upsert_claim(
        ClaimRow(epoch=EPOCH, status=SNAPSHOT_SENT, claim=base, snapshot_tx="0xs")
    )
    outbox.events = [
        {
            "name": "Challenged",
            "args": {"_epoch": EPOCH, "_challenger": US},
            "block_number": 510,
            "log_index": 0,
            "tx_hash": "0xc",
        }
    ]
    detector.sync_events()
    assert store.get_claim(EPOCH).status == SNAPSHOT_SENT


def test_verified_with_deleted_hash_marks_withdrawn(rig):
    """Finding 7: Verified + withdrawn inside one scan window is not a DESYNC."""
    store, outbox, _, notifier, detector = rig
    base = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60, challenger=US
    )
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=CHALLENGED, claim=base))
    # claimHashes deleted (default FakeOutbox returns zero hash)
    outbox.events = [
        {"name": "Verified", "args": {"_epoch": EPOCH}, "block_number": 700, "log_index": 0, "tx_hash": "0xv"},
    ]
    detector.sync_events()
    assert store.get_claim(EPOCH).status == WITHDRAWN
    assert notifier.has("WARNING", "check whether the challenge won")


def test_count_rule_is_not_bypassed_by_the_detector(rig, monkeypatch):
    """The detector acts on decide_detail's WAIT: a WAIT never becomes a challenge."""
    store, _, inbox, notifier, detector = rig
    row = _row_and_inputs(store)
    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1))
    monkeypatch.setattr(
        detector_mod,
        "decide_detail",
        lambda v: Decision(
            Verdict.WAIT, reason="insufficient agreement for epoch 100: 1 provider(s) (inbox#0) "
            "agree on a mismatch, fewer than 2"
        ),
    )
    assert detector.evaluate(row) == Verdict.WAIT
    assert store.get_claim(EPOCH).true_root is None
