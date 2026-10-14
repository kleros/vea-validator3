"""Detector: event sync, reconstruction, reconciliation, verdict wiring."""

from types import SimpleNamespace

import pytest

from vea_challenger import watcher
from vea_challenger.claims import ZERO_ADDRESS, Claim, Party, hash_claim
from vea_challenger.contracts import L2View, QuorumRead
import vea_challenger.detector as detector_mod
from vea_challenger.detector import Detector
from vea_challenger.store import (
    CHALLENGE_PENDING,
    CHALLENGED,
    CHALLENGED_BY_OTHER,
    DESYNC,
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
from vea_challenger.verdict import Decision, ProviderRoot, Verdict, VerdictInputs

from conftest import FakeInbox, FakeNotifier
from conftest import FakeOutbox as _BaseOutbox


class FakeOutbox(_BaseOutbox):
    """Block-aware: a pinned claim_hash read answers like latest (conftest's fake
    takes no block argument)."""

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


def _claimed_event(epoch=EPOCH, block=500, claimer=CLAIMER, root=ROOT_A):
    return {
        "name": "Claimed",
        "args": {"_claimer": claimer, "_epoch": epoch, "_stateRoot": root},
        "block_number": block,
        "log_index": 0,
        "tx_hash": "0xclaimtx",
    }


def test_claimed_event_creates_row(rig):
    store, outbox, _, notifier, detector = rig
    outbox.events = [_claimed_event()]
    outbox.block_timestamps[500] = EPOCH_END + 60
    detector.sync_events()

    row = store.get_claim(EPOCH)
    assert row.status == SEEN
    assert row.claim == Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60)
    assert store.get_cursor("outbox_events") == outbox.confirmed_head()


def test_duplicate_scan_is_idempotent(rig):
    store, outbox, _, _, detector = rig
    outbox.events = [_claimed_event()]
    outbox.block_timestamps[500] = EPOCH_END + 60
    detector.sync_events()
    outbox.head += 10
    detector.sync_events()  # cursor advanced past the event; nothing rescanned
    outbox.head += 10
    # even a forced rescan must not clobber state
    store.set_cursor("outbox_events", 0)
    detector.sync_events()
    assert len(store.all_claims()) == 1


def test_verification_started_updates_struct(rig):
    store, outbox, _, _, detector = rig
    outbox.events = [
        _claimed_event(),
        {
            "name": "VerificationStarted",
            "args": {"_epoch": EPOCH},
            "block_number": 600,
            "log_index": 0,
            "tx_hash": "0xv",
        },
    ]
    outbox.block_timestamps[500] = EPOCH_END + 60
    outbox.block_timestamps[600] = EPOCH_END + 90_000
    detector.sync_events()
    row = store.get_claim(EPOCH)
    assert row.claim.timestamp_verification == EPOCH_END + 90_000
    assert row.claim.blocknumber_verification == 600


def test_challenged_by_us_and_by_other(rig):
    store, outbox, _, notifier, detector = rig
    outbox.events = [
        _claimed_event(epoch=100, block=500),
        _claimed_event(epoch=101, block=501),
        {
            "name": "Challenged",
            "args": {"_epoch": 100, "_challenger": US},
            "block_number": 510,
            "log_index": 0,
            "tx_hash": "0xc1",
        },
        {
            "name": "Challenged",
            "args": {"_epoch": 101, "_challenger": OTHER},
            "block_number": 511,
            "log_index": 0,
            "tx_hash": "0xc2",
        },
    ]
    outbox.block_timestamps |= {500: EPOCH_END + 60, 501: EPOCH_END + 60}
    detector.sync_events()
    assert store.get_claim(100).status == CHALLENGED
    assert store.get_claim(100).claim.challenger == US
    assert store.get_claim(101).status == CHALLENGED_BY_OTHER


def test_verified_probes_winner_we_won(rig):
    store, outbox, _, notifier, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60, challenger=US)
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=CHALLENGED, claim=base))
    won = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60,
        challenger=US, honest=Party.CHALLENGER,
    )
    outbox.claim_hashes[EPOCH] = won.hash()
    outbox.events = [
        {"name": "Verified", "args": {"_epoch": EPOCH}, "block_number": 700, "log_index": 0, "tx_hash": "0xv"},
    ]
    detector.sync_events()
    row = store.get_claim(EPOCH)
    assert row.status == RESOLVED
    assert row.claim.honest == Party.CHALLENGER


def test_verified_probes_winner_we_lost(rig):
    store, outbox, _, notifier, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60, challenger=US)
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=CHALLENGED, claim=base))
    lost = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60,
        challenger=US, honest=Party.CLAIMER,
    )
    outbox.claim_hashes[EPOCH] = lost.hash()
    outbox.events = [
        {"name": "Verified", "args": {"_epoch": EPOCH}, "block_number": 700, "log_index": 0, "tx_hash": "0xv"},
    ]
    detector.sync_events()
    assert store.get_claim(EPOCH).status == LOST
    assert notifier.has("CRITICAL", "LOST")


def _verified_event():
    return [
        {"name": "Verified", "args": {"_epoch": EPOCH}, "block_number": 700, "log_index": 0, "tx_hash": "0xv"},
    ]


def test_verified_unchallenged_marks_verified_undecided(rig):
    store, outbox, _, notifier, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60)
    verified = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60,
        honest=Party.CLAIMER,
    )
    outbox.claim_hashes[EPOCH] = verified.hash()
    outbox.events = _verified_event()
    for status in (SEEN, UNDECIDED):
        store.upsert_claim(ClaimRow(epoch=EPOCH, status=status, claim=base))
        notifier.messages.clear()
        detector.store.set_cursor("outbox_events", 0)
        detector.sync_events()
        assert store.get_claim(EPOCH).status == VERIFIED_UNDECIDED
        assert notifier.has("CRITICAL", f"epoch {EPOCH}")


def test_verified_row_ruled_honest_stays_honest(rig):
    store, outbox, _, notifier, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60)
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=HONEST, claim=base))
    verified = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60,
        honest=Party.CLAIMER,
    )
    outbox.claim_hashes[EPOCH] = verified.hash()
    outbox.events = _verified_event()
    detector.sync_events()
    assert store.get_claim(EPOCH).status == HONEST
    assert not notifier.has("CRITICAL")


def test_failed_resolution_resets_to_challenged(rig):
    store, outbox, _, notifier, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60, challenger=US)
    store.upsert_claim(
        ClaimRow(epoch=EPOCH, status="SNAPSHOT_SENT", claim=base, snapshot_tx="0xs", l2tol1_json="{}")
    )
    outbox.events = [
        {"name": "FailedResolution", "args": {"_epoch": EPOCH}, "block_number": 800, "log_index": 0, "tx_hash": "0xf"},
    ]
    detector.sync_events()
    row = store.get_claim(EPOCH)
    assert row.status == CHALLENGED
    assert row.snapshot_tx is None
    assert notifier.has("CRITICAL", "FAILED")


def _l2tol1_json(claim):
    """An L2ToL1Tx message whose calldata is resolveDisputedClaim(epoch, root, claim)."""
    import json

    from eth_abi import encode

    from vea_challenger.arbitrum import RESOLVE_SELECTOR

    data = RESOLVE_SELECTOR + encode(
        ["uint256", "bytes32", "(bytes32,address,uint32,uint32,uint32,uint8,address)"],
        [EPOCH, ROOT_B, claim.as_tuple()],
    )
    return json.dumps({"position": 7, "data": "0x" + data.hex()})


def _failed_resolution_case(rig, sent_claim):
    store, outbox, _, notifier, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60, challenger=US)
    outbox.claim_hashes[EPOCH] = hash_claim(base)
    msg = _l2tol1_json(sent_claim)
    store.upsert_claim(
        ClaimRow(epoch=EPOCH, status=SNAPSHOT_SENT, claim=base, snapshot_tx="0xs", l2tol1_json=msg)
    )
    outbox.events = [
        {"name": "FailedResolution", "args": {"_epoch": EPOCH}, "block_number": 800, "log_index": 0, "tx_hash": "0xf"},
    ]
    detector.sync_events()
    return store.get_claim(EPOCH), msg


def test_failed_resolution_of_someone_elses_stale_message_keeps_ours(rig):
    """V3-02: our pending message still carries the current struct, so the
    FailedResolution came from someone else's stale message; keep our round trip."""
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60, challenger=US)
    row, msg = _failed_resolution_case(rig, base)
    assert row.status == SNAPSHOT_SENT
    assert row.snapshot_tx == "0xs"
    assert row.l2tol1_json == msg
    assert not rig[3].has("CRITICAL")
    assert rig[3].has("WARNING", "not ours")


def test_failed_resolution_of_our_stale_message_resets(rig):
    """Our own message carried a stale (pre-challenge) struct: re-send as before."""
    stale = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60)
    row, _ = _failed_resolution_case(rig, stale)
    assert row.status == CHALLENGED
    assert row.snapshot_tx is None and row.l2tol1_json is None
    assert rig[3].has("CRITICAL", "FAILED")


def test_reconcile_hash_gone_after_resolved(rig):
    store, outbox, _, _, detector = rig
    base = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60,
        challenger=US, honest=Party.CHALLENGER,
    )
    row = ClaimRow(epoch=EPOCH, status=RESOLVED, claim=base)
    store.upsert_claim(row)
    # claimHashes deleted: someone called withdrawChallengeDeposit for us
    detector.reconcile(row)
    assert store.get_claim(EPOCH).status == WITHDRAWN


def test_reconcile_probes_escape_hatch_mutation(rig):
    store, outbox, _, _, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60, challenger=US)
    row = ClaimRow(epoch=EPOCH, status=CHALLENGED, claim=base)
    store.upsert_claim(row)
    mutated = Claim(
        state_root=ROOT_A, claimer=ZERO_ADDRESS, timestamp_claimed=EPOCH_END + 60, challenger=US
    )
    outbox.claim_hashes[EPOCH] = mutated.hash()
    out = detector.reconcile(row)
    assert out.claim.claimer == ZERO_ADDRESS
    assert store.get_claim(EPOCH).claim.claimer == ZERO_ADDRESS


def test_reconcile_desync_alerts(rig):
    store, outbox, _, notifier, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60)
    row = ClaimRow(epoch=EPOCH, status=SEEN, claim=base)
    store.upsert_claim(row)
    outbox.claim_hashes[EPOCH] = b"\xee" * 32
    detector.reconcile(row)
    assert store.get_claim(EPOCH).status == DESYNC
    assert notifier.has("CRITICAL", "reconstruct")


def test_evaluate_challenge_and_honest(rig, params):
    store, outbox, inbox, _, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60)
    row = ClaimRow(epoch=EPOCH, status=SEEN, claim=base)
    store.upsert_claim(row)

    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1))
    assert detector.evaluate(row) == Verdict.CHALLENGE
    assert store.get_claim(EPOCH).true_root == "0x" + ROOT_B.hex()

    inbox.finalized = (ROOT_A, L2View(timestamp=EPOCH_END + 10, number=1))
    row = store.get_claim(EPOCH)
    assert detector.evaluate(row) == Verdict.HONEST
    assert store.get_claim(EPOCH).status == HONEST


def test_evaluate_waits_and_marks_undecided(rig):
    store, outbox, inbox, _, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60)
    row = ClaimRow(epoch=EPOCH, status=SEEN, claim=base)
    store.upsert_claim(row)
    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END - 100, number=1))
    inbox.latest = (ROOT_B, L2View(timestamp=EPOCH_END + 100, number=2))  # inside backdate window
    assert detector.evaluate(row) == Verdict.WAIT
    assert store.get_claim(EPOCH).status == UNDECIDED


def test_evaluate_quorum_split_waits_and_alerts(rig):
    store, outbox, inbox, notifier, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60)
    row = ClaimRow(epoch=EPOCH, status=SEEN, claim=base)
    store.upsert_claim(row)
    inbox.quorum_split = True
    assert detector.evaluate(row) == Verdict.WAIT
    assert notifier.has("CRITICAL", "quorum split")


# -- evaluate: decision inputs, true_root, WAIT reasons, alerts ---------------------


def _row(store, status=SEEN):
    row = ClaimRow(
        epoch=EPOCH, status=status,
        claim=Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60),
    )
    store.upsert_claim(row)
    return row


def _read(root, ts, labels=("inbox#0", "inbox#1"), missing=()):
    return QuorumRead(root, L2View(timestamp=ts, number=7), tuple(ProviderRoot(l, root) for l in labels), missing)


def test_evaluate_fills_decision_inputs(rig, params, monkeypatch):
    store, outbox, inbox, _, detector = rig
    row = _row(store)
    outbox._now = 12_345
    inbox.reads["finalized"] = _read(ROOT_B, EPOCH_END + 10)
    inbox.reads["latest"] = QuorumRead(
        None, L2View(timestamp=EPOCH_END + 99, number=9),
        (ProviderRoot("inbox#0", ROOT_A), ProviderRoot("inbox#1", ROOT_B)), (),
    )
    detector.min_challenge_agreement = 2
    detector.challenge_on_ambiguity = True
    captured = []

    def fake(v):
        captured.append(v)
        return Decision(Verdict.WAIT, reason="x")

    monkeypatch.setattr(detector_mod, "decide_detail", fake)
    detector.evaluate(row)
    v = captured[0]
    assert v.epoch == EPOCH and v.claimed_root == ROOT_A
    assert v.epoch_period == params.epoch_period
    assert v.sequencer_delay == outbox.seq_delay
    assert (v.finalized_ts, v.finalized_snapshot) == (EPOCH_END + 10, ROOT_B)
    assert (v.latest_ts, v.latest_snapshot) == (EPOCH_END + 99, None)  # split keeps ts
    assert v.finalized_reads == inbox.reads["finalized"].reads
    assert v.latest_reads == inbox.reads["latest"].reads
    assert v.total_providers == 2
    assert v.min_agreement == 2 and v.challenge_on_ambiguity is True
    assert v.now == 12_345 and v.devnet is False
    assert v.deadline == (
        EPOCH_END + 60 + params.epoch_period + outbox.seq_delay + params.min_challenge_period
    )


def test_true_root_is_deciding_leg_root(rig, monkeypatch):
    store, _, inbox, _, detector = rig
    row = _row(store)
    inbox.finalized = (ROOT_A, L2View(timestamp=EPOCH_END - 5, number=1))
    ROOT_C = b"\xcc" * 32
    monkeypatch.setattr(
        detector_mod, "decide_detail", lambda v: Decision(Verdict.CHALLENGE, ROOT_B, "latest")
    )
    assert detector.evaluate(row) == Verdict.CHALLENGE
    assert store.get_claim(EPOCH).true_root == "0x" + ROOT_B.hex()
    monkeypatch.setattr(
        detector_mod, "decide_detail", lambda v: Decision(Verdict.HONEST, ROOT_A, "finalized")
    )
    inbox.latest = (ROOT_C, L2View(timestamp=EPOCH_END, number=1))
    detector.evaluate(store.get_claim(EPOCH))
    assert store.get_claim(EPOCH).true_root == "0x" + ROOT_A.hex()


def test_wait_sets_note_and_single_source_alert_once(rig, monkeypatch):
    store, _, inbox, notifier, detector = rig
    row = _row(store)
    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1))
    reason = (
        f"insufficient agreement for epoch {EPOCH}: 1 provider(s) (inbox#1) agree on a "
        "mismatch, fewer than 2"
    )
    monkeypatch.setattr(detector_mod, "decide_detail", lambda v: Decision(Verdict.WAIT, reason=reason))
    assert detector.evaluate(row) == Verdict.WAIT
    assert detector.evaluate(store.get_claim(EPOCH)) == Verdict.WAIT
    got = store.get_claim(EPOCH)
    assert got.status == UNDECIDED and got.note == f"undecided: {reason}"
    assert [m for m in notifier.messages if m == ("WARNING", reason)] == [("WARNING", reason)]
    assert store.alert_sent(f"single-source:{EPOCH}") is not None


def test_override_declined_pages_once(rig, monkeypatch):
    store, _, inbox, notifier, detector = rig
    row = _row(store)
    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1))
    monkeypatch.setattr(
        detector_mod, "decide_detail",
        lambda v: Decision(Verdict.WAIT, reason="override declined: no immutable read"),
    )
    detector.evaluate(row)
    detector.evaluate(store.get_claim(EPOCH))
    crit = [m for l, m in notifier.messages if l == "CRITICAL" and "override declined" in m]
    assert len(crit) == 1
    assert store.alert_sent(f"override-declined:{EPOCH}") is not None


def test_override_challenge_pages_leg_provider_and_root(rig, monkeypatch):
    store, _, inbox, notifier, detector = rig
    row = _row(store)
    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1))
    inbox.reads["latest"] = QuorumRead(
        None, L2View(timestamp=EPOCH_END + 5, number=2),
        (ProviderRoot("inbox#0", ROOT_A), ProviderRoot("inbox#1", ROOT_B)), (),
    )
    monkeypatch.setattr(
        detector_mod, "decide_detail", lambda v: Decision(Verdict.CHALLENGE, ROOT_B, "override")
    )
    assert detector.evaluate(row) == Verdict.CHALLENGE
    msg = next(m for l, m in notifier.messages if l == "CRITICAL" and "override" in m)
    assert "inbox#1" in msg and ROOT_B.hex() in msg


def test_split_alert_names_labels_roots_and_missing(rig):
    store, _, inbox, notifier, detector = rig
    row = _row(store)
    inbox.reads["finalized"] = QuorumRead(
        None, L2View(timestamp=EPOCH_END + 10, number=1),
        (ProviderRoot("inbox#0", ROOT_A), ProviderRoot("inbox#1", ROOT_B)), ("inbox#2",),
    )
    detector.evaluate(row)
    msg = next(m for l, m in notifier.messages if l == "CRITICAL")
    for needle in ("inbox#0", ROOT_A.hex(), "inbox#1", ROOT_B.hex(), "inbox#2"):
        assert needle in msg


def test_incomplete_honest_note_names_missing(rig):
    store, _, inbox, _, detector = rig
    row = _row(store)
    inbox.finalized = (ROOT_A, L2View(timestamp=EPOCH_END + 10, number=1))
    inbox.complete = False
    assert detector.evaluate(row) == Verdict.WAIT
    assert store.get_claim(EPOCH).note == "undecided: incomplete: 1 of 2 providers answered"


# -- G1/G2/f11: Verified for a claim whose hash is already deleted ---------------------------


def _deleted_case(rig, status, note=None, challenger=ZERO_ADDRESS):
    store, outbox, _, notifier, detector = rig
    base = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60, challenger=challenger
    )
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=status, claim=base, note=note))
    outbox.events = _verified_event()
    detector.sync_events()
    return store.get_claim(EPOCH), notifier


@pytest.mark.parametrize("status", [SEEN, UNDECIDED])
def test_deleted_hash_undecided_row_is_verified_undecided(rig, status):
    got, notifier = _deleted_case(rig, status, "undecided: quorum split")
    assert got.status == VERIFIED_UNDECIDED
    assert "withdrawn before processing" in got.note
    assert notifier.has("CRITICAL", f"epoch {EPOCH}")


@pytest.mark.parametrize("status", [SEEN, UNDECIDED, CHALLENGE_PENDING])
def test_deleted_hash_fraud_row_is_missed(rig, status):
    note = "fraud: finalized root 0xbb differs from the claim; challenge not confirmed yet"
    got, notifier = _deleted_case(rig, status, note if status != CHALLENGE_PENDING else None)
    assert got.status == MISSED
    assert notifier.has("CRITICAL", "fraud verified before our challenge landed")


def test_deleted_hash_challenged_by_other_is_missed(rig):
    got, notifier = _deleted_case(rig, CHALLENGED_BY_OTHER, challenger=OTHER)
    assert got.status == MISSED and got.note
    assert not notifier.has("WARNING", "check whether the challenge won")


def test_deleted_hash_honest_row_is_withdrawn(rig):
    got, _ = _deleted_case(rig, HONEST)
    assert got.status == WITHDRAWN


@pytest.mark.parametrize("status", [CHALLENGED, SNAPSHOT_SENT, L1_EXECUTED])
def test_deleted_hash_our_challenge_states_keep_warning_and_withdrawn(rig, status):
    got, notifier = _deleted_case(rig, status, challenger=US)
    assert got.status == WITHDRAWN
    assert notifier.has("WARNING", "check whether the challenge won")
    assert not notifier.has("CRITICAL")


def test_verified_for_claimer_with_fraud_note_is_missed(rig):
    store, outbox, _, notifier, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60)
    note = "fraud: latest root 0xbb differs from the claim; challenge not confirmed yet"
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=UNDECIDED, claim=base, note=note))
    outbox.claim_hashes[EPOCH] = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60,
        honest=Party.CLAIMER,
    ).hash()
    outbox.events = _verified_event()
    detector.sync_events()
    assert store.get_claim(EPOCH).status == MISSED
    assert notifier.has("CRITICAL", "fraud verified before our challenge landed")


def test_seen_row_with_fraud_note_verified_for_claimer_is_missed(rig):
    store, outbox, _, notifier, detector = rig
    base = Claim(state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60)
    note = "fraud: finalized root 0xbb differs from the claim; challenge not confirmed yet"
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=SEEN, claim=base, note=note))
    outbox.claim_hashes[EPOCH] = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60,
        honest=Party.CLAIMER,
    ).hash()
    outbox.events = _verified_event()
    detector.sync_events()
    row = store.get_claim(EPOCH)
    assert row.status == MISSED
    assert note in row.note
    assert notifier.has("CRITICAL", "fraud verified before our challenge landed")
    assert not notifier.has("CRITICAL", "verified as honest but we never judged it")


@pytest.mark.parametrize("status", [CHALLENGED, SNAPSHOT_SENT, L1_EXECUTED])
@pytest.mark.parametrize("ruled_honest", [True, False])
def test_our_challenge_states_verified_for_claimer_after_other_challenged_never_lost(
    rig, status, ruled_honest
):
    # Our challenge reorged out, a third party's Challenged landed (the struct
    # moves to OTHER, the status stays), then Verified for the Claimer.
    store, outbox, _, notifier, detector = rig
    base = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60, challenger=US,
    )
    true_root = "0x" + (ROOT_A if ruled_honest else ROOT_B).hex()
    store.upsert_claim(
        ClaimRow(epoch=EPOCH, status=status, claim=base, true_root=true_root, challenge_tx="0xc0")
    )
    outbox.claim_hashes[EPOCH] = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60,
        challenger=OTHER, honest=Party.CLAIMER,
    ).hash()
    outbox.events = [
        {
            "name": "Challenged",
            "args": {"_epoch": EPOCH, "_challenger": OTHER},
            "block_number": 650,
            "log_index": 0,
            "tx_hash": "0xc2",
        },
        *_verified_event(),
    ]
    detector.sync_events()
    row = store.get_claim(EPOCH)
    assert row.claim.challenger == OTHER
    assert row.status != LOST
    assert not notifier.has("CRITICAL", "LOST")
    assert not notifier.has("CRITICAL", "deposit forfeited")
    if ruled_honest:
        assert row.status == HONEST
        assert not notifier.has("CRITICAL")
    else:
        assert row.status == VERIFIED_UNDECIDED
        assert notifier.has("CRITICAL", "verified as honest but we never judged it honest")


@pytest.mark.parametrize("ours, status", [(False, MISSED), (True, LOST)])
def test_challenge_pending_verified_for_claimer(rig, ours, status):
    store, outbox, _, notifier, detector = rig
    base = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60,
        challenger=US if ours else ZERO_ADDRESS,
    )
    store.upsert_claim(ClaimRow(epoch=EPOCH, status=CHALLENGE_PENDING, claim=base))
    outbox.claim_hashes[EPOCH] = Claim(
        state_root=ROOT_A, claimer=CLAIMER, timestamp_claimed=EPOCH_END + 60,
        challenger=US if ours else ZERO_ADDRESS, honest=Party.CLAIMER,
    ).hash()
    outbox.events = _verified_event()
    detector.sync_events()
    assert store.get_claim(EPOCH).status == status
    if ours:
        assert notifier.has("CRITICAL", "LOST")
    else:
        assert notifier.has("CRITICAL", "fraud verified before our challenge landed")
        assert not notifier.has("CRITICAL", "deposit forfeited")


# -- evaluate: fraud note, override page, incomplete warning ---------------------------------


def test_challenge_verdict_writes_the_fraud_note(rig):
    store, _, inbox, _, detector = rig
    row = _row(store)
    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1))
    assert detector.evaluate(row) == Verdict.CHALLENGE
    assert store.get_claim(EPOCH).note == (
        f"fraud: finalized root 0x{ROOT_B.hex()} differs from the claim; "
        "challenge not confirmed yet"
    )


def test_fraud_note_survives_a_flapping_quorum_and_the_deadline_says_fraud(rig):
    store, outbox, inbox, notifier, detector = rig
    row = _row(store)
    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1))
    assert detector.evaluate(row) == Verdict.CHALLENGE
    inbox.quorum_split = True  # the quorum flaps to a split
    assert detector.evaluate(store.get_claim(EPOCH)) == Verdict.WAIT
    assert detector.evaluate(store.get_claim(EPOCH)) == Verdict.WAIT
    got = store.get_claim(EPOCH)
    assert got.status == UNDECIDED
    assert got.note.startswith("fraud: finalized root")
    assert got.note.count("latest read:") == 1 and "quorum split" in got.note

    params = detector.params
    deadline = (
        EPOCH_END + 60 + params.epoch_period + outbox.seq_delay + params.min_challenge_period
    )
    outbox._now = deadline - 3_000
    app = SimpleNamespace(
        route=SimpleNamespace(devnet=False), outbox=outbox, detector=detector,
        store=store, notifier=notifier,
    )
    notifier.messages.clear()
    watcher.check_deadlines(app, store.active_claims())
    msgs = [m for l, m in notifier.messages if l in ("WARNING", "CRITICAL")]
    assert msgs and all(m.startswith(f"FRAUD for epoch {EPOCH} not challenged yet: fraud:") for m in msgs)
    assert all(m.endswith("3000 s left") for m in msgs)


def test_override_challenge_page_is_hourly_per_epoch(rig, monkeypatch):
    store, _, inbox, notifier, detector = rig
    row = _row(store)
    inbox.finalized = (ROOT_B, L2View(timestamp=EPOCH_END + 10, number=1))
    monkeypatch.setattr(
        detector_mod, "decide_detail", lambda v: Decision(Verdict.CHALLENGE, ROOT_B, "override")
    )
    now = [1_000_000]
    monkeypatch.setattr(detector_mod.time, "time", lambda: now[0])
    for _ in range(3):  # ticks with no challenge sent
        assert detector.evaluate(store.get_claim(EPOCH)) == Verdict.CHALLENGE

    def pages():
        return [m for l, m in notifier.messages if l == "CRITICAL" and "override" in m]

    assert len(pages()) == 1
    assert store.alert_sent(f"override-challenge:{EPOCH}") == 1_000_000
    now[0] += 3_601
    detector.evaluate(store.get_claim(EPOCH))
    assert len(pages()) == 2


def test_override_page_names_the_deciding_leg_and_only_immutable_reads(rig):
    store, outbox, inbox, notifier, detector = rig
    detector.challenge_on_ambiguity = True
    row = _row(store)
    params = detector.params
    outbox._now = (
        EPOCH_END + 60 + params.epoch_period + outbox.seq_delay + params.min_challenge_period
    )
    # finalized is past the epoch end (immutable) and splits; latest is inside the
    # backdating window (not immutable) with a differing read of its own.
    inbox.reads["finalized"] = QuorumRead(
        None, L2View(timestamp=EPOCH_END + 10, number=1),
        (ProviderRoot("inbox#0", ROOT_A), ProviderRoot("inbox#1", ROOT_B)), (),
    )
    inbox.reads["latest"] = QuorumRead(
        ROOT_C, L2View(timestamp=EPOCH_END + 5, number=2),
        (ProviderRoot("inbox#7", ROOT_C), ProviderRoot("inbox#8", ROOT_C)), (),
    )
    assert detector.evaluate(row) == Verdict.CHALLENGE
    msg = next(m for l, m in notifier.messages if l == "CRITICAL" and "deadline override" in m)
    assert "in the finalized leg" in msg
    assert "inbox#1" in msg and ROOT_B.hex() in msg
    assert "inbox#7" not in msg and "inbox#8" not in msg and ROOT_C.hex() not in msg


def test_incomplete_warning_is_sent_once_across_ticks(rig):
    store, _, inbox, notifier, detector = rig
    row = _row(store)
    inbox.finalized = (ROOT_A, L2View(timestamp=EPOCH_END + 10, number=1))
    inbox.complete = False
    for _ in range(3):
        assert detector.evaluate(store.get_claim(EPOCH)) == Verdict.WAIT
    warnings = [m for l, m in notifier.messages if l == "WARNING" and "withholding" in m]
    assert len(warnings) == 1 and "1 of 2" in warnings[0]
    assert store.alert_sent(f"incomplete:{EPOCH}") is not None
    inbox.complete = True
    assert detector.evaluate(store.get_claim(EPOCH)) == Verdict.HONEST


ROOT_C = b"\xcc" * 32
