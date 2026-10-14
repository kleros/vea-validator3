"""Verdict logic: the safety-critical decision rules."""

import pytest

from vea_challenger.verdict import (
    OVERRIDE_WINDOW,
    ProviderRoot,
    Verdict,
    VerdictInputs,
    decide,
    decide_detail,
    earliest_verification_ts,
)

EPOCH = 100
PERIOD = 7_200
SEQ_DELAY = 86_400
EPOCH_END = (EPOCH + 1) * PERIOD

ROOT_A = b"\xaa" * 32
ROOT_B = b"\xbb" * 32
ZERO = b"\x00" * 32


def R(root, n=2):
    return tuple(ProviderRoot(f"inbox#{i}", root) for i in range(n))


def _inputs(**kw) -> VerdictInputs:
    base = dict(
        epoch=EPOCH,
        claimed_root=ROOT_A,
        epoch_period=PERIOD,
        sequencer_delay=SEQ_DELAY,
        finalized_ts=None,
        finalized_snapshot=None,
        latest_ts=None,
        latest_snapshot=None,
        min_agreement=2,
    )
    base.update(kw)
    return VerdictInputs(**base)


def test_honest_when_finalized_matches():
    v = _inputs(finalized_ts=EPOCH_END, finalized_snapshot=ROOT_A)
    assert decide(v) == Verdict.HONEST


def test_challenge_when_finalized_differs():
    v = _inputs(finalized_ts=EPOCH_END + 1, finalized_snapshot=ROOT_B, finalized_reads=R(ROOT_B))
    assert decide(v) == Verdict.CHALLENGE


def test_challenge_when_no_snapshot_saved():
    """snapshots(E) == 0x0 makes any claim fraudulent."""
    v = _inputs(finalized_ts=EPOCH_END + 1, finalized_snapshot=ZERO, finalized_reads=R(ZERO))
    assert decide(v) == Verdict.CHALLENGE


def test_wait_when_finalized_before_epoch_end():
    """Snapshot can still be overwritten inside the epoch: no verdict."""
    v = _inputs(finalized_ts=EPOCH_END - 1, finalized_snapshot=ROOT_B)
    assert decide(v) == Verdict.WAIT


def test_wait_when_no_data():
    assert decide(_inputs()) == Verdict.WAIT


def test_latest_fallback_requires_sequencer_delay_buffer():
    """Backdating window: latest data younger than epochEnd + seqDelay decides nothing."""
    v = _inputs(latest_ts=EPOCH_END + SEQ_DELAY - 1, latest_snapshot=ROOT_B)
    assert decide(v) == Verdict.WAIT


def test_latest_fallback_after_backdating_window():
    v = _inputs(latest_ts=EPOCH_END + SEQ_DELAY, latest_snapshot=ROOT_B, latest_reads=R(ROOT_B))
    assert decide(v) == Verdict.CHALLENGE
    v = _inputs(latest_ts=EPOCH_END + SEQ_DELAY, latest_snapshot=ROOT_A)
    assert decide(v) == Verdict.HONEST


def test_finalized_takes_priority_over_latest():
    """A finalized read past epoch end wins even if latest disagrees."""
    v = _inputs(
        finalized_ts=EPOCH_END,
        finalized_snapshot=ROOT_A,
        latest_ts=EPOCH_END + SEQ_DELAY,
        latest_snapshot=ROOT_B,
    )
    assert decide(v) == Verdict.HONEST


def test_stale_finalized_falls_through_to_latest():
    v = _inputs(
        finalized_ts=EPOCH_END - 100,
        finalized_snapshot=ROOT_B,
        latest_ts=EPOCH_END + SEQ_DELAY,
        latest_snapshot=ROOT_A,
    )
    assert decide(v) == Verdict.HONEST


def test_earliest_verification_mainnet_style():
    ts = earliest_verification_ts(1_000_000, PERIOD, SEQ_DELAY, 10_800, devnet=False)
    assert ts == 1_000_000 + PERIOD + SEQ_DELAY + 10_800


def test_earliest_verification_devnet_is_immediate():
    assert earliest_verification_ts(1_000_000, PERIOD, SEQ_DELAY, 10_800, devnet=True) == 1_000_000


def test_single_agreeing_read_waits():
    v = _inputs(
        finalized_ts=EPOCH_END, finalized_snapshot=ROOT_B, finalized_reads=R(ROOT_B, 1)
    )
    d = decide_detail(v)
    assert d.verdict == Verdict.WAIT
    assert d.reason == (
        f"insufficient agreement for epoch {EPOCH}: 1 provider(s) (inbox#0) agree on a "
        "mismatch, fewer than 2"
    )


def test_short_leg_reason_counts_agreeing_providers():
    v = _inputs(
        min_agreement=3,
        finalized_ts=EPOCH_END,
        finalized_snapshot=ROOT_B,
        finalized_reads=R(ROOT_B, 2),
        total_providers=3,
    )
    d = decide_detail(v)
    assert d.reason == (
        f"insufficient agreement for epoch {EPOCH}: 2 provider(s) (inbox#0, inbox#1) "
        "agree on a mismatch, fewer than 3"
    )


def test_two_agreeing_reads_challenge():
    v = _inputs(
        finalized_ts=EPOCH_END, finalized_snapshot=ROOT_B, finalized_reads=R(ROOT_B)
    )
    d = decide_detail(v)
    assert (d.verdict, d.root, d.leg) == (Verdict.CHALLENGE, ROOT_B, "finalized")


def test_snapshot_without_reads_never_challenges():
    v = _inputs(finalized_ts=EPOCH_END, finalized_snapshot=ROOT_B)
    assert decide(v) == Verdict.WAIT


def test_short_finalized_leg_falls_to_latest():
    v = _inputs(
        finalized_ts=EPOCH_END,
        finalized_snapshot=ROOT_B,
        finalized_reads=R(ROOT_B, 1),
        latest_ts=EPOCH_END + SEQ_DELAY,
        latest_snapshot=ROOT_B,
        latest_reads=R(ROOT_B),
    )
    d = decide_detail(v)
    assert (d.verdict, d.leg) == (Verdict.CHALLENGE, "latest")


def test_decision_root_is_deciding_leg():
    v = _inputs(
        finalized_ts=EPOCH_END - 1,
        finalized_snapshot=ROOT_A,
        finalized_reads=R(ROOT_A),
        latest_ts=EPOCH_END + SEQ_DELAY,
        latest_snapshot=ROOT_B,
        latest_reads=R(ROOT_B),
        claimed_root=b"\xcc" * 32,
    )
    d = decide_detail(v)
    assert (d.root, d.leg) == (ROOT_B, "latest")


def test_split_leg_named_in_reason():
    v = _inputs(
        finalized_ts=EPOCH_END,
        finalized_snapshot=None,
        finalized_reads=(ProviderRoot("a", ROOT_A), ProviderRoot("b", ROOT_B)),
    )
    d = decide_detail(v)
    assert d.verdict == Verdict.WAIT
    assert d.reason == f"quorum split on finalized: a=0x{ROOT_A.hex()}, b=0x{ROOT_B.hex()}"


DEADLINE = 10_000_000
NEAR = DEADLINE - OVERRIDE_WINDOW


def _ovr(**kw):
    base = dict(
        claimed_root=ROOT_A,
        finalized_ts=EPOCH_END,
        finalized_snapshot=ROOT_B,
        finalized_reads=(ProviderRoot("inbox#0", ROOT_B),),
        now=NEAR,
        deadline=DEADLINE,
        challenge_on_ambiguity=True,
    )
    base.update(kw)
    return _inputs(**base)


@pytest.mark.parametrize(
    "kw, verdict, leg, text",
    [
        ({}, Verdict.CHALLENGE, "override", "inbox#0"),
        ({"challenge_on_ambiguity": False}, Verdict.WAIT, None, "insufficient agreement"),
        ({"now": NEAR - 1}, Verdict.WAIT, None, "insufficient agreement"),
        ({"devnet": True}, Verdict.WAIT, None, "insufficient agreement"),
        ({"now": None}, Verdict.WAIT, None, "insufficient agreement"),
        (
            {"finalized_ts": EPOCH_END - 1},
            Verdict.WAIT,
            None,
            "override declined: no immutable read",
        ),
        (
            {"finalized_reads": (), "finalized_snapshot": None, "finalized_ts": None},
            Verdict.WAIT,
            None,
            "override declined: no immutable read",
        ),
        (
            {
                "finalized_snapshot": None,
                "finalized_reads": (
                    ProviderRoot("inbox#0", ROOT_A),
                    ProviderRoot("inbox#1", ROOT_A),
                ),
            },
            Verdict.WAIT,
            None,
            "override declined: every immutable read equals the claim",
        ),
        (
            {
                "finalized_snapshot": None,
                "finalized_reads": (
                    ProviderRoot("inbox#0", ROOT_A),
                    ProviderRoot("inbox#1", ROOT_B),
                ),
            },
            Verdict.CHALLENGE,
            "override",
            "inbox#1",
        ),
    ],
)
def test_override_table(kw, verdict, leg, text):
    d = decide_detail(_ovr(**kw))
    assert (d.verdict, d.leg) == (verdict, leg)
    assert text in d.reason
    if leg == "override":
        assert d.root == ROOT_B


# -- f9: HONEST needs a complete leg; reason precedence ------------------------------


def test_honest_needs_every_provider_to_answer():
    v = _inputs(
        finalized_ts=EPOCH_END,
        finalized_snapshot=ROOT_A,
        finalized_reads=R(ROOT_A, 1),
        total_providers=2,
    )
    d = decide_detail(v)
    assert d.verdict == Verdict.WAIT
    assert d.reason == "incomplete: 1 of 2 providers answered"
    complete = _inputs(
        finalized_ts=EPOCH_END,
        finalized_snapshot=ROOT_A,
        finalized_reads=R(ROOT_A, 2),
        total_providers=2,
    )
    assert decide(complete) == Verdict.HONEST


def test_incomplete_matching_finalized_leg_continues_to_the_next_leg():
    v = _inputs(
        finalized_ts=EPOCH_END,
        finalized_snapshot=ROOT_A,
        finalized_reads=R(ROOT_A, 1),
        latest_ts=EPOCH_END + SEQ_DELAY,
        latest_snapshot=ROOT_B,
        latest_reads=R(ROOT_B, 2),
        total_providers=2,
    )
    d = decide_detail(v)
    assert (d.verdict, d.leg, d.root) == (Verdict.CHALLENGE, "latest", ROOT_B)


def test_incomplete_matching_leg_then_override_near_the_deadline():
    v = _ovr(
        finalized_snapshot=ROOT_A,
        finalized_reads=R(ROOT_A, 1),
        latest_ts=EPOCH_END + SEQ_DELAY,
        latest_snapshot=ROOT_B,
        latest_reads=(ProviderRoot("inbox#1", ROOT_B),),
        total_providers=2,
    )
    d = decide_detail(v)
    assert (d.verdict, d.leg, d.root) == (Verdict.CHALLENGE, "override", ROOT_B)
    assert "inbox#1" in d.reason and "latest leg" in d.reason


def test_incomplete_matching_leg_without_override_waits():
    v = _inputs(
        finalized_ts=EPOCH_END,
        finalized_snapshot=ROOT_A,
        finalized_reads=R(ROOT_A, 1),
        latest_ts=EPOCH_END + SEQ_DELAY,
        latest_snapshot=ROOT_B,
        latest_reads=(ProviderRoot("inbox#1", ROOT_B),),
        total_providers=2,
    )
    d = decide_detail(v)
    assert d.verdict == Verdict.WAIT
    assert d.reason.startswith("insufficient agreement")  # outranks incomplete


def test_incomplete_counts_the_first_incomplete_immutable_leg():
    v = _inputs(
        finalized_ts=EPOCH_END - 1,  # not immutable: ignored
        finalized_snapshot=ROOT_A,
        finalized_reads=R(ROOT_A, 1),
        latest_ts=EPOCH_END + SEQ_DELAY,
        latest_snapshot=ROOT_A,
        latest_reads=R(ROOT_A, 2),
        total_providers=3,
    )
    d = decide_detail(v)
    assert d.reason == "incomplete: 2 of 3 providers answered"


def test_reason_order_split_then_insufficient_then_incomplete_then_none():
    split_leg = dict(
        finalized_ts=EPOCH_END,
        finalized_snapshot=None,
        finalized_reads=(ProviderRoot("a", ROOT_A), ProviderRoot("b", ROOT_B)),
    )
    short_leg = dict(
        latest_ts=EPOCH_END + SEQ_DELAY,
        latest_snapshot=ROOT_B,
        latest_reads=R(ROOT_B, 1),
    )
    # split + short: split wins
    d = decide_detail(_inputs(total_providers=3, **split_leg, **short_leg))
    assert d.reason.startswith("quorum split on finalized:")
    # short + incomplete matching: insufficient agreement wins
    d = decide_detail(
        _inputs(
            total_providers=3,
            finalized_ts=EPOCH_END,
            finalized_snapshot=ROOT_A,
            finalized_reads=R(ROOT_A, 2),
            **short_leg,
        )
    )
    assert d.reason.startswith("insufficient agreement")
    # incomplete alone
    d = decide_detail(
        _inputs(
            total_providers=3,
            finalized_ts=EPOCH_END,
            finalized_snapshot=ROOT_A,
            finalized_reads=R(ROOT_A, 2),
        )
    )
    assert d.reason == "incomplete: 2 of 3 providers answered"
    # nothing immutable
    assert decide_detail(_inputs()).reason == "no immutable read past the epoch end yet"


def test_override_declined_wraps_the_incomplete_reason():
    v = _ovr(
        finalized_snapshot=ROOT_A,
        finalized_reads=R(ROOT_A, 1),
        total_providers=2,
    )
    d = decide_detail(v)
    assert d.verdict == Verdict.WAIT
    assert d.reason.startswith("override declined: every immutable read equals the claim")
    assert "incomplete: 1 of 2 providers answered" in d.reason
