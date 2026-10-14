"""Pure verdict logic: is a claim honest, fraudulent, or undecidable (yet)?

Safety rules (from the red-teamed design):

- A verdict may only come from inbox state that can no longer change:
  * the ``finalized`` tag once the finalized L2 timestamp passes the epoch end
    (finalized history cannot be reorged or backdated into), or
  * the ``latest`` tag once the latest L2 timestamp passes
    ``epoch end + sequencerDelayLimit`` — before that, a malicious sequencer can
    still backdate a ``saveSnapshot`` into the epoch, and N-of-M RPC agreement
    is no protection because every RPC mirrors the same sequencer feed.
- ``snapshots(epoch) == 0x0`` (nobody saved a snapshot) makes ANY claim for that
  epoch fraudulent, since resolution forwards the zero root.
- HONEST is irreversible (we stop tracking), so a leg only rules HONEST when
  every configured provider answered it (``*_reads`` count == ``total_providers``).
  An incomplete matching leg does not decide; evaluation goes on to the next leg
  and then to the deadline override.

When nothing decides, the WAIT reason is the first of these that applies:

1. ``quorum split on <leg>: <label>=<root>, ...`` (a split leg that could have decided)
2. ``insufficient agreement for epoch <E>: <n> provider(s) (<labels>) agree on a
   mismatch, fewer than <min_agreement>``
3. ``incomplete: <answered> of <total> providers answered`` (first incomplete
   immutable leg)
4. ``no immutable read past the epoch end yet``

The deadline override wraps that reason in ``override declined: ...`` or answers
CHALLENGE.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Verdict(Enum):
    WAIT = "wait"  # cannot decide yet; keep polling
    HONEST = "honest"  # claimed root == immutable snapshot
    CHALLENGE = "challenge"  # claimed root != immutable snapshot


@dataclass(frozen=True)
class ProviderRoot:
    """One provider's answer for snapshots(epoch) at a pinned block."""

    label: str  # e.g. "arbitrum-sepolia#1 (arb-sepolia.g.alchemy.com)"
    root: bytes


@dataclass(frozen=True)
class VerdictInputs:
    epoch: int
    claimed_root: bytes
    epoch_period: int
    sequencer_delay: int
    # Quorum reads of the inbox chain; None when the read failed / disagreed.
    finalized_ts: int | None
    finalized_snapshot: bytes | None
    latest_ts: int | None
    latest_snapshot: bytes | None
    # Each answering provider's root per leg, including on a split (where the
    # *_snapshot field above is None). Empty when the leg's read failed.
    finalized_reads: tuple[ProviderRoot, ...] = ()
    latest_reads: tuple[ProviderRoot, ...] = ()
    total_providers: int = 0  # configured inbox RPCs
    # CHALLENGE needs at least this many agreeing answers (PRD 1.2).
    min_agreement: int = 1
    # Deadline override (PRD 1.1): outbox-chain clock and the earliest
    # verification time (earliest_verification_ts); None disables it.
    now: int | None = None
    deadline: int | None = None
    devnet: bool = False
    challenge_on_ambiguity: bool = False

    @property
    def epoch_end(self) -> int:
        return (self.epoch + 1) * self.epoch_period


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    # Root of the leg that decided (PRD 1.5); None for WAIT.
    root: bytes | None = None
    # "finalized", "latest" or "override" (the 1.1 deadline override); None for WAIT.
    leg: str | None = None
    # Why the verdict is WAIT (or how an override was reached); free text for
    # alerts and the row note, e.g. "incomplete: 1 of 2 providers answered".
    reason: str = ""


# The deadline override acts this long before the earliest verification time.
OVERRIDE_WINDOW = 15 * 60


def _agreeing(reads: tuple[ProviderRoot, ...], root: bytes) -> list[ProviderRoot]:
    return [r for r in reads if r.root == root]


def decide_detail(v: VerdictInputs) -> Decision:
    # (leg, ts, snapshot, reads, boundary): finalized data past the epoch end is
    # immutable; latest data is only once it is older than the backdating window.
    legs = (
        ("finalized", v.finalized_ts, v.finalized_snapshot, v.finalized_reads, v.epoch_end),
        (
            "latest",
            v.latest_ts,
            v.latest_snapshot,
            v.latest_reads,
            v.epoch_end + v.sequencer_delay,
        ),
    )
    short: list[ProviderRoot] = []  # largest agreeing mismatch group of a short leg
    split: list[str] = []  # one "quorum split on <leg>: ..." text per split leg
    incomplete: tuple[int, int] | None = None  # (answered, total) of the first one
    for leg, ts, snapshot, _reads, boundary in legs:
        if ts is None or ts < boundary:
            continue
        if snapshot is None:
            split.append(
                f"quorum split on {leg}: "
                + ", ".join(f"{r.label}=0x{r.root.hex()}" for r in _reads)
            )
            continue
        complete = v.total_providers <= 0 or len(_reads) >= v.total_providers
        if not complete and incomplete is None:
            incomplete = (len(_reads), v.total_providers)
        if snapshot == v.claimed_root:
            if complete:
                return Decision(Verdict.HONEST, snapshot, leg)
            continue
        agreeing = _agreeing(_reads, snapshot)
        if len(agreeing) >= v.min_agreement:
            return Decision(Verdict.CHALLENGE, snapshot, leg)
        if len(agreeing) > len(short):
            short = agreeing

    if split:
        reason = "; ".join(split)
    elif short:
        reason = (
            f"insufficient agreement for epoch {v.epoch}: {len(short)} provider(s) "
            f"({', '.join(r.label for r in short)}) agree on a mismatch, "
            f"fewer than {v.min_agreement}"
        )
    elif incomplete is not None:
        reason = f"incomplete: {incomplete[0]} of {incomplete[1]} providers answered"
    else:
        reason = "no immutable read past the epoch end yet"

    # Deadline override (PRD 1.1): opt-in, never on devnet, only near the deadline.
    if (
        v.challenge_on_ambiguity
        and not v.devnet
        and v.now is not None
        and v.deadline is not None
        and v.now >= v.deadline - OVERRIDE_WINDOW
    ):
        immutable = [
            (leg, r)
            for leg, ts, _s, reads, boundary in legs
            if ts is not None and ts >= boundary
            for r in reads
        ]
        if not immutable:
            return Decision(
                Verdict.WAIT, reason=f"override declined: no immutable read ({reason})"
            )
        for leg, r in immutable:
            if r.root != v.claimed_root:
                return Decision(
                    Verdict.CHALLENGE,
                    r.root,
                    "override",
                    f"deadline override: {r.label} read a root differing from the "
                    f"claim in the {leg} leg ({reason})",
                )
        return Decision(
            Verdict.WAIT,
            reason=f"override declined: every immutable read equals the claim ({reason})",
        )
    return Decision(Verdict.WAIT, reason=reason)


def decide(v: VerdictInputs) -> Verdict:
    return decide_detail(v).verdict


def earliest_verification_ts(
    timestamp_claimed: int,
    epoch_period: int,
    sequencer_delay: int,
    min_challenge_period: int,
    devnet: bool,
) -> int:
    """Earliest outbox-chain time at which verifySnapshot can possibly succeed.

    This is the hard deadline for landing a challenge. Devnet outboxes skip both
    the sequencer-delay wait and the censorship test, so the deadline is
    effectively "immediately after the claim".
    """
    if devnet:
        return timestamp_claimed
    return timestamp_claimed + epoch_period + sequencer_delay + min_challenge_period
