"""Shared fakes for detector/challenger tests."""

from dataclasses import dataclass, field

import pytest

from vea_challenger.claims import Claim, hash_claim
from vea_challenger.contracts import L2View, OutboxParams, QuorumRead
from vea_challenger.verdict import ProviderRoot


@dataclass
class FakeNotifier:
    messages: list = field(default_factory=list)

    def send(self, level, message):
        self.messages.append((level, message))

    def has(self, level, needle=""):
        return any(l == level and needle in m for l, m in self.messages)


class FakeOutbox:
    """Stands in for OutboxContract: events + claim hashes + clocks."""

    def __init__(self):
        self.events: list[dict] = []
        self.claim_hashes: dict[int, bytes] = {}
        self.block_timestamps: dict[int, int] = {}
        self.head = 1_000
        self.confirmations = 3
        self._now = 0
        self.seq_delay = 86_400
        self.latest_verified = 0

    def confirmed_head(self):
        return self.head - self.confirmations

    def fetch_events(self, from_block, to_block, chunk):
        return [
            e for e in self.events if from_block <= e["block_number"] <= to_block
        ]

    def block_timestamp(self, n):
        return self.block_timestamps[n]

    def claim_hash(self, epoch):
        return self.claim_hashes.get(epoch, b"\x00" * 32)

    def now(self):
        return self._now

    def sequencer_delay_limit(self):
        return self.seq_delay

    def latest_verified_epoch(self):
        return self.latest_verified


class FakeInbox:
    """snapshot_quorum stand-in with per-tag values.

    Two configured providers, labelled ``inbox#0`` and ``inbox#1``. By default
    both answer the tag's value. ``complete = False`` leaves ``inbox#1`` out;
    ``quorum_split = True`` makes ``inbox#1`` answer a different root. For
    finer cases set ``reads[tag]`` to a QuorumRead returned as is.
    """

    LABELS = ("inbox#0", "inbox#1")
    SPLIT_ROOT = b"\x5e" * 32

    def __init__(self):
        self.finalized: tuple[bytes, L2View] | None = None
        self.latest: tuple[bytes, L2View] | None = None
        self.quorum_split = False
        self.complete = True  # every configured RPC answered
        self.reads: dict[str, QuorumRead] = {}

    def snapshot_quorum(self, epoch, tag):
        if tag in self.reads:
            return self.reads[tag]
        value = self.finalized if tag == "finalized" else self.latest
        if self.quorum_split:
            # Splits regardless of the tag's value, as the old fake did.
            root, view = value or (b"\x00" * 32, L2View(timestamp=0, number=0))
            other = self.SPLIT_ROOT if root != self.SPLIT_ROOT else b"\x5f" * 32
            reads = (ProviderRoot(self.LABELS[0], root), ProviderRoot(self.LABELS[1], other))
            return QuorumRead(None, view, reads, ())
        if value is None:
            raise RuntimeError("no data")
        root, view = value
        first = ProviderRoot(self.LABELS[0], root)
        if not self.complete:
            return QuorumRead(root, view, (first,), (self.LABELS[1],))
        return QuorumRead(root, view, (first, ProviderRoot(self.LABELS[1], root)), ())


@pytest.fixture
def params():
    return OutboxParams(
        deposit=10**18, epoch_period=7_200, min_challenge_period=10_800, timeout_epochs=10
    )
