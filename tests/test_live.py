"""Read-only smoke tests against public Sepolia / Arbitrum Sepolia RPCs.

Opt-in: ``uv run pytest -m live``. No keys, no transactions.
"""

import pytest

from vea_challenger.chain import FINALIZED, LATEST, ChainClient
from vea_challenger.claims import Claim
from vea_challenger.config import BUILTIN_ROUTES
from vea_challenger.contracts import InboxContract, OutboxContract

pytestmark = pytest.mark.live

ROUTE = BUILTIN_ROUTES["arb-sepolia-to-sepolia-testnet"]


@pytest.fixture(scope="module")
def outbox():
    return OutboxContract(ChainClient(ROUTE.outbox_chain), ROUTE)


@pytest.fixture(scope="module")
def inbox():
    return InboxContract(ChainClient(ROUTE.inbox_chain), ROUTE)


def test_outbox_params(outbox):
    params = outbox.params()
    assert params.epoch_period == 7_200
    assert params.deposit == 10**18
    assert params.min_challenge_period == 10_800
    assert outbox.sequencer_delay_limit() > 0


def test_hash_claim_parity_against_contract(outbox):
    probe = Claim(
        state_root=b"\x11" * 32,
        claimer="0x00000000000000000000000000000000000000A1",
        timestamp_claimed=1_700_000_001,
        timestamp_verification=1_700_000_002,
        blocknumber_verification=12_345,
        honest=1,
        challenger="0x00000000000000000000000000000000000000B2",
    )
    assert outbox.hash_claim_onchain(probe) == probe.hash()


def test_inbox_finalized_quorum_read(inbox):
    view = inbox.l2_view(FINALIZED)
    assert view.timestamp > 1_700_000_000
    current_epoch = view.timestamp // 7_200
    read = inbox.snapshot_quorum(current_epoch - 2, FINALIZED)
    snap, snap_view, complete = read.root, read.view, read.complete
    assert isinstance(snap, bytes) and len(snap) == 32
    assert snap_view.number <= inbox.l2_view(LATEST).number
    assert complete in (True, False)


def test_outbox_event_scan(outbox):
    head = outbox.confirmed_head()
    events = outbox.fetch_events(head - 4_000, head, chunk=2_000)
    for ev in events:
        assert ev["name"] in (
            "Claimed", "Challenged", "VerificationStarted", "Verified", "FailedResolution",
        )


def test_finalized_tag_supported(inbox):
    assert inbox.client.supports_finalized()
