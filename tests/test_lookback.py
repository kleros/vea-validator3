"""First-run event lookback (PRD 2.4), with Chiado parameters and 5 s blocks."""

import logging

import pytest

from vea_challenger.contracts import OutboxParams
from vea_challenger.detector import Detector
from vea_challenger.store import Store

from conftest import FakeInbox, FakeNotifier, FakeOutbox

HEAD_BLOCK = 2_000_000  # confirmed head (head - confirmations)
BLOCK_TIME = 5
# epoch_period + sequencer_delay + min_challenge_period + epoch_period + 7200
BUDGET = 3_600 + 86_400 + 7_200 + 3_600 + 7_200  # 108_000 s
DERIVED = BUDGET // BLOCK_TIME  # 21_600 blocks, exact


@pytest.fixture
def chiado():
    return OutboxParams(
        deposit=10**18, epoch_period=3_600, min_challenge_period=7_200, timeout_epochs=10
    )


def _detector(tmp_path, params, lookback=None, block_time=BLOCK_TIME):
    store = Store(tmp_path / "t.db")
    outbox = FakeOutbox()
    outbox.head = HEAD_BLOCK + outbox.confirmations
    outbox.seq_delay = 86_400
    base = 1_700_000_000
    outbox.block_timestamps[HEAD_BLOCK] = base + HEAD_BLOCK * block_time
    outbox.block_timestamps[HEAD_BLOCK - 1_000] = base + (HEAD_BLOCK - 1_000) * block_time
    seen = {}
    outbox.fetch_events = lambda a, b, c: seen.setdefault("range", (a, b)) and []
    d = Detector(
        store, outbox, FakeInbox(), params, FakeNotifier(), None, devnet=False,
        genesis_lookback_blocks=lookback,
    )
    return d, store, seen


def test_first_run_starts_at_derived_window(tmp_path, chiado, caplog):
    d, store, seen = _detector(tmp_path, chiado)
    with caplog.at_level(logging.INFO, logger="vea_challenger.detector"):
        d.sync_events()
    # fetch_events is called with cursor + 1
    assert seen["range"] == (HEAD_BLOCK - DERIVED + 1, HEAD_BLOCK)
    assert f"{BUDGET} s" in caplog.text and f"{DERIVED} blocks" in caplog.text


def test_block_time_rounds_up(tmp_path, chiado):
    d, _, seen = _detector(tmp_path, chiado, block_time=7)
    d.sync_events()
    blocks = -(-BUDGET // 7)
    assert seen["range"][0] == HEAD_BLOCK - blocks + 1


def test_smaller_override_is_ignored_with_warning(tmp_path, chiado, caplog):
    d, _, seen = _detector(tmp_path, chiado, lookback=1_000)
    with caplog.at_level(logging.WARNING, logger="vea_challenger.detector"):
        d.sync_events()
    assert seen["range"][0] == HEAD_BLOCK - DERIVED + 1
    assert any(r.levelno == logging.WARNING and "ignoring" in r.message for r in caplog.records)


def test_larger_override_widens_window(tmp_path, chiado):
    d, _, seen = _detector(tmp_path, chiado, lookback=DERIVED + 5_000)
    d.sync_events()
    assert seen["range"][0] == HEAD_BLOCK - DERIVED - 5_000 + 1


def test_existing_cursor_is_not_rewound(tmp_path, chiado):
    d, store, seen = _detector(tmp_path, chiado)
    store.set_cursor("outbox_events", HEAD_BLOCK - 10)
    d.sync_events()
    assert seen["range"] == (HEAD_BLOCK - 9, HEAD_BLOCK)


@pytest.mark.parametrize("confirmed", [0, 1])
def test_head_too_young_to_sample_scans_from_block_zero(tmp_path, chiado, caplog, confirmed):
    d, store, seen = _detector(tmp_path, chiado)
    d.outbox.head = confirmed + d.outbox.confirmations
    with caplog.at_level(logging.WARNING, logger="vea_challenger.detector"):
        d.sync_events()  # must not raise
    assert any("starts at block 0" in r.message for r in caplog.records)
    if confirmed:
        assert seen["range"] == (1, confirmed)
    assert store.get_cursor("outbox_events") == (confirmed or None)
