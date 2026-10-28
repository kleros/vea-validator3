"""SQLite store: idempotency, cursors, journal."""

from vea_challenger.claims import Claim, Party
from vea_challenger.store import (
    CHALLENGED,
    SEEN,
    ClaimRow,
    Store,
)


def _claim() -> Claim:
    return Claim(
        state_root=b"\x22" * 32,
        claimer="0x00000000000000000000000000000000000000A1",
        timestamp_claimed=1_700_000_000,
    )


def test_upsert_and_get(tmp_path):
    store = Store(tmp_path / "t.db")
    row = ClaimRow(epoch=7, status=SEEN, claim=_claim())
    store.upsert_claim(row)
    got = store.get_claim(7)
    assert got.status == SEEN
    assert got.claim == _claim()

    row.status = CHALLENGED
    row.challenge_tx = "0xabc"
    store.upsert_claim(row)
    got = store.get_claim(7)
    assert got.status == CHALLENGED
    assert got.challenge_tx == "0xabc"
    assert len(store.all_claims()) == 1


def test_active_claims_excludes_terminal(tmp_path):
    store = Store(tmp_path / "t.db")
    store.upsert_claim(ClaimRow(epoch=1, status=SEEN, claim=_claim()))
    store.upsert_claim(ClaimRow(epoch=2, status="HONEST", claim=_claim()))
    store.upsert_claim(ClaimRow(epoch=3, status="WITHDRAWN", claim=_claim()))
    store.upsert_claim(ClaimRow(epoch=4, status="MISSED", claim=_claim()))
    actives = store.active_claims()
    assert [r.epoch for r in actives] == [1]


def test_cursor_roundtrip(tmp_path):
    store = Store(tmp_path / "t.db")
    assert store.get_cursor("outbox_events") is None
    store.set_cursor("outbox_events", 123)
    assert store.get_cursor("outbox_events") == 123
    store.set_cursor("outbox_events", 456)
    assert store.get_cursor("outbox_events") == 456


def test_journal_lifecycle(tmp_path):
    store = Store(tmp_path / "t.db")
    jid = store.journal_intent(9, "challenge", "sepolia", "0xdead", 42)
    assert len(store.open_intents()) == 1
    store.journal_sent(jid, "0xhash")
    assert len(store.open_intents("challenge")) == 1
    store.journal_final(jid, "CONFIRMED")
    assert store.open_intents() == []


def test_reopen_persists(tmp_path):
    path = tmp_path / "t.db"
    store = Store(path)
    store.upsert_claim(ClaimRow(epoch=5, status=SEEN, claim=_claim()))
    store.close()
    store2 = Store(path)
    assert store2.get_claim(5).epoch == 5


def test_alerts_once_survive_reopen_and_clear_by_prefix(tmp_path):
    store = Store(tmp_path / "t.db")
    assert store.alert_sent("deadline:7:4h") is None
    store.mark_alert("deadline:7:4h", ts=100)
    store.mark_alert("deadline:7:1h", ts=200)
    store.mark_alert("shutdown:50", ts=300)
    store.close()

    store = Store(tmp_path / "t.db")
    assert store.alert_sent("deadline:7:4h") == 100
    store.mark_alert("deadline:7:4h", ts=150)
    assert store.alert_sent("deadline:7:4h") == 150
    store.clear_alerts("deadline:7:")
    assert store.alert_sent("deadline:7:4h") is None
    assert store.alert_sent("deadline:7:1h") is None
    assert store.alert_sent("shutdown:50") == 300
