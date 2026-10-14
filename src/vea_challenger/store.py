"""SQLite persistence: claim state machine, scan cursors, tx journal.

All writes are idempotent; the process can crash at any point and resume.
Transaction *intent* is journaled before broadcast so an in-flight tx can be
recovered after a restart (by nonce + on-chain scan) instead of double-spent.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

from .claims import Claim

# Claim lifecycle states.
SEEN = "SEEN"  # claim observed, verdict pending
UNDECIDED = "UNDECIDED"  # waiting for finality past epoch end
HONEST = "HONEST"  # root matches; terminal
CHALLENGE_PENDING = "CHALLENGE_PENDING"  # mismatch found, our challenge tx in flight
CHALLENGED = "CHALLENGED"  # our challenge confirmed on-chain
CHALLENGED_BY_OTHER = "CHALLENGED_BY_OTHER"  # someone else challenged first
SNAPSHOT_SENT = "SNAPSHOT_SENT"  # inbox.sendSnapshot confirmed on L2
L1_EXECUTED = "L1_EXECUTED"  # Arbitrum outbox executeTransaction confirmed
RESOLVED = "RESOLVED"  # Verified with honest == Challenger (us)
WITHDRAWN = "WITHDRAWN"  # deposit + reward withdrawn; terminal
MISSED = "MISSED"  # claim verified before we could act; terminal
LOST = "LOST"  # resolution ruled the claimer honest; terminal
DESYNC = "DESYNC"  # cannot reconstruct on-chain claim hash; needs a human
# Verified as honest (honest == Claimer) while we never reached a verdict of our
# own (SEEN/UNDECIDED); terminal, and always paged. HONEST is reserved for rows
# that Detector.evaluate() ruled honest.
VERIFIED_UNDECIDED = "VERIFIED_UNDECIDED"

ACTIVE_STATES = (
    SEEN,
    UNDECIDED,
    CHALLENGE_PENDING,
    CHALLENGED,
    # Reconciled every tick (a third-party challenge can be reorged out), but
    # neither challenged nor resolved by us while it stays in this state.
    CHALLENGED_BY_OTHER,
    SNAPSHOT_SENT,
    L1_EXECUTED,
    RESOLVED,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS claims (
    epoch INTEGER PRIMARY KEY,
    status TEXT NOT NULL,
    claim_json TEXT NOT NULL,
    true_root TEXT,
    challenge_tx TEXT,
    snapshot_tx TEXT,
    l2tol1_json TEXT,
    execute_tx TEXT,
    withdraw_tx TEXT,
    note TEXT,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cursors (
    name TEXT PRIMARY KEY,
    block INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tx_journal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    epoch INTEGER NOT NULL,
    action TEXT NOT NULL,
    chain TEXT NOT NULL,
    sender TEXT NOT NULL,
    nonce INTEGER,
    tx_hash TEXT,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    max_fee_per_gas TEXT,
    max_priority_fee_per_gas TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    key TEXT PRIMARY KEY,
    sent_at INTEGER NOT NULL
);
"""


@dataclass
class ClaimRow:
    epoch: int
    status: str
    claim: Claim
    true_root: str | None = None
    challenge_tx: str | None = None
    snapshot_tx: str | None = None
    l2tol1_json: str | None = None
    execute_tx: str | None = None
    withdraw_tx: str | None = None
    note: str | None = None


class Store:
    def __init__(self, path: Path | str):
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.executescript(_SCHEMA)
        # Journals created before the fee columns existed: add them (NULL fees).
        cols = {r["name"] for r in self._conn.execute("PRAGMA table_info(tx_journal)")}
        for col in ("max_fee_per_gas", "max_priority_fee_per_gas"):
            if col not in cols:
                self._conn.execute(f"ALTER TABLE tx_journal ADD COLUMN {col} TEXT")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- claims ---------------------------------------------------------------

    def upsert_claim(self, row: ClaimRow) -> None:
        self._conn.execute(
            """
            INSERT INTO claims (epoch, status, claim_json, true_root, challenge_tx,
                                snapshot_tx, l2tol1_json, execute_tx, withdraw_tx, note, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(epoch) DO UPDATE SET
                status=excluded.status, claim_json=excluded.claim_json,
                true_root=excluded.true_root, challenge_tx=excluded.challenge_tx,
                snapshot_tx=excluded.snapshot_tx, l2tol1_json=excluded.l2tol1_json,
                execute_tx=excluded.execute_tx, withdraw_tx=excluded.withdraw_tx,
                note=excluded.note, updated_at=excluded.updated_at
            """,
            (
                row.epoch,
                row.status,
                row.claim.to_json(),
                row.true_root,
                row.challenge_tx,
                row.snapshot_tx,
                row.l2tol1_json,
                row.execute_tx,
                row.withdraw_tx,
                row.note,
                int(time.time()),
            ),
        )
        self._conn.commit()

    def get_claim(self, epoch: int) -> ClaimRow | None:
        cur = self._conn.execute("SELECT * FROM claims WHERE epoch = ?", (epoch,))
        r = cur.fetchone()
        return self._to_row(r) if r else None

    def active_claims(self) -> list[ClaimRow]:
        marks = ",".join("?" * len(ACTIVE_STATES))
        cur = self._conn.execute(
            f"SELECT * FROM claims WHERE status IN ({marks}) ORDER BY epoch", ACTIVE_STATES
        )
        return [self._to_row(r) for r in cur.fetchall()]

    def all_claims(self) -> list[ClaimRow]:
        cur = self._conn.execute("SELECT * FROM claims ORDER BY epoch")
        return [self._to_row(r) for r in cur.fetchall()]

    @staticmethod
    def _to_row(r: sqlite3.Row) -> ClaimRow:
        return ClaimRow(
            epoch=r["epoch"],
            status=r["status"],
            claim=Claim.from_json(r["claim_json"]),
            true_root=r["true_root"],
            challenge_tx=r["challenge_tx"],
            snapshot_tx=r["snapshot_tx"],
            l2tol1_json=r["l2tol1_json"],
            execute_tx=r["execute_tx"],
            withdraw_tx=r["withdraw_tx"],
            note=r["note"],
        )

    # -- cursors --------------------------------------------------------------

    def get_cursor(self, name: str) -> int | None:
        cur = self._conn.execute("SELECT block FROM cursors WHERE name = ?", (name,))
        r = cur.fetchone()
        return r["block"] if r else None

    def set_cursor(self, name: str, block: int) -> None:
        self._conn.execute(
            "INSERT INTO cursors (name, block) VALUES (?, ?) "
            "ON CONFLICT(name) DO UPDATE SET block=excluded.block",
            (name, block),
        )
        self._conn.commit()

    # -- tx journal -----------------------------------------------------------

    def journal_intent(
        self,
        epoch: int,
        action: str,
        chain: str,
        sender: str,
        nonce: int,
        fees: tuple[int, int] | None = None,
    ) -> int:
        """``fees`` is (maxFeePerGas, maxPriorityFeePerGas) as signed; wei values are
        kept as TEXT because they can exceed SQLite's 64-bit INTEGER."""
        max_fee, max_prio = (str(fees[0]), str(fees[1])) if fees else (None, None)
        cur = self._conn.execute(
            "INSERT INTO tx_journal (epoch, action, chain, sender, nonce, status, created_at, "
            "max_fee_per_gas, max_priority_fee_per_gas) "
            "VALUES (?, ?, ?, ?, ?, 'INTENT', ?, ?, ?)",
            (epoch, action, chain, sender, nonce, int(time.time()), max_fee, max_prio),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def journal_fees(self, chain: str, sender: str, nonce: int) -> list[tuple[int, int, bool]]:
        """Every (maxFeePerGas, maxPriorityFeePerGas, broadcast) journaled at this
        nonce; ``broadcast`` is whether the attempt got a tx hash."""
        rows = self._conn.execute(
            "SELECT max_fee_per_gas, max_priority_fee_per_gas, tx_hash FROM tx_journal "
            "WHERE chain = ? AND sender = ? AND nonce = ? AND max_fee_per_gas IS NOT NULL",
            (chain, sender, nonce),
        ).fetchall()
        return [
            (int(r["max_fee_per_gas"]), int(r["max_priority_fee_per_gas"]), r["tx_hash"] is not None)
            for r in rows
        ]

    def journal_sent(self, journal_id: int, tx_hash: str) -> None:
        self._conn.execute(
            "UPDATE tx_journal SET tx_hash = ?, status = 'SENT' WHERE id = ?",
            (tx_hash, journal_id),
        )
        self._conn.commit()

    def journal_final(self, journal_id: int, status: str) -> None:
        self._conn.execute(
            "UPDATE tx_journal SET status = ? WHERE id = ?", (status, journal_id)
        )
        self._conn.commit()

    def open_intents(self, action: str | None = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM tx_journal WHERE status IN ('INTENT', 'SENT')"
        args: tuple = ()
        if action:
            q += " AND action = ?"
            args = (action,)
        return self._conn.execute(q, args).fetchall()

    # -- alert de-duplication -------------------------------------------------
    # Keys are free-form strings chosen by the caller, e.g. "deadline:<epoch>:4h".
    # They survive a restart so a once-only alert is not repeated after one.

    def alert_sent(self, key: str) -> int | None:
        """Unix time the alert `key` was last marked as sent, or None."""
        r = self._conn.execute("SELECT sent_at FROM alerts WHERE key = ?", (key,)).fetchone()
        return int(r["sent_at"]) if r else None

    def mark_alert(self, key: str, ts: int | None = None) -> None:
        self._conn.execute(
            "INSERT INTO alerts (key, sent_at) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET sent_at=excluded.sent_at",
            (key, int(time.time()) if ts is None else int(ts)),
        )
        self._conn.commit()

    def clear_alerts(self, prefix: str) -> None:
        """Forget every alert whose key starts with `prefix`."""
        self._conn.execute(
            "DELETE FROM alerts WHERE substr(key, 1, ?) = ?", (len(prefix), prefix)
        )
        self._conn.commit()
