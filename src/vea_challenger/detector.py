"""Event sync, claim-struct reconstruction, and verdict evaluation.

The detector scans outbox events into the SQLite state machine, keeps each
tracked Claim struct byte-identical to the on-chain ``claimHashes`` preimage
(including probing for the event-less escape-hatch mutations and the ambiguous
``Verified`` winner), and evaluates verdicts against quorum inbox reads.
"""

from __future__ import annotations

import json
import logging
import math
import time

from .arbitrum import decode_claim_from_l2tol1_data
from .chain import FINALIZED, LATEST, AllProvidersFailed, redact
from .claims import ZERO_ADDRESS, Claim, Party, find_matching
from .contracts import InboxContract, OutboxContract, OutboxParams
from .notify import CRITICAL, INFO, WARNING, Notifier
from .store import (
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
from .verdict import Verdict, VerdictInputs, decide_detail, earliest_verification_ts

log = logging.getLogger(__name__)

_OUR_CHALLENGE_STATES = (CHALLENGE_PENDING, CHALLENGED, SNAPSHOT_SENT, L1_EXECUTED)
# Rows whose challenge can be reverted (reorg, escape hatch) back to a challengeable state.
_REVERTIBLE = (CHALLENGED, SNAPSHOT_SENT, L1_EXECUTED, CHALLENGED_BY_OTHER)
_VERIFIABLE = (SEEN, UNDECIDED, CHALLENGE_PENDING, *_REVERTIBLE)

# State a non-archive node still holds: a pinned claimHashes read is only used
# within this many blocks of confirmed_head() (design [L6]).
STATE_WINDOW = 64
# A revert held by the receipt gate this long pages CRITICAL (then hourly).
REORG_STUCK_AFTER = 600
_EVENT_FAILED = "event-failed:"  # alerts-table keys: one page per failing event
_PARTIAL_SCAN = "scan-partial"  # alerts-table flag: sync_events stopped mid-block
FRAUD_NOT_LANDED = "fraud verified before our challenge landed"

_BLOCK_TIME_SAMPLE = 1_000
_LOOKBACK_MARGIN = 7_200
_SINGLE_SOURCE_ALERT_INTERVAL = 3_600


class Detector:
    def __init__(
        self,
        store: Store,
        outbox: OutboxContract,
        inbox: InboxContract,
        params: OutboxParams,
        notifier: Notifier,
        challenge_address: str | None,
        devnet: bool,
        log_scan_chunk: int = 5_000,
        genesis_lookback_blocks: int | None = None,
        min_challenge_agreement: int = 2,
        challenge_on_ambiguity: bool = False,
    ):
        self.store = store
        self.outbox = outbox
        self.inbox = inbox
        self.params = params
        self.notifier = notifier
        self.challenge_address = challenge_address
        self.devnet = devnet
        self.log_scan_chunk = log_scan_chunk
        # Operator override of the first-run lookback (PRD 2.4); None: derived.
        self.genesis_lookback_blocks = genesis_lookback_blocks
        self.min_challenge_agreement = min_challenge_agreement
        self.challenge_on_ambiguity = challenge_on_ambiguity
        self._window_logged: dict[int, float] = {}  # epoch -> last out-of-window log

    # -- event sync ------------------------------------------------------------

    def sync_events(self) -> None:
        head = self.outbox.confirmed_head()
        cursor = self.store.get_cursor("outbox_events")
        if cursor is None:
            cursor = max(0, head - self._lookback_blocks(head))
        if head <= cursor:
            return
        events = self.outbox.fetch_events(cursor + 1, head, self.log_scan_chunk)
        applied_blocks: set[int] = set()
        for ev in events:
            try:
                self._apply_event(ev)
                applied_blocks.add(ev["block_number"])
            except Exception:  # noqa: BLE001
                # Do NOT skip past a failed event: a dropped Claimed is a fraud
                # the bot would never track. Rewind the cursor to just before it
                # and retry the range next tick (all handlers are idempotent).
                log.exception("failed applying event %s", ev)
                fail_key = (
                    f"{_EVENT_FAILED}{ev['block_number']}:{ev.get('log_index')}:{ev['name']}"
                )
                if self.store.alert_sent(fail_key) is None:
                    self.notifier.send(
                        CRITICAL, f"event processing failed (will retry next tick): {ev}"
                    )
                    self.store.mark_alert(fail_key)
                self.store.set_cursor("outbox_events", ev["block_number"] - 1)
                if ev["block_number"] in applied_blocks:
                    # Earlier events of that block are already applied, so the
                    # rows run ahead of the chain state at the rewound cursor:
                    # reconcile takes no transition until a scan completes.
                    self.store.mark_alert(_PARTIAL_SCAN, ev["block_number"])
                else:
                    # A failure at a block <= the stored flag keeps it: an earlier
                    # tick may have applied part of that block. A failure at a
                    # later block means the flagged block is complete.
                    flagged = self.store.alert_sent(_PARTIAL_SCAN)
                    if flagged is not None and ev["block_number"] > flagged:
                        self.store.clear_alerts(_PARTIAL_SCAN)
                return
        self.store.set_cursor("outbox_events", head)
        self.store.clear_alerts(_EVENT_FAILED)
        if self.store.alert_sent(_PARTIAL_SCAN) is not None:
            self.store.clear_alerts(_PARTIAL_SCAN)

    def _lookback_blocks(self, head: int) -> int:
        """First-run window: every claim that can still be challenged (PRD 2.4)."""
        budget = (
            self.params.epoch_period
            + self.outbox.sequencer_delay_limit()
            + self.params.min_challenge_period
            + self.params.epoch_period
            + _LOOKBACK_MARGIN
        )
        sample = min(_BLOCK_TIME_SAMPLE, head - 1)
        block_time = 0.0
        if sample > 0:
            block_time = (
                self.outbox.block_timestamp(head) - self.outbox.block_timestamp(head - sample)
            ) / sample
        if block_time <= 0:
            # A head too young to sample (fresh chain): scan from the start.
            log.warning(
                "cannot derive block time from blocks %s..%s (head too young); "
                "first-run scan starts at block 0",
                head - sample,
                head,
            )
            return max(0, head)
        derived = math.ceil(budget / block_time)
        blocks = derived
        if self.genesis_lookback_blocks is not None:
            if self.genesis_lookback_blocks < derived:
                log.warning(
                    "genesis_lookback_blocks=%s is smaller than the derived window of %s "
                    "blocks; ignoring it",
                    self.genesis_lookback_blocks,
                    derived,
                )
            else:
                blocks = self.genesis_lookback_blocks
        log.info(
            "first run: scanning back %s s = %s blocks (block time %.3f s) from block %s",
            budget,
            blocks,
            block_time,
            head,
        )
        return blocks

    def _apply_event(self, ev: dict) -> None:
        name, args = ev["name"], ev["args"]
        if name == "Claimed":
            epoch = int(args["_epoch"])
            ts = self.outbox.block_timestamp(ev["block_number"])
            claim = Claim(
                state_root=bytes(args["_stateRoot"]),
                claimer=args["_claimer"],
                timestamp_claimed=ts,
            )
            existing = self.store.get_claim(epoch)
            if existing is not None:
                return  # duplicate scan
            self.store.upsert_claim(ClaimRow(epoch=epoch, status=SEEN, claim=claim))
            self.notifier.send(
                INFO,
                f"claim seen: epoch={epoch} claimer={claim.claimer} "
                f"root=0x{claim.state_root.hex()}",
            )
            return

        epoch = int(args["_epoch"]) if "_epoch" in args else int(args.get("_epochSent", -1))
        row = self.store.get_claim(epoch)
        if row is None:
            return  # event for a claim from before our lookback window

        if name == "VerificationStarted":
            ts = self.outbox.block_timestamp(ev["block_number"])
            row.claim = Claim(
                state_root=row.claim.state_root,
                claimer=row.claim.claimer,
                timestamp_claimed=row.claim.timestamp_claimed,
                timestamp_verification=ts,
                blocknumber_verification=ev["block_number"],
                honest=row.claim.honest,
                challenger=row.claim.challenger,
            )
            self.store.upsert_claim(row)

        elif name == "Challenged":
            challenger = args["_challenger"]
            row.claim = Claim(
                state_root=row.claim.state_root,
                claimer=row.claim.claimer,
                timestamp_claimed=row.claim.timestamp_claimed,
                timestamp_verification=row.claim.timestamp_verification,
                blocknumber_verification=row.claim.blocknumber_verification,
                honest=row.claim.honest,
                challenger=challenger,
            )
            ours = (
                self.challenge_address is not None
                and challenger.lower() == self.challenge_address.lower()
            )
            # Only transition rows that haven't advanced past the challenge
            # stage: a rescan of an old Challenged event must not drag a
            # SNAPSHOT_SENT/RESOLVED row backwards.
            pre_challenge = row.status in (SEEN, UNDECIDED, CHALLENGE_PENDING)
            if ours:
                if pre_challenge:
                    row.status = CHALLENGED
                row.challenge_tx = row.challenge_tx or ev["tx_hash"]
                self.notifier.send(INFO, f"our challenge confirmed for epoch {epoch}")
            elif pre_challenge:
                # Includes CHALLENGE_PENDING: a third party front-ran our
                # challenge; stand down (the fraud is handled either way).
                row.status = CHALLENGED_BY_OTHER
                self.notifier.send(
                    WARNING, f"epoch {epoch} challenged by third party {challenger}"
                )
            self.store.upsert_claim(row)

        elif name == "Verified":
            self._apply_verified(row, ev["block_number"])

        elif name == "FailedResolution":
            if row.status in (SNAPSHOT_SENT, L1_EXECUTED) and self._pending_message_current(
                row, ev["block_number"]
            ):
                # The event names only the epoch, and sendSnapshot is
                # permissionless: a message carrying the current struct cannot
                # fail, so this was someone else's stale one. Keep our round trip.
                log.warning(
                    "epoch %s: FailedResolution at block %s is not ours (our pending "
                    "message still matches claimHashes); keeping %s",
                    epoch,
                    ev["block_number"],
                    row.status,
                )
                self.notifier.send(
                    WARNING,
                    f"epoch {epoch}: FailedResolution not ours (a third party's stale "
                    "snapshot); our pending resolution continues",
                )
            elif row.status in (SNAPSHOT_SENT, L1_EXECUTED):
                row.status = CHALLENGED
                row.snapshot_tx = None
                row.l2tol1_json = None
                row.execute_tx = None
                row.note = "FailedResolution: stale struct sent; will re-send snapshot"
                self.store.upsert_claim(row)
                self.notifier.send(
                    CRITICAL,
                    f"resolution FAILED for epoch {epoch} (stale claim struct); re-sending",
                )

    def _pending_message_current(self, row: ClaimRow, block: int) -> bool:
        """Does our journaled L2->L1 message carry the struct claimHashes(epoch)
        holds at `block`? False when unknown (no/undecodable message, unreadable
        hash): the caller then resets as for our own stale message."""
        if not row.l2tol1_json:
            return False
        try:
            carried = decode_claim_from_l2tol1_data(
                json.loads(row.l2tol1_json)["data"], row.epoch
            )
        except Exception as exc:  # noqa: BLE001 - treat as our message failing
            log.warning("epoch %s: cannot decode our pending message: %s", row.epoch, exc)
            return False
        if carried is None:
            return False
        onchain = self._claim_hash_for_event(row.epoch, block)
        return onchain is not None and carried.hash() == onchain

    # -- confirmed-height reads --------------------------------------------------

    def _in_window(self, block: int) -> bool:
        """Is `block` recent enough for a non-archive node to serve its state?"""
        return block >= self.outbox.confirmed_head() - STATE_WINDOW

    def _scan_block(self) -> int:
        """The block the event scan has reached (before the first scan: the head)."""
        cursor = self.store.get_cursor("outbox_events")
        return cursor if cursor is not None else self.outbox.confirmed_head()

    def _log_out_of_window(self, epoch: int, block: int, why: str) -> None:
        now = time.time()
        last = self._window_logged.get(epoch)
        if last is None or now - last >= _SINGLE_SOURCE_ALERT_INTERVAL:
            self._window_logged[epoch] = now
            log.warning(
                "epoch %s: claimHashes at block %s is %s; reconcile takes no transition",
                epoch,
                block,
                why,
            )

    def _claim_hash_for_event(self, epoch: int, block: int | None) -> bytes | None:
        """claimHashes(epoch) at the event's block while that state is held,
        else at latest. A failed latest read returns None (no transition, never
        raises into the scan)."""
        in_window = block is not None and self._in_window(block)
        if in_window:
            try:
                return self.outbox.claim_hash(epoch, block=block)
            except AllProvidersFailed:
                log.warning(
                    "epoch %s: claimHashes at block %s unavailable; reading latest", epoch, block
                )
        try:
            return self.outbox.claim_hash(epoch)
        except AllProvidersFailed:
            self._log_out_of_window(epoch, block or 0, "not readable at latest")
            return None

    def _fraud_note(self, row: ClaimRow) -> bool:
        return bool(row.note) and row.note.startswith("fraud:")

    def _fraud_missed(self, row: ClaimRow) -> None:
        row.status = MISSED
        row.note = f"{FRAUD_NOT_LANDED} ({row.note or 'no note'})"
        self.store.upsert_claim(row)
        self.notifier.send(
            CRITICAL,
            f"epoch {row.epoch}: {FRAUD_NOT_LANDED}. Our challenge never landed; "
            "investigate now.",
        )

    def _apply_deleted(self, row: ClaimRow) -> None:
        """The claim hash is gone: verified and withdrawn before we saw the state."""
        epoch = row.epoch
        if row.status in (SEEN, UNDECIDED):
            if self._fraud_note(row):
                self._fraud_missed(row)
                return
            row.status = VERIFIED_UNDECIDED
            row.note = (
                "withdrawn before processing: verified and withdrawn before we judged "
                f"it ({row.note or 'no note'})"
            )
            self.store.upsert_claim(row)
            self.notifier.send(
                CRITICAL,
                f"epoch {epoch}: claim was verified and withdrawn before we judged it "
                f"({row.note}); a fraud may have passed. Investigate now.",
            )
        elif row.status == CHALLENGED_BY_OTHER:
            row.status = MISSED
            row.note = "claim hash deleted after another party's challenge"
            self.store.upsert_claim(row)
        elif row.status == CHALLENGE_PENDING:
            self._fraud_missed(row)
        elif row.status == HONEST:
            row.status = WITHDRAWN
            row.note = row.note or "verified and withdrawn"
            self.store.upsert_claim(row)
        elif row.status in (CHALLENGED, SNAPSHOT_SENT, L1_EXECUTED, RESOLVED):
            # The withdrawal paid claim.challenger / claim.claimer directly, so
            # funds are safe either way; flag for a human to confirm which.
            row.status = WITHDRAWN
            row.note = "verified + withdrawn before processing; verify balances"
            self.store.upsert_claim(row)
            self.notifier.send(
                WARNING,
                f"epoch {epoch}: verified and withdrawn in one scan window; "
                "check whether the challenge won (balances)",
            )
        # terminal rows (MISSED, LOST, DESYNC, VERIFIED_UNDECIDED, WITHDRAWN): unchanged

    def _apply_verified(
        self, row: ClaimRow, block: int | None = None, onchain: bytes | None = None
    ) -> None:
        """`Verified` does not say who won: probe the on-chain hash, read at the
        event's block (or `block`) while that state is held, else at latest.
        `onchain` is a hash the caller already read at its confirmed block; it
        is used as is, with no second read."""
        if onchain is None:
            onchain = self._claim_hash_for_event(row.epoch, block)
        if onchain is None:
            return
        if onchain == b"\x00" * 32:
            self._apply_deleted(row)
            return
        matched = find_matching(row.claim, onchain)
        if matched is None:
            row.status = DESYNC
            row.note = "Verified event but no probe variant matches claimHashes"
            self.store.upsert_claim(row)
            self.notifier.send(CRITICAL, f"epoch {row.epoch}: DESYNC after Verified")
            return
        row.claim = matched
        ours = (
            self.challenge_address is not None
            and matched.challenger.lower() == self.challenge_address.lower()
        )
        if matched.honest == Party.CHALLENGER:
            if ours:
                row.status = RESOLVED
                self.notifier.send(
                    INFO, f"epoch {row.epoch}: challenge WON, withdrawal pending"
                )
            else:
                row.status = MISSED
                row.note = "fraud defeated by another challenger"
        elif matched.honest == Party.CLAIMER:
            if row.status == CHALLENGE_PENDING and not ours:
                # Our challenge never landed (a Challenged event of ours would
                # have moved the row before Verified): never LOST, no deposit.
                self._fraud_missed(row)
                return
            if row.status in _OUR_CHALLENGE_STATES and ours:
                row.status = LOST
                self.notifier.send(
                    CRITICAL,
                    f"epoch {row.epoch}: our challenge LOST — deposit forfeited. "
                    "Investigate immediately (RPC lied or verdict bug).",
                )
            elif row.status in (SEEN, UNDECIDED, CHALLENGED_BY_OTHER) or (
                row.status in _OUR_CHALLENGE_STATES
            ):
                # Not ours: a third party's challenge (our own was reorged out).
                if row.status in (SEEN, UNDECIDED) and self._fraud_note(row):
                    self._fraud_missed(row)
                    return
                if row.status not in (SEEN, UNDECIDED) and self._ruled_honest(row):
                    row.status = HONEST
                    row.note = row.note or "verified as honest"
                else:
                    row.status = VERIFIED_UNDECIDED
                    row.note = (
                        f"verified as honest before we could judge it ({row.note or 'no note'})"
                    )
                    self.notifier.send(
                        CRITICAL,
                        f"epoch {row.epoch}: claim verified as honest but we never "
                        f"judged it honest ({row.note}); a fraud may have passed. "
                        "Investigate now.",
                    )
        self.store.upsert_claim(row)

    @staticmethod
    def _ruled_honest(row: ClaimRow) -> bool:
        return bool(row.true_root) and row.true_root.lower() == (
            "0x" + row.claim.state_root.hex()
        )

    # -- struct reconciliation ---------------------------------------------------

    def reconcile(self, row: ClaimRow) -> ClaimRow | None:
        """Ensure our struct hashes to claimHashes[epoch] as of the event scan.

        claimHashes is read at the block the event scan has reached, so the
        event handlers and reconcile see one chain state: an event not scanned
        yet cannot make a row DESYNC. Returns the (possibly updated) row, or
        None when the claim hash is gone (deleted by a withdrawal). Returns the
        row unchanged, with no transition, when that read is not possible: the
        last scan stopped mid-block, the block is older than the node's state
        window, or no provider could serve it.
        """
        epoch = row.epoch
        if self.store.alert_sent(_PARTIAL_SCAN) is not None:
            return row
        block = self._scan_block()
        if not self._in_window(block):
            self._log_out_of_window(epoch, block, "older than the state window")
            return row
        try:
            onchain = self.outbox.claim_hash(epoch, block=block)
        except AllProvidersFailed:
            self._log_out_of_window(epoch, block, "not served by any provider")
            return row

        if onchain == b"\x00" * 32:
            if row.status == RESOLVED:
                # Someone executed withdrawChallengeDeposit for us; funds went to
                # claim.challenger regardless of caller.
                row.status = WITHDRAWN
                self.store.upsert_claim(row)
                self.notifier.send(INFO, f"epoch {epoch}: deposit withdrawn")
            else:
                self._apply_deleted(row)
            return None

        matched = row.claim if row.claim.hash() == onchain else find_matching(row.claim, onchain)
        if matched is None:
            row.status = DESYNC
            row.note = "claimHashes changed to an unreconstructable value"
            self.store.upsert_claim(row)
            self.notifier.send(
                CRITICAL,
                f"epoch {epoch}: cannot reconstruct on-chain claim hash "
                f"({onchain.hex()}); manual intervention required",
            )
            return row

        if (
            row.status in _REVERTIBLE
            and matched.challenger == ZERO_ADDRESS
            and matched.honest == Party.NONE
        ):
            self._revert(row, matched, block)
            return row
        if row.status in _REVERTIBLE:
            self._clear_suspect(epoch)  # the hash matches the stored struct again

        if matched == row.claim:
            return row
        if (
            row.claim.honest == Party.NONE
            and matched.honest != Party.NONE
            and row.status in _VERIFIABLE
        ):
            # A Verified whose own read failed was consumed by the scan: apply it
            # here from the hash read at the scan block (it persists the struct
            # only once the outcome is applied).
            self._apply_verified(row, block, onchain)
            return row
        row.claim = matched
        row.note = "struct updated via hash probing (event-less mutation)"
        self.store.upsert_claim(row)
        return row

    def _bridge_shutdown(self) -> bool:
        now_epoch = self.outbox.now() // self.params.epoch_period
        return now_epoch - self.outbox.latest_verified_epoch() > self.params.timeout_epochs

    @staticmethod
    def _receipt_field(receipt, name: str):
        try:
            return receipt[name]
        except (KeyError, TypeError):
            return None

    def _revert(self, row: ClaimRow, matched: Claim, block: int) -> None:
        """The confirmed-height hash shows no challenger: our challenge was reorged
        out, or (after a bridge shutdown) the escape hatch zeroed it. `row` is
        written once, with the matched struct and the new status together."""
        epoch = row.epoch
        if self._bridge_shutdown():
            # After a shutdown anyone may call withdrawChallengerEscapeHatch,
            # which zeroes `challenger` without an event: the deposit was
            # refunded, nothing was reorged.
            row.claim = matched
            row.status = WITHDRAWN
            row.challenge_tx = None
            row.note = "bridge shutdown: challenger zeroed by escape hatch (deposit refunded)"
            self.store.upsert_claim(row)
            self._clear_suspect(epoch)
            self.notifier.send(
                WARNING, f"epoch {epoch}: escape hatch used (bridge shutdown); not re-challenging"
            )
            return
        if row.status != CHALLENGED_BY_OTHER and row.challenge_tx:
            receipt = self.outbox.client.receipt_or_none(row.challenge_tx)
            if receipt is not None and self._receipt_field(receipt, "status") != 0:
                landed = self._receipt_field(receipt, "blockNumber")
                if landed is not None and int(landed) > block:
                    return  # mined above what the scan has reached: not scanned yet
                self._reorg_held(row)
                return
        # Taking the transition: the suspicion is resolved either way.
        self._clear_suspect(epoch)
        row.claim = matched
        if row.status == CHALLENGED_BY_OTHER:
            row.status = UNDECIDED
            row.note = "undecided: the other party's challenge was reverted; re-evaluating"
            self.store.upsert_claim(row)
            self.notifier.send(
                WARNING,
                f"epoch {epoch}: the third-party challenge is gone (reverted); re-evaluating",
            )
            return
        if row.status in (SNAPSHOT_SENT, L1_EXECUTED):
            row.snapshot_tx = None
            row.l2tol1_json = None
            row.execute_tx = None
        row.status = CHALLENGE_PENDING
        row.challenge_tx = None
        row.note = "our challenge was reorged out; re-challenging"
        self.store.upsert_claim(row)
        self.notifier.send(
            CRITICAL, f"our challenge for epoch {epoch} was reorged out; re-challenging"
        )

    def _clear_suspect(self, epoch: int) -> None:
        key = f"reorg-suspect:{epoch}"
        if self.store.alert_sent(key) is not None:
            self.store.clear_alerts(key)

    def _reorg_held(self, row: ClaimRow) -> None:
        """The confirmed-height hash shows no challenger but our challenge tx has a
        successful receipt: hold the transition; page if it lasts."""
        epoch = row.epoch
        key = f"reorg-suspect:{epoch}"
        now = int(time.time())
        first = self.store.alert_sent(key)
        if first is None:
            self.store.mark_alert(key, now)
            return
        if now - first >= REORG_STUCK_AFTER:
            self._alert_once(
                f"reorg-stuck:{epoch}",
                CRITICAL,
                f"epoch {epoch}: claimHashes shows no challenger for {now - first} s but "
                f"our challenge tx {row.challenge_tx} has a successful receipt, so the "
                "receipt gate holds the re-challenge. Check the outbox RPCs and whether "
                "the challenge is really in.",
                _SINGLE_SOURCE_ALERT_INTERVAL,
            )

    # -- verdicts ----------------------------------------------------------------

    def _alert_once(self, key: str, level: str, message: str, interval: int | None = None) -> None:
        """Send `message` unless `key` was already sent (within `interval` s, if given)."""
        sent = self.store.alert_sent(key)
        now = int(time.time())
        if sent is not None and (interval is None or now - sent < interval):
            return
        self.notifier.send(level, message)
        self.store.mark_alert(key, now)

    @staticmethod
    def _split_message(epoch: int, tag: str, read) -> str:
        answers = ", ".join(f"{r.label}=0x{r.root.hex()}" for r in read.reads)
        missing = ", ".join(read.missing) or "none"
        return (
            f"epoch {epoch}: {tag} quorum split: {answers}; "
            f"did not answer: {missing}"
        )

    def evaluate(self, row: ClaimRow) -> Verdict:
        """Verdict for a SEEN/UNDECIDED claim from quorum inbox reads."""
        epoch = row.epoch
        legs: dict[str, tuple] = {}  # tag -> (root, ts, reads)
        total = 0
        for tag in (FINALIZED, LATEST):
            try:
                read = self.inbox.snapshot_quorum(epoch, tag)
            except Exception as exc:  # noqa: BLE001
                log.warning("%s read failed for epoch %s: %s", tag, epoch, redact(str(exc)))
                legs[tag] = (None, None, ())
                continue
            total = max(total, read.total)
            if read.split:
                self._alert_once(
                    f"split:{epoch}:{tag}",
                    CRITICAL,
                    self._split_message(epoch, tag, read),
                    _SINGLE_SOURCE_ALERT_INTERVAL,
                )
            legs[tag] = (read.root, read.view.timestamp, read.reads)

        sequencer_delay = self.outbox.sequencer_delay_limit()
        decision = decide_detail(
            VerdictInputs(
                epoch=epoch,
                claimed_root=row.claim.state_root,
                epoch_period=self.params.epoch_period,
                sequencer_delay=sequencer_delay,
                finalized_ts=legs[FINALIZED][1],
                finalized_snapshot=legs[FINALIZED][0],
                latest_ts=legs[LATEST][1],
                latest_snapshot=legs[LATEST][0],
                finalized_reads=legs[FINALIZED][2],
                latest_reads=legs[LATEST][2],
                total_providers=total,
                min_agreement=self.min_challenge_agreement,
                now=self.outbox.now(),
                deadline=earliest_verification_ts(
                    row.claim.timestamp_claimed,
                    self.params.epoch_period,
                    sequencer_delay,
                    self.params.min_challenge_period,
                    self.devnet,
                ),
                devnet=self.devnet,
                challenge_on_ambiguity=self.challenge_on_ambiguity,
            )
        )
        verdict = decision.verdict

        if verdict == Verdict.WAIT:
            reason = decision.reason or "no immutable read past the epoch end yet"
            if reason.startswith("insufficient agreement"):
                self._alert_once(
                    f"single-source:{epoch}", WARNING, reason, _SINGLE_SOURCE_ALERT_INTERVAL
                )
            elif reason.startswith("incomplete:"):
                self._alert_once(
                    f"incomplete:{epoch}",
                    WARNING,
                    f"epoch {epoch}: looks honest but not all RPCs answered ({reason}); "
                    "withholding the terminal verdict",
                    _SINGLE_SOURCE_ALERT_INTERVAL,
                )
            elif reason.startswith("override declined:"):
                self._alert_once(
                    f"override-declined:{epoch}",
                    CRITICAL,
                    f"epoch {epoch}: {reason}",
                )
            if self._fraud_note(row):
                # Keep the fraud mark through a flapping quorum: the deadline
                # alerts and a later Verified must still treat the row as fraud.
                base = row.note.split("; latest read: ")[0]
                row.note = f"{base}; latest read: {reason}"
            else:
                row.note = f"undecided: {reason}"
            if row.status == SEEN:
                row.status = UNDECIDED
            self.store.upsert_claim(row)
            return verdict

        assert decision.root is not None
        row.true_root = "0x" + decision.root.hex()
        if verdict == Verdict.HONEST:
            row.status = HONEST
        else:
            row.note = (
                f"fraud: {decision.leg} root {row.true_root} differs from the claim; "
                "challenge not confirmed yet"
            )
            if decision.leg == "override":
                self._alert_once(
                    f"override-challenge:{epoch}",
                    CRITICAL,
                    f"epoch {epoch}: deadline override CHALLENGE — {decision.reason}; "
                    f"{self._mismatching(row, legs, sequencer_delay)}; "
                    f"true root {row.true_root}",
                    _SINGLE_SOURCE_ALERT_INTERVAL,
                )
        self.store.upsert_claim(row)
        return verdict

    def _mismatching(self, row: ClaimRow, legs: dict, sequencer_delay: int) -> str:
        """Reads of immutable legs (past their boundary) that differ from the claim."""
        epoch_end = (row.epoch + 1) * self.params.epoch_period
        boundary = {FINALIZED: epoch_end, LATEST: epoch_end + sequencer_delay}
        found = [
            f"{r.label} (0x{r.root.hex()}, {tag} leg)"
            for tag, (_, ts, reads) in legs.items()
            if ts is not None and ts >= boundary[tag]
            for r in reads
            if r.root != row.claim.state_root
        ]
        return "mismatching immutable provider(s): " + (", ".join(found) or "none")
