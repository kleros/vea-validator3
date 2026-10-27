"""Drives challenged claims to resolution and collects the reward.

Slow lane (ops account): nothing here is deadline-critical, but each step must
be idempotent and crash-safe:

  CHALLENGED      -> sendSnapshot on the inbox (L2), with the exact
                     post-challenge struct; adopt a third party's ticket only
                     if their calldata carried the same struct
  SNAPSHOT_SENT   -> execute the L2->L1 message on the L1 Arbitrum Outbox once
                     the assertion confirms (ArbToGnosis: this executes
                     route(), the AMB then delivers to the Gnosis outbox)
  RESOLVED        -> withdrawChallengeDeposit on the outbox chain
  bridge shutdown -> withdrawChallengerEscapeHatch (deposit only, no reward)
"""

from __future__ import annotations

import json
import logging
import time

from .arbitrum import (
    ArbOutboxExecutor,
    NotReadyError,
    decode_claim_from_l2tol1_data,
    parse_l2tol1_event,
)
from .claims import Party
from .contracts import InboxContract, OutboxContract, OutboxParams
from .notify import CRITICAL, INFO, WARNING, Notifier
from .store import (
    CHALLENGED,
    L1_EXECUTED,
    RESOLVED,
    SNAPSHOT_SENT,
    WITHDRAWN,
    ClaimRow,
    Store,
)
from .txsender import TxSender

log = logging.getLogger(__name__)


class Resolver:
    def __init__(
        self,
        store: Store,
        outbox: OutboxContract,
        inbox: InboxContract,
        params: OutboxParams,
        executor: ArbOutboxExecutor,
        l2_sender: TxSender,  # ops key on the inbox (Arbitrum) chain
        l1_sender: TxSender,  # ops key on the L1 chain (rollup home)
        outbox_sender: TxSender,  # ops key on the outbox chain
        notifier: Notifier,
        challenge_address: str,
        dry_run: bool,
    ):
        self.store = store
        self.outbox = outbox
        self.inbox = inbox
        self.params = params
        self.executor = executor
        self.l2_sender = l2_sender
        self.l1_sender = l1_sender
        self.outbox_sender = outbox_sender
        self.notifier = notifier
        self.challenge_address = challenge_address
        self.dry_run = dry_run
        self._adoption_checked: set[int] = set()
        # The only L2->L1 message we accept: from the inbox to the route's L1
        # target (the outbox for ArbToEth, the router for ArbToGnosis).
        route = inbox.route
        self._ticket_destination = (
            route.router_address if route.kind == "arb_to_gnosis" else route.outbox_address
        )

    def tick(self, rows: list[ClaimRow]) -> None:
        if self.dry_run:
            return
        for row in rows:
            try:
                if row.status == CHALLENGED and self._ours(row):
                    self.send_snapshot(row)
                elif row.status == SNAPSHOT_SENT:
                    self.execute_l1(row)
                elif row.status == RESOLVED:
                    self.withdraw(row)
            except Exception as exc:  # noqa: BLE001 - resolution retries next tick
                log.warning("resolver step failed for epoch %s: %s", row.epoch, exc)

    def _parse_ticket(self, receipt, check_destination: bool = True) -> dict:
        return parse_l2tol1_event(
            self.inbox.client,
            receipt,
            self.inbox.address,
            self._ticket_destination if check_destination else None,
        )

    def _ours(self, row: ClaimRow) -> bool:
        return row.claim.challenger.lower() == self.challenge_address.lower()

    # -- step 1: sendSnapshot ---------------------------------------------------

    def send_snapshot(self, row: ClaimRow) -> None:
        # Adopt an existing ticket if a third party already sent the snapshot
        # with the exact same (correct) struct.
        adopted = self._find_existing_ticket(row)
        if adopted is not None:
            row.snapshot_tx, row.l2tol1_json = adopted
            row.status = SNAPSHOT_SENT
            self.store.upsert_claim(row)
            self.notifier.send(INFO, f"epoch {row.epoch}: adopted existing snapshot ticket")
            return

        fn = self.inbox.send_snapshot_fn(row.epoch, row.claim)
        receipt = self.l2_sender.send(fn, epoch=row.epoch, action="send_snapshot")
        # Our tx calls the inbox directly, so its log is the inbox's; skip the
        # destination check so a misconfigured router can't make every tick
        # re-send sendSnapshot.
        msg = self._parse_ticket(receipt, check_destination=False)
        row.snapshot_tx = receipt["transactionHash"].to_0x_hex()
        row.l2tol1_json = json.dumps(msg)
        row.status = SNAPSHOT_SENT
        self.store.upsert_claim(row)
        self.notifier.send(
            INFO,
            f"epoch {row.epoch}: snapshot sent through canonical bridge "
            f"(tx {row.snapshot_tx}, position {msg['position']})",
        )

    def _find_existing_ticket(self, row: ClaimRow) -> tuple[str, str] | None:
        """Scan recent SnapshotSent events for this epoch; verify the struct they carried.

        Best-effort optimization only (adopting a third party's ticket saves one
        sendSnapshot tx): the scan window is small and the result is cached per
        process, because a duplicate sendSnapshot is harmless — the loser merely
        emits FailedResolution after the winner resolves.
        """
        if row.epoch in self._adoption_checked:
            return None
        self._adoption_checked.add(row.epoch)
        try:
            head = self.inbox.client.latest_block_number()
            events = self.inbox.snapshot_sent_events(
                row.epoch, max(0, head - 120_000), head
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("SnapshotSent scan failed: %s", exc)
            return None
        for ev in events:
            try:
                receipt = self.inbox.client.receipt_or_none(ev["tx_hash"])
                if receipt is None:
                    continue
                msg = self._parse_ticket(receipt)
                carried = decode_claim_from_l2tol1_data(msg["data"], row.epoch)
                if carried is not None and carried.hash() == row.claim.hash():
                    return ev["tx_hash"], json.dumps(msg)
            except Exception as exc:  # noqa: BLE001
                log.warning("could not verify SnapshotSent ticket %s: %s", ev, exc)
        return None

    # -- step 2: L1 execution -----------------------------------------------------

    def execute_l1(self, row: ClaimRow) -> None:
        if not row.l2tol1_json:
            # Crash window: snapshot sent but message not journaled. Re-derive.
            receipt = (
                self.inbox.client.receipt_or_none(row.snapshot_tx)
                if row.snapshot_tx
                else None
            )
            if receipt is not None:
                row.l2tol1_json = json.dumps(self._parse_ticket(receipt))
                self.store.upsert_claim(row)
            else:
                row.status = CHALLENGED  # re-run step 1
                row.snapshot_tx = None
                self.store.upsert_claim(row)
                return
        msg = json.loads(row.l2tol1_json)

        if self.executor.is_spent(msg["position"]):
            row.status = L1_EXECUTED
            self.store.upsert_claim(row)
            self.notifier.send(INFO, f"epoch {row.epoch}: L2->L1 message executed")
            return
        try:
            fn = self.executor.execute_fn(msg)
        except NotReadyError as exc:
            log.info("epoch %s: %s", row.epoch, exc)
            return
        receipt = self.l1_sender.send(
            fn, epoch=row.epoch, action="execute_l2_to_l1", timeout=600
        )
        row.execute_tx = receipt["transactionHash"].to_0x_hex()
        row.status = L1_EXECUTED
        self.store.upsert_claim(row)
        self.notifier.send(
            INFO, f"epoch {row.epoch}: executed L2->L1 message (tx {row.execute_tx})"
        )
        # ArbToEth: resolveDisputedClaim already ran inside this tx; the detector
        # picks up Verified on the next sync. ArbToGnosis: the AMB leg follows.

    # -- step 3: withdraw ----------------------------------------------------------

    def withdraw(self, row: ClaimRow) -> None:
        if row.claim.honest != Party.CHALLENGER or not self._ours(row):
            return
        if self.dry_run:
            log.info("dry-run: would withdraw the deposit for epoch %s", row.epoch)
            return
        fn = self.outbox.contract().functions.withdrawChallengeDeposit(
            row.epoch, row.claim.as_tuple()
        )
        receipt = self.outbox_sender.send(fn, epoch=row.epoch, action="withdraw")
        row.withdraw_tx = receipt["transactionHash"].to_0x_hex()
        row.status = WITHDRAWN
        self.store.upsert_claim(row)
        self.notifier.send(
            INFO,
            f"epoch {row.epoch}: reward withdrawn to {row.claim.challenger} "
            f"(tx {row.withdraw_tx})",
        )

    # -- shutdown escape hatch --------------------------------------------------------

    def bridge_shutdown(self) -> bool:
        now_epoch = self.outbox.now() // self.params.epoch_period
        return now_epoch - self.outbox.latest_verified_epoch() > self.params.timeout_epochs

    def escape_hatch(self, row: ClaimRow) -> None:
        if self.dry_run or not self._ours(row):
            return
        if row.claim.honest != Party.NONE:
            # Resolved claims never go through the escape hatch (the contract
            # requires honest == None); RESOLVED rows use withdraw() instead.
            return
        fn = self.outbox.contract().functions.withdrawChallengerEscapeHatch(
            row.epoch, row.claim.as_tuple()
        )
        receipt = self.outbox_sender.send(fn, epoch=row.epoch, action="escape_hatch")
        row.withdraw_tx = receipt["transactionHash"].to_0x_hex()
        row.status = WITHDRAWN
        row.note = "bridge shutdown: deposit recovered via escape hatch (no reward)"
        self.store.upsert_claim(row)
        self.notifier.send(WARNING, f"epoch {row.epoch}: escape hatch used (bridge shutdown)")
