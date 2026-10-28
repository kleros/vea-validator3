"""The deadline-critical path: submitting challenge transactions.

Pre-flight checks immediately before broadcast (the struct may have changed
since the verdict):

- reconstructed struct hashes to the on-chain ``claimHashes[epoch]``
- nobody has challenged yet (``challenger == 0``) and ``honest == None``
- funds: native deposit + gas reserve (ArbToEth) or WETH balance + allowance
  (ArbToGnosis; allowance is topped up with a one-time max approve)

The deposit sent is *exactly* ``deposit``: the contract refunds overpayment via
``.send()`` with a 2300-gas stipend, which silently burns money sent from
anything but a plain EOA.
"""

from __future__ import annotations

import logging
import time

from .chain import redact
from .claims import ZERO_ADDRESS, Party
from .contracts import OutboxContract, OutboxParams, WethToken
from .notify import CRITICAL, INFO, Notifier
from .store import CHALLENGE_PENDING, CHALLENGED, ClaimRow, Store
from .txsender import TxSender
from .verdict import earliest_verification_ts

log = logging.getLogger(__name__)

MAX_UINT256 = 2**256 - 1


class Challenger:
    def __init__(
        self,
        store: Store,
        outbox: OutboxContract,
        params: OutboxParams,
        sender: TxSender,
        notifier: Notifier,
        weth: WethToken | None,
        gas_reserve_wei: int,
        devnet: bool,
        dry_run: bool,
    ):
        self.store = store
        self.outbox = outbox
        self.params = params
        self.sender = sender
        self.notifier = notifier
        self.weth = weth
        self.gas_reserve_wei = gas_reserve_wei
        self.devnet = devnet
        self.dry_run = dry_run

    def _page_hourly(self, key: str, message: str) -> None:
        """CRITICAL at most once per hour per key: the row is retried every tick."""
        now = int(time.time())
        sent = self.store.alert_sent(key)
        if sent is not None and now - sent < 3600:
            return
        self.store.mark_alert(key, now)
        self.notifier.send(CRITICAL, message)

    # -- funding ----------------------------------------------------------------

    def can_fund_challenge(self) -> bool:
        native = self.sender.client.with_failover(
            lambda w3: w3.eth.get_balance(self.sender.address)
        )
        if self.weth is not None:
            return (
                native >= self.gas_reserve_wei
                and self.weth.balance_of(self.sender.address) >= self.params.deposit
            )
        return native >= self.params.deposit + self.gas_reserve_wei

    def ensure_allowance(self) -> None:
        if self.weth is None or self.dry_run:
            return
        allowance = self.weth.allowance(self.sender.address, self.outbox.address)
        if allowance >= self.params.deposit * 16:
            return
        log.info("approving WETH for outbox %s", self.outbox.address)
        self.sender.send(
            self.weth.approve_fn(self.outbox.address, MAX_UINT256),
            epoch=0,
            action="weth_approve",
        )

    # -- challenge ----------------------------------------------------------------

    def urgency(self, row: ClaimRow, now: int) -> float:
        """Fee multiplier that ramps as the hard deadline approaches."""
        deadline = earliest_verification_ts(
            row.claim.timestamp_claimed,
            self.params.epoch_period,
            self.outbox.sequencer_delay_limit(),
            self.params.min_challenge_period,
            self.devnet,
        )
        remaining = deadline - now
        if remaining <= 900:
            return 5.0
        if remaining <= 3600:
            return 3.0
        if remaining <= 4 * 3600:
            return 2.0
        return 1.0

    def _stuck_challenge_nonce(self, epoch: int) -> int | None:
        """Lowest unmined nonce of an earlier challenge attempt, to replace.

        An INTENT row with no tx hash counts too: its broadcast may have reached
        a node before failing. Rows whose nonce is still pending stay open until
        the challenge confirms or the nonce is consumed, so an attempt that fails
        before its own intent is journaled (simulation, fee quote) cannot lose it.
        """
        replace: int | None = None
        confirmed: int | None = None
        for intent in self.store.open_intents("challenge"):
            if intent["epoch"] != epoch or intent["sender"] != self.sender.address:
                continue
            if intent["tx_hash"] and self.sender.client.receipt_or_none(intent["tx_hash"]):
                # Mined (possibly reverted); the event scan / reconcile pass
                # will surface the outcome. Nothing to replace.
                self.store.journal_final(intent["id"], "MINED")
                continue
            if intent["nonce"] is None:
                self.store.journal_final(intent["id"], "SUPERSEDED")
                continue
            if confirmed is None:
                confirmed = self.sender.client.with_failover(
                    lambda w3: w3.eth.get_transaction_count(self.sender.address)
                )
            if intent["nonce"] < confirmed:
                # The nonce was used by another tx (a replacement that mined).
                self.store.journal_final(intent["id"], "SUPERSEDED")
                continue
            nonce = int(intent["nonce"])
            replace = nonce if replace is None else min(replace, nonce)
        return replace

    def _close_open_intents(self, epoch: int) -> None:
        """The challenge confirmed: earlier attempts for the epoch were replaced."""
        for intent in self.store.open_intents("challenge"):
            if intent["epoch"] == epoch and intent["sender"] == self.sender.address:
                self.store.journal_final(intent["id"], "SUPERSEDED")

    def challenge(self, row: ClaimRow) -> bool:
        """Attempt to challenge; returns True when the challenge confirmed."""
        epoch = row.epoch

        # Pre-flight: fresh on-chain state.
        onchain = self.outbox.claim_hash(epoch)
        if onchain != row.claim.hash():
            log.info("epoch %s: struct stale before challenge; deferring to reconcile", epoch)
            return False
        if row.claim.challenger != ZERO_ADDRESS or row.claim.honest != Party.NONE:
            return False

        if self.dry_run:
            self._page_hourly(
                f"dry-run:{epoch}",
                f"DRY-RUN: would challenge epoch {epoch} "
                f"(claimed 0x{row.claim.state_root.hex()}, true {row.true_root})",
            )
            return False

        if not self.can_fund_challenge():
            self._page_hourly(
                f"unfunded:{epoch}",
                f"INSUFFICIENT FUNDS to challenge fraudulent claim epoch {epoch} — "
                f"an unchallenged fraud WILL verify. Fund {self.sender.address} now.",
            )
            return False
        self.ensure_allowance()

        try:
            urgency = self.urgency(row, self.outbox.now())
        except Exception as exc:  # noqa: BLE001 - urgency is best-effort
            log.warning("urgency computation failed (%s); using max", exc)
            urgency = 5.0
        value = self.params.deposit if self.weth is None else 0
        fn = self.outbox.contract().functions.challenge(epoch, row.claim.as_tuple())

        # If a previous attempt is stuck in the mempool, replace it at the same
        # nonce with escalated fees instead of queueing behind it.
        nonce_override = self._stuck_challenge_nonce(epoch)
        if nonce_override is not None:
            urgency = max(urgency, 3.0)
            log.info("epoch %s: replacing stuck challenge at nonce %s", epoch, nonce_override)

        row.status = CHALLENGE_PENDING
        self.store.upsert_claim(row)
        try:
            receipt = self.sender.send(
                fn,
                epoch=epoch,
                action="challenge",
                value=value,
                urgency=urgency,
                nonce_override=nonce_override,
            )
        except Exception as exc:  # noqa: BLE001
            # Someone may have front-run us, or the struct changed, or the RPC
            # dropped the tx. The row stays CHALLENGE_PENDING and the watcher
            # RETRIES it every tick until Challenged appears or the state moves.
            log.warning("challenge tx failed for epoch %s: %s", epoch, redact(str(exc)))
            row.status = CHALLENGE_PENDING
            row.note = f"challenge attempt failed: {redact(str(exc))}"
            self.store.upsert_claim(row)
            self._page_hourly(
                f"challenge-failed:{epoch}",
                f"CHALLENGE FAILED for fraudulent claim epoch {epoch} (retrying every "
                f"tick): {redact(str(exc))}",
            )
            return False

        self._close_open_intents(epoch)
        row.challenge_tx = receipt["transactionHash"].to_0x_hex()
        row.status = CHALLENGED
        row.note = f"challenged (tx {row.challenge_tx})"
        # The contract sets challenger to msg.sender (we use the 2-arg overload).
        row.claim = row.claim.__class__(
            state_root=row.claim.state_root,
            claimer=row.claim.claimer,
            timestamp_claimed=row.claim.timestamp_claimed,
            timestamp_verification=row.claim.timestamp_verification,
            blocknumber_verification=row.claim.blocknumber_verification,
            honest=row.claim.honest,
            challenger=self.sender.address,
        )
        self.store.upsert_claim(row)
        self.notifier.send(
            INFO,
            f"CHALLENGED epoch {epoch}: claimed 0x{row.claim.state_root.hex()} "
            f"!= true {row.true_root} (tx {row.challenge_tx})",
        )
        return True
