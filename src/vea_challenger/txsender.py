"""Journaled transaction submission.

Intent is written to SQLite *before* broadcast so a crash mid-send is
recoverable; receipts finalize the journal entry. Each lane (challenge vs ops)
uses its own account so a stuck slow-lane tx can never block a challenge.
"""

from __future__ import annotations

import logging
from typing import Any

from eth_account.signers.local import LocalAccount
from web3.types import TxReceipt

from .chain import ChainClient
from .store import Store

log = logging.getLogger(__name__)


def _bumped(wei: int) -> int:
    """ceil(1.1 * wei) + 1: geth and most clients need +10% on both caps to replace."""
    return -(-wei * 11 // 10) + 1


def _replacement_base(
    fees: list[tuple[int, int, bool]], market: tuple[int, int]
) -> tuple[int, int] | None:
    """Fee caps a replacement must outbid, from the attempts journaled at its nonce.

    Anchored on the highest attempt that got a tx hash (else the lowest one).
    A failed broadcast may still have reached a node, so it counts up to one
    bump above the anchor or the current market quote, whichever is higher:
    failed broadcasts during an RPC outage must not compound fees every tick
    until no balance can cover them.
    """
    if not fees:
        return None
    sent = [(f, p) for f, p, broadcast in fees if broadcast]
    unsent = [(f, p) for f, p, broadcast in fees if not broadcast]
    if sent:
        anchor = (max(f for f, _ in sent), max(p for _, p in sent))
    else:
        anchor = (min(f for f, _ in unsent), min(p for _, p in unsent))
    if not unsent:
        return anchor
    return tuple(  # type: ignore[return-value]
        max(a, min(max(u[i] for u in unsent), _bumped(max(a, market[i]))))
        for i, a in enumerate(anchor)
    )


class TxFailed(RuntimeError):
    def __init__(self, tx_hash: str, receipt: TxReceipt):
        super().__init__(f"tx {tx_hash} reverted")
        self.tx_hash = tx_hash
        self.receipt = receipt


class TxSender:
    def __init__(self, store: Store, client: ChainClient, account: LocalAccount):
        self.store = store
        self.client = client
        self.account = account

    @property
    def address(self) -> str:
        return self.account.address

    def send(
        self,
        fn: Any,
        *,
        epoch: int,
        action: str,
        value: int = 0,
        urgency: float = 1.0,
        gas_limit: int | None = None,
        timeout: float = 300.0,
        nonce_override: int | None = None,
    ) -> TxReceipt:
        """Simulate, journal, broadcast and await one contract call.

        ``nonce_override`` replaces a stuck in-flight tx at that nonce: both fee
        caps are raised to at least 10% (+1 wei) over the highest attempt
        journaled at that nonce, or nodes reject it as underpriced.
        """
        tx_params: dict[str, Any] = {"from": self.account.address, "value": value}
        # eth_call simulation first: never broadcast a tx that reverts.
        fn.call(tx_params)

        fees = self.client.fees(urgency)
        max_fee, max_prio = fees.max_fee_per_gas, fees.max_priority_fee_per_gas
        nonce = (
            nonce_override
            if nonce_override is not None
            else self.client.pending_nonce(self.account.address)
        )
        if nonce_override is not None:
            prev = _replacement_base(
                self.store.journal_fees(self.client.name, self.account.address, nonce),
                (max_fee, max_prio),
            )
            if prev is not None:
                max_fee = max(max_fee, _bumped(prev[0]))
                max_prio = max(max_prio, _bumped(prev[1]))
                max_fee = max(max_fee, max_prio)
        tx_params |= {
            "nonce": nonce,
            "maxFeePerGas": max_fee,
            "maxPriorityFeePerGas": max_prio,
            "chainId": self.client.cfg.chain_id,
        }
        if gas_limit is not None:
            tx_params["gas"] = gas_limit
        tx = fn.build_transaction(tx_params)
        if gas_limit is None:
            tx["gas"] = int(tx["gas"] * 1.3)

        journal_id = self.store.journal_intent(
            epoch, action, self.client.name, self.account.address, nonce, (max_fee, max_prio)
        )
        tx_hash = self.client.send_signed(self.account, tx)
        self.store.journal_sent(journal_id, tx_hash)
        log.info("%s epoch=%s tx=%s nonce=%s sent", action, epoch, tx_hash, nonce)

        receipt = self.client.wait_receipt(tx_hash, timeout=timeout)
        if receipt["status"] != 1:
            self.store.journal_final(journal_id, "REVERTED")
            raise TxFailed(tx_hash, receipt)
        self.store.journal_final(journal_id, "CONFIRMED")
        return receipt
