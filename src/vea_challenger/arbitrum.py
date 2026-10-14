"""Arbitrum L2->L1 message execution, in pure web3 (no arbitrum-sdk).

Flow: ``sendSnapshot`` on the inbox emits an ArbSys ``L2ToL1Tx``. Once the
assertion containing it is confirmed on L1 (the rollup's Outbox emits
``SendRootUpdated``), the message is executable: build a merkle proof with the
``NodeInterface`` precompile (an L2 node-side virtual contract) and call
``Outbox.executeTransaction`` on L1.

Readiness is detected by comparing the message's leaf ``position`` with the
``sendCount`` of the latest *confirmed* L2 block (from the newest
``SendRootUpdated`` event's ``l2BlockHash``).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from eth_abi import decode as abi_decode
from web3 import Web3
from web3.types import TxReceipt

from . import abi
from .chain import ChainClient
from .claims import Claim, Party

log = logging.getLogger(__name__)

RESOLVE_SELECTOR = Web3.keccak(
    text="resolveDisputedClaim(uint256,bytes32,(bytes32,address,uint32,uint32,uint32,uint8,address))"
)[:4]
ROUTE_SELECTOR = Web3.keccak(
    text="route(uint256,bytes32,uint256,(bytes32,address,uint32,uint32,uint32,uint8,address))"
)[:4]


def parse_l2tol1_event(
    l2_client: ChainClient,
    receipt: TxReceipt,
    caller: str,
    destination: str | None = None,
) -> dict:
    """Extract the inbox's ArbSys L2ToL1Tx message from a sendSnapshot receipt.

    Only a log whose ``caller`` is the inbox (and, when given, whose
    ``destination`` is the route's L1 target) counts: a third party's tx can
    wrap ``sendSnapshot`` and emit its own L2->L1 message first, carrying any
    calldata it likes.
    """
    contract = l2_client.w3.eth.contract(
        address=Web3.to_checksum_address(abi.ARBSYS_ADDRESS), abi=abi.ARBSYS_ABI
    )
    event = contract.events.L2ToL1Tx()
    for entry in receipt["logs"]:
        if entry["address"].lower() != abi.ARBSYS_ADDRESS.lower():
            continue
        parsed = event.process_log(entry)
        a = parsed["args"]
        if a["caller"].lower() != caller.lower():
            continue
        if destination is not None and a["destination"].lower() != destination.lower():
            continue
        return {
            "caller": a["caller"],
            "destination": a["destination"],
            "position": int(a["position"]),
            "arbBlockNum": int(a["arbBlockNum"]),
            "ethBlockNum": int(a["ethBlockNum"]),
            "timestamp": int(a["timestamp"]),
            "callvalue": int(a["callvalue"]),
            "data": "0x" + bytes(a["data"]).hex(),
        }
    raise ValueError(f"no L2ToL1Tx event from {caller} found in receipt")


def decode_claim_from_l2tol1_data(data_hex: str, epoch: int | None = None) -> Claim | None:
    """Decode the Claim struct from a resolveDisputedClaim / route calldata.

    Used to check whether a third party's sendSnapshot carried the correct
    (post-challenge) struct before adopting their ticket as ours. With
    ``epoch``, a message for any other epoch decodes to None: a wrapper can
    send our struct for a different epoch in the same tx.
    """
    data = bytes.fromhex(data_hex.removeprefix("0x"))
    selector, payload = data[:4], data[4:]
    claim_type = "(bytes32,address,uint32,uint32,uint32,uint8,address)"
    if selector == RESOLVE_SELECTOR:
        types = ["uint256", "bytes32", claim_type]
        claim_idx = 2
    elif selector == ROUTE_SELECTOR:
        types = ["uint256", "bytes32", "uint256", claim_type]
        claim_idx = 3
    else:
        return None
    decoded = abi_decode(types, payload)
    if epoch is not None and int(decoded[0]) != epoch:
        return None
    c = decoded[claim_idx]
    return Claim(
        state_root=bytes(c[0]),
        claimer=Web3.to_checksum_address(c[1]),
        timestamp_claimed=int(c[2]),
        timestamp_verification=int(c[3]),
        blocknumber_verification=int(c[4]),
        honest=Party(int(c[5])),
        challenger=Web3.to_checksum_address(c[6]),
    )


class ArbOutboxExecutor:
    """Executes confirmed L2->L1 messages on the L1 Arbitrum Outbox."""

    def __init__(
        self,
        l1_client: ChainClient,
        l2_client: ChainClient,
        bridge_address: str,
        outbox_address_override: str | None = None,
    ):
        self.l1 = l1_client
        self.l2 = l2_client
        self.bridge_address = Web3.to_checksum_address(bridge_address)
        self._outbox_address = (
            Web3.to_checksum_address(outbox_address_override)
            if outbox_address_override
            else None
        )

    def outbox_address(self) -> str:
        if self._outbox_address is None:
            rollup_addr = self.l1.with_failover(
                lambda w3: w3.eth.contract(
                    address=self.bridge_address, abi=abi.ARB_BRIDGE_ABI
                ).functions.rollup().call()
            )
            self._outbox_address = Web3.to_checksum_address(
                self.l1.with_failover(
                    lambda w3: w3.eth.contract(
                        address=Web3.to_checksum_address(rollup_addr),
                        abi=abi.ARB_ROLLUP_ABI,
                    ).functions.outbox().call()
                )
            )
        return self._outbox_address

    def _outbox(self, w3: Web3):
        return w3.eth.contract(address=self.outbox_address(), abi=abi.ARB_OUTBOX_ABI)

    def is_spent(self, position: int) -> bool:
        return bool(
            self.l1.with_failover(
                lambda w3: self._outbox(w3).functions.isSpent(position).call()
            )
        )

    def confirmed_send_count(self, scan_window: int = 60_000) -> int | None:
        """sendCount of the newest confirmed L2 block, via SendRootUpdated on L1."""
        head = self.l1.latest_block_number()
        topic = self.l1.w3.eth.contract(
            address=self.outbox_address(), abi=abi.ARB_OUTBOX_ABI
        ).events.SendRootUpdated().topic
        window_start = max(0, head - scan_window)
        logs = self.l1.get_logs_chunked(
            address=self.outbox_address(),
            topics=[topic],
            from_block=window_start,
            to_block=head,
            chunk=10_000,
        )
        if not logs:
            return None
        newest = max(logs, key=lambda e: (e["blockNumber"], e["logIndex"]))
        l2_block_hash = newest["topics"][2].to_0x_hex()
        # Raw request: web3 does not model Arbitrum's extra header fields.
        block = self.l2.with_failover(
            lambda w3: w3.provider.make_request(
                "eth_getBlockByHash", [l2_block_hash, False]
            )["result"]
        )
        if block is None or "sendCount" not in block:
            return None
        return int(block["sendCount"], 16)

    def construct_proof(self, size: int, leaf: int) -> list[bytes]:
        _send, _root, proof = self.l2.with_failover(
            lambda w3: w3.eth.contract(
                address=Web3.to_checksum_address(abi.NODE_INTERFACE_ADDRESS),
                abi=abi.NODE_INTERFACE_ABI,
            ).functions.constructOutboxProof(size, leaf).call()
        )
        return list(proof)

    def execute_fn(self, msg: dict) -> Any:
        """Bound Outbox.executeTransaction for a parsed L2ToL1Tx message."""
        size = self.confirmed_send_count()
        if size is None or size <= msg["position"]:
            raise NotReadyError(
                f"message position {msg['position']} not yet confirmed (sendCount={size})"
            )
        proof = self.construct_proof(size, msg["position"])
        outbox = self._outbox(self.l1.w3)
        return outbox.functions.executeTransaction(
            proof,
            msg["position"],
            msg["caller"],
            msg["destination"],
            msg["arbBlockNum"],
            msg["ethBlockNum"],
            msg["timestamp"],
            msg["callvalue"],
            bytes.fromhex(msg["data"].removeprefix("0x")),
        )


class NotReadyError(RuntimeError):
    """The L2->L1 message's assertion is not yet confirmed on L1."""
