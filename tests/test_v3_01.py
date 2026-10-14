"""V3-01: a third party's SnapshotSent ticket is adopted only from the inbox's L2ToL1Tx.

A wrapper contract can emit its own ArbSys L2ToL1Tx (carrying our exact
post-challenge struct) before calling inbox.sendSnapshot with a wrong struct.
The inbox still emits SnapshotSent, so the adoption scan finds the tx; the
parser must pick the inbox's message, not the first ArbSys log.
"""

import json
from types import SimpleNamespace

from eth_abi import encode as abi_encode
from hexbytes import HexBytes
from web3 import Web3

from vea_challenger import abi
from vea_challenger.arbitrum import RESOLVE_SELECTOR
from vea_challenger.claims import Claim, Party
from vea_challenger.config import BUILTIN_ROUTES
from vea_challenger.resolver import Resolver
from vea_challenger.store import CHALLENGED, ClaimRow

ROUTE = BUILTIN_ROUTES["arb-sepolia-to-sepolia-testnet"]
INBOX = Web3.to_checksum_address(ROUTE.inbox_address)
OUTBOX = Web3.to_checksum_address(ROUTE.outbox_address)
WRAPPER = "0x00000000000000000000000000000000000000E5"
CLAIMER = "0x00000000000000000000000000000000000000A1"
US = "0x00000000000000000000000000000000000000C3"
EPOCH = 100
TOPIC = Web3.keccak(text="L2ToL1Tx(address,address,uint256,uint256,uint256,uint256,uint256,uint256,bytes)")

GOOD = Claim(b"\xaa" * 32, CLAIMER, 1_000, 2_000, 50, Party.NONE, US)
BAD = Claim(b"\xbb" * 32, CLAIMER, 1_000, 2_000, 50, Party.NONE, US)


def _resolve_data(claim: Claim, epoch: int = EPOCH) -> bytes:
    return RESOLVE_SELECTOR + abi_encode(
        ["uint256", "bytes32", "(bytes32,address,uint32,uint32,uint32,uint8,address)"],
        [epoch, b"\x11" * 32, claim.as_tuple()],
    )


def _l2tol1_log(
    caller: str, destination: str, position: int, claim: Claim, log_index: int, epoch: int = EPOCH
) -> dict:
    topics = [
        HexBytes(TOPIC),
        HexBytes(abi_encode(["address"], [destination])),
        HexBytes(abi_encode(["uint256"], [position + 7])),
        HexBytes(abi_encode(["uint256"], [position])),
    ]
    data = abi_encode(
        ["address", "uint256", "uint256", "uint256", "uint256", "bytes"],
        [caller, 1, 2, 3, 0, _resolve_data(claim, epoch)],
    )
    return {
        "address": Web3.to_checksum_address(abi.ARBSYS_ADDRESS),
        "topics": topics,
        "data": HexBytes(data),
        "logIndex": log_index,
        "transactionIndex": 0,
        "transactionHash": HexBytes(b"\x01" * 32),
        "blockHash": HexBytes(b"\x02" * 32),
        "blockNumber": 10,
    }


def _resolver(receipt: dict) -> Resolver:
    client = SimpleNamespace(
        w3=Web3(),
        latest_block_number=lambda: 200_000,
        receipt_or_none=lambda h: receipt,
    )
    inbox = SimpleNamespace(
        client=client,
        address=INBOX,
        route=ROUTE,
        snapshot_sent_events=lambda epoch, a, b: [{"tx_hash": "0x" + "01" * 32}],
    )
    return Resolver(
        store=None, outbox=None, inbox=inbox, params=None, executor=None,
        l2_sender=None, l1_sender=None, outbox_sender=None, notifier=None,
        challenge_address=US, dry_run=False,
    )


def _row() -> ClaimRow:
    return ClaimRow(epoch=EPOCH, status=CHALLENGED, claim=GOOD)


def test_forged_wrapper_ticket_not_adopted():
    # Wrapper emits our exact struct first; the inbox's real message carries a wrong one.
    receipt = {"logs": [
        _l2tol1_log(WRAPPER, OUTBOX, 5, GOOD, 0),
        _l2tol1_log(INBOX, OUTBOX, 6, BAD, 1),
    ]}
    assert _resolver(receipt)._find_existing_ticket(_row()) is None


def test_ticket_without_inbox_message_not_adopted():
    receipt = {"logs": [_l2tol1_log(WRAPPER, OUTBOX, 5, GOOD, 0)]}
    assert _resolver(receipt)._find_existing_ticket(_row()) is None


def test_inbox_message_selected_after_unrelated_log():
    # A wrapper's own (wrong) message first does not hide the inbox's correct one.
    receipt = {"logs": [
        _l2tol1_log(WRAPPER, OUTBOX, 5, BAD, 0),
        _l2tol1_log(INBOX, OUTBOX, 6, GOOD, 1),
    ]}
    adopted = _resolver(receipt)._find_existing_ticket(_row())
    assert adopted is not None
    msg = json.loads(adopted[1])
    assert (msg["caller"], msg["position"]) == (INBOX, 6)


def test_inbox_message_for_another_epoch_not_adopted():
    # A wrapper calls inbox.sendSnapshot(E-1, our struct), then sendSnapshot(E, a bad
    # struct): the first inbox message carries our struct but resolves another epoch.
    receipt = {"logs": [
        _l2tol1_log(INBOX, OUTBOX, 5, GOOD, 0, epoch=EPOCH - 1),
        _l2tol1_log(INBOX, OUTBOX, 6, BAD, 1),
    ]}
    assert _resolver(receipt)._find_existing_ticket(_row()) is None
