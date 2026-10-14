"""Typed wrappers around the Vea inbox/outbox contracts.

These adapt ChainClient + ABIs into the narrow read/write surface the detector,
challenger and resolver need. Verdict-critical inbox reads go through
``read_quorum`` so every configured RPC must agree.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from web3 import Web3

from . import abi
from .chain import FINALIZED, LATEST, ChainClient, redact
from .claims import Claim
from .config import RouteCfg
from .verdict import ProviderRoot

log = logging.getLogger(__name__)

# A provider this many blocks behind the highest one is named in a warning.
PIN_SPREAD_WARN = 64
# The spread warning for one provider is logged at most this often.
PIN_SPREAD_LOG_INTERVAL = 3_600


@dataclass(frozen=True)
class OutboxParams:
    deposit: int
    epoch_period: int
    min_challenge_period: int
    timeout_epochs: int


@dataclass(frozen=True)
class L2View:
    """A consistent (timestamp, number) view of the inbox chain at some tag."""

    timestamp: int
    number: int


@dataclass(frozen=True)
class QuorumRead:
    """snapshots(epoch) as every configured inbox RPC answered it at one tag."""

    root: bytes | None  # the agreed root; None when the answers disagree (split)
    view: L2View  # the block the answers were read at
    reads: tuple[ProviderRoot, ...]  # each answering provider's root
    missing: tuple[str, ...]  # labels of providers that did not answer

    @property
    def answered(self) -> int:
        return len(self.reads)

    @property
    def total(self) -> int:
        return len(self.reads) + len(self.missing)

    @property
    def complete(self) -> bool:
        return not self.missing

    @property
    def split(self) -> bool:
        return len({r.root for r in self.reads}) > 1


class OutboxContract:
    def __init__(self, client: ChainClient, route: RouteCfg):
        self.client = client
        self.route = route
        self.address = Web3.to_checksum_address(route.outbox_address)
        self._contract_for = {
            id(w3): w3.eth.contract(address=self.address, abi=abi.OUTBOX_ABI)
            for w3 in client.all_w3()
        }
        self._ts_cache: dict[int, int] = {}

    def _c(self, w3: Web3):
        return self._contract_for[id(w3)]

    def contract(self):
        return self._c(self.client.w3)

    # -- reads ----------------------------------------------------------------

    def params(self) -> OutboxParams:
        def _read(w3: Web3) -> OutboxParams:
            c = self._c(w3)
            return OutboxParams(
                deposit=c.functions.deposit().call(),
                epoch_period=c.functions.epochPeriod().call(),
                min_challenge_period=c.functions.minChallengePeriod().call(),
                timeout_epochs=c.functions.timeoutEpochs().call(),
            )

        return self.client.with_failover(_read)

    def sequencer_delay_limit(self) -> int:
        return int(
            self.client.with_failover(
                lambda w3: self._c(w3).functions.sequencerDelayLimit().call()
            )
        )

    def claim_hash(self, epoch: int, block: int | None = None) -> bytes:
        """claimHashes(epoch) at `latest`, or at `block` when given. A provider
        that cannot serve that block fails over rather than answering stale."""
        if block is None:
            return bytes(
                self.client.with_failover(
                    lambda w3: self._c(w3).functions.claimHashes(epoch).call()
                )
            )
        return bytes(
            self.client.with_failover(
                lambda w3: self._c(w3)
                .functions.claimHashes(epoch)
                .call(block_identifier=block)
            )
        )

    def latest_verified_epoch(self) -> int:
        return int(
            self.client.with_failover(
                lambda w3: self._c(w3).functions.latestVerifiedEpoch().call()
            )
        )

    def upstream_address(self) -> str:
        """The outbox's immutable pairing: veaInboxArbToEth, or routerArbToGnosis."""
        name = (
            "routerArbToGnosis" if self.route.kind == "arb_to_gnosis" else "veaInboxArbToEth"
        )
        return self.client.with_failover(
            lambda w3: self._c(w3).functions[name]().call()
        )

    def hash_claim_onchain(self, claim: Claim) -> bytes:
        """Contract-side hashClaim; used once at startup for parity checking."""
        return bytes(
            self.client.with_failover(
                lambda w3: self._c(w3).functions.hashClaim(claim.as_tuple()).call()
            )
        )

    def fetch_events(self, from_block: int, to_block: int, chunk: int) -> list[dict]:
        """All outbox events in range, normalized and ordered by (block, logIndex)."""
        raw = self.client.get_logs_chunked(
            address=self.address,
            topics=None,
            from_block=from_block,
            to_block=to_block,
            chunk=chunk,
        )
        contract = self.contract()
        events = []
        by_topic = {
            contract.events[name]().topic: name
            for name in (
                "Claimed",
                "Challenged",
                "VerificationStarted",
                "Verified",
                "FailedResolution",
            )
        }
        for entry in raw:
            topic0 = entry["topics"][0].to_0x_hex() if entry["topics"] else None
            name = by_topic.get(topic0)
            if name is None:
                continue
            parsed = contract.events[name]().process_log(entry)
            events.append(
                {
                    "name": name,
                    "args": dict(parsed["args"]),
                    "block_number": parsed["blockNumber"],
                    "log_index": parsed["logIndex"],
                    "tx_hash": parsed["transactionHash"].to_0x_hex(),
                }
            )
        events.sort(key=lambda e: (e["block_number"], e["log_index"]))
        return events

    def block_timestamp(self, block_number: int) -> int:
        cached = self._ts_cache.get(block_number)
        if cached is None:
            cached = int(self.client.block(block_number)["timestamp"])
            self._ts_cache[block_number] = cached
        return cached

    def now(self) -> int:
        """Outbox-chain clock (latest block timestamp)."""
        return int(self.client.block(LATEST)["timestamp"])

    def confirmed_head(self) -> int:
        return self.client.latest_block_number() - self.route.outbox_chain.confirmations


class InboxContract:
    def __init__(self, client: ChainClient, route: RouteCfg):
        self.client = client
        self.route = route
        self.address = Web3.to_checksum_address(route.inbox_address)
        self._spread_logged: dict[str, float] = {}  # label -> last warning time

    def _contract(self, w3: Web3):
        return w3.eth.contract(address=self.address, abi=abi.INBOX_ABI)

    def snapshot_quorum(self, epoch: int, tag: str) -> QuorumRead:
        """snapshots(epoch) at `tag` from every configured RPC.

        Never raises on disagreement: a split is returned with ``root=None`` and
        each provider's answer in ``reads``, so the caller can alert and the
        deadline rule can use per-provider reads. Raises RuntimeError only when
        no provider answered. Every provider is read at one pinned block: the
        lowest tag block among those that answered (minus the inbox chain's
        confirmations for ``latest``); ``view`` is that block.
        """

        client = self.client
        w3s = client.all_w3()
        labels = client.labels

        # 1. resolve the tag on every provider
        heads: dict[int, int] = {}  # provider index -> block number
        failed: set[int] = set()
        for i, w3 in enumerate(w3s):
            try:
                heads[i] = int(w3.eth.get_block(tag)["number"])
            except Exception as exc:  # noqa: BLE001
                failed.add(i)
                client.record_failure(labels[i], exc)
                log.warning("%s: inbox %s block lookup failed: %s", labels[i], tag, redact(str(exc)))
        if not heads:
            raise RuntimeError(
                f"inbox: all RPCs failed resolving {tag}: " + ", ".join(labels)
            )

        # 2. pin the lowest head (minus the confirmation depth for `latest`)
        low_i = min(heads, key=lambda i: heads[i])
        pinned = heads[low_i]
        spread = max(heads.values()) - pinned
        if spread > PIN_SPREAD_WARN:
            # Finality jumps make honest providers differ by this much: no call
            # failed, so this is a log line, not a failure count, once per hour.
            now = time.time()
            last = self._spread_logged.get(labels[low_i])
            if last is None or now - last >= PIN_SPREAD_LOG_INTERVAL:
                self._spread_logged[labels[low_i]] = now
                log.warning(
                    "%s: lowest %s block %d is %d blocks behind the highest provider; "
                    "it sets the pinned block for every provider",
                    labels[low_i],
                    tag,
                    pinned,
                    spread,
                )
        if tag == LATEST:
            pinned = max(0, pinned - self.route.inbox_chain.confirmations)

        # 3. read snapshots(epoch) at that block on every provider
        reads: list[ProviderRoot] = []
        timestamps: list[int] = []
        for i, w3 in enumerate(w3s):
            if i in failed:
                continue
            try:
                block = w3.eth.get_block(pinned)
                root = self._contract(w3).functions.snapshots(epoch).call(
                    block_identifier=pinned
                )
                reads.append(ProviderRoot(label=labels[i], root=bytes(root)))
                timestamps.append(int(block["timestamp"]))
            except Exception as exc:  # noqa: BLE001
                failed.add(i)
                client.record_failure(labels[i], exc)
                log.warning(
                    "%s: inbox quorum read at block %d failed: %s",
                    labels[i],
                    pinned,
                    redact(str(exc)),
                )
        if not reads:
            raise RuntimeError(
                f"inbox: all RPCs failed reading snapshot at block {pinned}: "
                + ", ".join(labels)
            )
        roots = {r.root for r in reads}
        if len(roots) > 1:
            client.record_split([(r.label, r.root) for r in reads])
            log.warning(
                "inbox quorum split for epoch %d at %s block %d: %s; no answer from: %s",
                epoch,
                tag,
                pinned,
                ", ".join(f"{r.label}=0x{r.root.hex()}" for r in reads),
                ", ".join(labels[i] for i in sorted(failed)) or "none",
            )
        return QuorumRead(
            root=reads[0].root if len(roots) == 1 else None,
            view=L2View(timestamp=min(timestamps), number=pinned),
            reads=tuple(reads),
            missing=tuple(labels[i] for i in sorted(failed)),
        )

    def destination(self) -> str:
        """The inbox's immutable L1 target: veaOutboxArbToEth, or routerArbToGnosis."""
        name = (
            "routerArbToGnosis" if self.route.kind == "arb_to_gnosis" else "veaOutboxArbToEth"
        )
        return self.client.with_failover(
            lambda w3: self._contract(w3).functions[name]().call()
        )

    def epoch_period(self) -> int:
        return int(
            self.client.with_failover(
                lambda w3: self._contract(w3).functions.epochPeriod().call()
            )
        )

    def l2_view(self, tag: str) -> L2View:
        block = self.client.block(tag)
        return L2View(timestamp=int(block["timestamp"]), number=int(block["number"]))

    def send_snapshot_fn(self, epoch: int, claim: Claim) -> Any:
        """Bound contract function for sendSnapshot, per route kind."""
        w3 = self.client.w3
        if self.route.kind == "arb_to_gnosis":
            c = w3.eth.contract(
                address=self.address, abi=abi.INBOX_GNOSIS_SEND_SNAPSHOT_ABI
            )
            return c.functions.sendSnapshot(
                epoch, self.route.amb_gas_limit, claim.as_tuple()
            )
        c = self._contract(w3)
        return c.functions.sendSnapshot(epoch, claim.as_tuple())

    def snapshot_sent_events(self, epoch: int, from_block: int, to_block: int) -> list[dict]:
        contract = self._contract(self.client.w3)
        event = contract.events.SnapshotSent()
        raw = self.client.get_logs_chunked(
            address=self.address,
            topics=[event.topic, "0x" + epoch.to_bytes(32, "big").hex()],
            from_block=from_block,
            to_block=to_block,
            chunk=10_000,
        )
        return [dict(event.process_log(entry)["args"]) | {
            "tx_hash": entry["transactionHash"].to_0x_hex()
        } for entry in raw]


class RouterContract:
    """RouterArbToGnosis on the L1 chain; read only for the startup pairing check."""

    def __init__(self, client: ChainClient, address: str):
        self.client = client
        self.address = Web3.to_checksum_address(address)

    def endpoints(self) -> tuple[str, str]:
        """(veaInboxArbToGnosis, veaOutboxArbToGnosis)."""

        def _read(w3: Web3) -> tuple[str, str]:
            c = w3.eth.contract(address=self.address, abi=abi.ROUTER_ABI)
            return (
                c.functions.veaInboxArbToGnosis().call(),
                c.functions.veaOutboxArbToGnosis().call(),
            )

        return self.client.with_failover(_read)


class WethToken:
    def __init__(self, client: ChainClient, token_address: str):
        self.client = client
        self.address = Web3.to_checksum_address(token_address)

    def _contract(self, w3: Web3):
        return w3.eth.contract(address=self.address, abi=abi.WETH_ABI)

    def balance_of(self, owner: str) -> int:
        return int(
            self.client.with_failover(
                lambda w3: self._contract(w3).functions.balanceOf(owner).call()
            )
        )

    def allowance(self, owner: str, spender: str) -> int:
        return int(
            self.client.with_failover(
                lambda w3: self._contract(w3).functions.allowance(owner, spender).call()
            )
        )

    def approve_fn(self, spender: str, amount: int) -> Any:
        return self._contract(self.client.w3).functions.approve(spender, amount)
