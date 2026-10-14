"""Multi-RPC chain client: rotating failover, quorum reads, tx submission.

Verdict-critical reads use ``read_quorum`` (every configured RPC must agree);
everything else rides a primary provider that rotates away on failure.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit
from typing import Any, Callable, Iterable, TypeVar

from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import HTTPProvider, Web3
from web3.exceptions import TransactionNotFound
from web3.types import TxReceipt

from .config import ChainCfg

log = logging.getLogger(__name__)

T = TypeVar("T")

FINALIZED = "finalized"
LATEST = "latest"


class QuorumError(RuntimeError):
    """Configured RPCs disagree on a verdict-critical read."""


class AllProvidersFailed(RuntimeError):
    pass


@dataclass
class ProviderStats:
    """Per-endpoint counters for the process lifetime (shown by `status`)."""

    label: str
    failures: int = 0
    quorum_disagreements: int = 0
    last_error_ts: float | None = None


# -- endpoint labels and redaction ----------------------------------------------
# RPC URLs often carry API keys (path, query, userinfo or subdomain). Logs and
# alerts name an endpoint by its label, never by its URL.

_LABELLED = re.compile(r"^([A-Za-z0-9_.-]+)=([A-Za-z][A-Za-z0-9+.-]*://.*)$")
_REDACTIONS: dict[str, str] = {}  # secret substring -> label replacing it
_MIN_SECRET_LEN = 8  # shorter path/query parts (e.g. "/rpc") are not secrets


def parse_endpoint(raw: str) -> tuple[str | None, str]:
    """`label=https://...` -> ("label", "https://..."); a bare URL -> (None, url)."""
    m = _LABELLED.match(raw.strip())
    if m:
        return m.group(1), m.group(2)
    return None, raw.strip()


def endpoint_label(chain_name: str, index: int, url: str, operator_label: str | None) -> str:
    """`<chain>#<index> (<host>)`, or `(<operator label>)` to keep the host out."""
    shown = operator_label or (urlsplit(url).hostname or "?")
    return f"{chain_name}#{index} ({shown})"


def register_endpoint(url: str, label: str, hide_host: bool) -> None:
    """Make redact() replace this URL, and its secret-bearing parts, with label."""
    parts = urlsplit(url)
    _REDACTIONS[url] = label
    _REDACTIONS[url.rstrip("/")] = label
    path_query = parts.path + (f"?{parts.query}" if parts.query else "")
    for secret in (path_query, parts.path, parts.query):
        if len(secret) >= _MIN_SECRET_LEN:
            _REDACTIONS[secret] = label
    if "@" in parts.netloc:
        _REDACTIONS[parts.netloc.rsplit("@", 1)[0]] = label
    if hide_host and parts.hostname:
        _REDACTIONS[parts.hostname] = label


def redact(text: str) -> str:
    """Replace every registered URL (or secret part of one) in text by its label."""
    for secret in sorted(_REDACTIONS, key=len, reverse=True):
        if secret in text:
            text = text.replace(secret, _REDACTIONS[secret])
    return text


class RedactingFilter(logging.Filter):
    """Handler filter: redacts the formatted message and any traceback text."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact(record.exc_text)
        return True


def install_log_redaction(logger: logging.Logger | None = None) -> None:
    """Attach RedactingFilter to every handler of `logger` (default: root)."""
    for handler in (logger or logging.getLogger()).handlers:
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(RedactingFilter())


@dataclass
class Eip1559Fees:
    max_fee_per_gas: int
    max_priority_fee_per_gas: int


class ChainClient:
    def __init__(self, cfg: ChainCfg, request_timeout: float = 30.0):
        self.cfg = cfg
        urls: list[str] = []
        self.labels: list[str] = []
        for i, raw in enumerate(cfg.rpc_urls):
            operator_label, url = parse_endpoint(raw)
            label = endpoint_label(cfg.name, i, url, operator_label)
            register_endpoint(url, label, hide_host=operator_label is not None)
            urls.append(url)
            self.labels.append(label)
        self._stats = [ProviderStats(label=label) for label in self.labels]
        self._w3s = [
            Web3(HTTPProvider(url, request_kwargs={"timeout": request_timeout}))
            for url in urls
        ]
        if not self._w3s:
            raise ValueError(f"chain {cfg.name}: no RPC URLs configured")
        self._primary = 0

    @property
    def name(self) -> str:
        return self.cfg.name

    @property
    def w3(self) -> Web3:
        return self._w3s[self._primary]

    def all_w3(self) -> list[Web3]:
        return list(self._w3s)

    def provider_stats(self) -> list[ProviderStats]:
        """Counters per endpoint, in configured order (labels as in self.labels)."""
        return list(self._stats)

    # -- per-provider counters ------------------------------------------------

    def record_failure(self, label: str, exc: BaseException | None = None) -> None:
        for st in self._stats:
            if st.label == label:
                st.failures += 1
                st.last_error_ts = time.time()
                return

    def record_split(self, answers: list[tuple[str, Any]]) -> None:
        """Count a disagreement for each provider whose answer differs from the
        most common one. On a tie for most common, every provider is counted."""
        groups: list[list[Any]] = []  # [value, count]
        for _, value in answers:
            for g in groups:
                if g[0] == value:
                    g[1] += 1
                    break
            else:
                groups.append([value, 1])
        if len(groups) < 2:
            return
        top = max(g[1] for g in groups)
        winners = [g[0] for g in groups if g[1] == top]
        tie = len(winners) > 1
        for label, value in answers:
            if tie or value != winners[0]:
                for st in self._stats:
                    if st.label == label:
                        st.quorum_disagreements += 1

    def with_failover(self, fn: Callable[[Web3], T]) -> T:
        """Run fn against the primary; rotate to the next RPC on failure."""
        last_exc: Exception | None = None
        n = len(self._w3s)
        for attempt in range(n):
            idx = (self._primary + attempt) % n
            try:
                result = fn(self._w3s[idx])
                self._primary = idx
                return result
            except Exception as exc:  # noqa: BLE001 - provider errors are diverse
                last_exc = exc
                self.record_failure(self.labels[idx], exc)
                if attempt + 1 < n:
                    nxt = self.labels[(idx + 1) % n]
                    log.warning(
                        "%s failed: %s; failing over to %s",
                        self.labels[idx],
                        redact(str(exc)),
                        nxt,
                    )
                else:
                    log.warning(
                        "%s failed: %s; no providers left to try",
                        self.labels[idx],
                        redact(str(exc)),
                    )
        raise AllProvidersFailed(
            f"chain {self.cfg.name}: all RPCs failed"
            + (f": {redact(str(last_exc))}" if last_exc else "")
        ) from last_exc

    def read_quorum(self, fn: Callable[[Web3], T]) -> T:
        """Run fn on every RPC; all reachable ones must agree, and at least one
        must answer. Raises QuorumError on disagreement."""
        answers: list[tuple[str, T]] = []
        errors: list[tuple[str, str]] = []
        for w3, label in zip(self._w3s, self.labels):
            try:
                answers.append((label, fn(w3)))
            except Exception as exc:  # noqa: BLE001
                text = redact(str(exc))
                errors.append((label, text))
                self.record_failure(label, exc)
                log.warning("%s: quorum read failed: %s", label, text)
        if not answers:
            raise AllProvidersFailed(
                f"chain {self.cfg.name}: all RPCs failed during quorum read: "
                + "; ".join(f"{lb}: {t}" for lb, t in errors)
            )
        first = answers[0][1]
        if any(r != first for _, r in answers[1:]):
            self.record_split(answers)
            detail = "; ".join(f"{lb}: {r!r}" for lb, r in answers)
            if errors:
                detail += "; no answer from " + ", ".join(lb for lb, _ in errors)
            raise QuorumError(
                redact(f"chain {self.cfg.name}: RPCs disagree on quorum read: {detail}")
            )
        return first

    # -- blocks / finality ----------------------------------------------------

    def block(self, tag: str | int = LATEST) -> Any:
        return self.with_failover(lambda w3: w3.eth.get_block(tag))

    def latest_block_number(self) -> int:
        return int(self.with_failover(lambda w3: w3.eth.block_number))

    def supports_finalized(self) -> bool:
        """True if the primary RPC serves a genuine `finalized` tag.

        An RPC that aliases finalized->latest returns the same block for both;
        real finality always lags the head on live chains (retry once to ride
        out the corner case of an idle chain tip).
        """
        for _ in range(2):
            try:
                fin = self.block(FINALIZED)
                latest = self.block(LATEST)
            except Exception:  # noqa: BLE001
                return False
            if fin["number"] < latest["number"]:
                return True
            time.sleep(2)
        return False

    # -- logs -----------------------------------------------------------------

    def get_logs_chunked(
        self,
        *,
        address: str,
        topics: list | None,
        from_block: int,
        to_block: int,
        chunk: int = 5_000,
        inter_chunk_delay: float = 0.25,
        retries: int = 4,
    ) -> list[dict]:
        out: list[dict] = []
        start = from_block
        while start <= to_block:
            end = min(start + chunk - 1, to_block)
            params = {
                "address": Web3.to_checksum_address(address),
                "fromBlock": start,
                "toBlock": end,
            }
            if topics is not None:
                params["topics"] = topics
            # Public RPCs rate-limit bursts of getLogs; back off and retry
            # before concluding the range is unfetchable.
            for attempt in range(retries):
                try:
                    out.extend(
                        self.with_failover(lambda w3, p=params: w3.eth.get_logs(p))
                    )
                    break
                except AllProvidersFailed as exc:
                    if attempt == retries - 1:
                        raise
                    delay = 2.0 * 2**attempt
                    log.warning(
                        "%s: getLogs [%s, %s] failed on all of %s (%s); retrying in %.0fs",
                        self.cfg.name,
                        start,
                        end,
                        ", ".join(self.labels),
                        redact(str(exc.__cause__ or exc)),
                        delay,
                    )
                    time.sleep(delay)
            start = end + 1
            if start <= to_block and inter_chunk_delay:
                time.sleep(inter_chunk_delay)
        return out

    # -- transactions ---------------------------------------------------------

    def fees(self, urgency: float = 1.0) -> Eip1559Fees:
        def _fees(w3: Web3) -> Eip1559Fees:
            base = w3.eth.get_block(LATEST)["baseFeePerGas"]
            try:
                prio = w3.eth.max_priority_fee
            except Exception:  # noqa: BLE001 - some RPCs lack the endpoint
                prio = Web3.to_wei(0.1, "gwei")
            prio = max(int(prio * urgency), Web3.to_wei(0.05, "gwei"))
            return Eip1559Fees(
                max_fee_per_gas=int(base * 2 * urgency) + prio,
                max_priority_fee_per_gas=prio,
            )

        return self.with_failover(_fees)

    def pending_nonce(self, address: str) -> int:
        return int(
            self.with_failover(lambda w3: w3.eth.get_transaction_count(address, "pending"))
        )

    def send_signed(self, account: LocalAccount, tx: dict) -> str:
        signed = account.sign_transaction(tx)
        tx_hash = self.with_failover(
            lambda w3: w3.eth.send_raw_transaction(signed.raw_transaction)
        )
        return tx_hash.to_0x_hex()

    def wait_receipt(self, tx_hash: str, timeout: float = 300.0) -> TxReceipt:
        return self.with_failover(
            lambda w3: w3.eth.wait_for_transaction_receipt(tx_hash, timeout=timeout)
        )

    def receipt_or_none(self, tx_hash: str) -> TxReceipt | None:
        """The receipt any provider has, else None when the providers that answered
        all said the transaction is not found; raises AllProvidersFailed only when
        no provider gave either answer. A not-found answer is not a provider
        failure and does not end the search."""
        not_found = 0
        last_exc: Exception | None = None
        for w3, label in zip(self._w3s, self.labels):
            try:
                return w3.eth.get_transaction_receipt(tx_hash)
            except TransactionNotFound:
                not_found += 1
            except Exception as exc:  # noqa: BLE001 - provider errors are diverse
                last_exc = exc
                self.record_failure(label, exc)
                log.warning("%s: receipt lookup failed: %s", label, redact(str(exc)))
        if not_found:
            return None
        raise AllProvidersFailed(
            f"chain {self.cfg.name}: all RPCs failed"
            + (f": {redact(str(last_exc))}" if last_exc else "")
        ) from last_exc


def load_account(private_key: str) -> LocalAccount:
    return Account.from_key(private_key)


def wait_for(predicate: Callable[[], bool], timeout: float, interval: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()
