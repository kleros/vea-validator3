"""Seeded cross-lane interfaces (frozen for the challenger-v1-fixes run)."""

import logging

from vea_challenger.chain import (
    ChainClient,
    RedactingFilter,
    endpoint_label,
    parse_endpoint,
    redact,
)
from vea_challenger.config import ChainCfg
from vea_challenger.contracts import L2View, QuorumRead
from vea_challenger.verdict import Decision, ProviderRoot, Verdict

KEYED = [
    "https://arb-sepolia.g.alchemy.com/v2/SECRETPATHKEY123",
    "https://rpc.example.org/?apikey=SECRETQUERYKEY456",
    "https://user:SECRETPASS789@node.example.net/rpc",
    "ops=https://SECRETSUBDOMAIN.rpc.example.io",
]
SECRETS = ("SECRETPATHKEY123", "SECRETQUERYKEY456", "SECRETPASS789", "SECRETSUBDOMAIN")


def test_parse_endpoint_and_label():
    assert parse_endpoint("ops=https://a.example/x") == ("ops", "https://a.example/x")
    assert parse_endpoint("https://a.example/x?k=v") == (None, "https://a.example/x?k=v")
    assert endpoint_label("arbitrum-sepolia", 2, "https://h.example/k", None) == (
        "arbitrum-sepolia#2 (h.example)"
    )
    assert endpoint_label("arbitrum-sepolia", 3, "https://h.example/k", "ops") == (
        "arbitrum-sepolia#3 (ops)"
    )


def test_client_labels_and_redaction():
    client = ChainClient(ChainCfg(name="arbitrum-sepolia", chain_id=1, rpc_urls=KEYED))
    assert client.labels == [
        "arbitrum-sepolia#0 (arb-sepolia.g.alchemy.com)",
        "arbitrum-sepolia#1 (rpc.example.org)",
        "arbitrum-sepolia#2 (node.example.net)",
        "arbitrum-sepolia#3 (ops)",
    ]
    assert [s.label for s in client.provider_stats()] == client.labels
    text = redact(" | ".join(KEYED + ["https://SECRETSUBDOMAIN.rpc.example.io/"]))
    for secret in SECRETS:
        assert secret not in text
    assert "arbitrum-sepolia#0 (arb-sepolia.g.alchemy.com)" in text


def test_redacting_filter_covers_args_and_traceback():
    ChainClient(ChainCfg(name="arbitrum-sepolia", chain_id=1, rpc_urls=KEYED))
    try:
        raise ConnectionError(f"failed to reach {KEYED[0]}")
    except ConnectionError:
        import sys

        record = logging.LogRecord(
            "t", logging.WARNING, __file__, 1, "rpc %s down", (KEYED[1],), sys.exc_info()
        )
    RedactingFilter().filter(record)
    out = logging.Formatter().format(record)
    for secret in SECRETS[:2]:
        assert secret not in out
    assert "arbitrum-sepolia#1 (rpc.example.org)" in out


def test_quorum_read_properties():
    view = L2View(timestamp=10, number=5)
    a, b = b"\xaa" * 32, b"\xbb" * 32
    agree = QuorumRead(a, view, (ProviderRoot("i#0", a), ProviderRoot("i#1", a)), ())
    assert agree.complete and not agree.split and agree.answered == 2 == agree.total
    partial = QuorumRead(a, view, (ProviderRoot("i#0", a),), ("i#1",))
    assert not partial.complete and partial.answered == 1 and partial.total == 2
    split = QuorumRead(None, view, (ProviderRoot("i#0", a), ProviderRoot("i#1", b)), ())
    assert split.split and split.root is None


def test_decision_defaults():
    d = Decision(Verdict.WAIT)
    assert d.root is None and d.leg is None and d.reason == ""
