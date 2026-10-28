"""Redaction and failure counters in the chain client (PRD 3.1)."""

import logging

import pytest
from web3.exceptions import TransactionNotFound

from vea_challenger.chain import AllProvidersFailed, ChainClient, QuorumError
from vea_challenger.config import ChainCfg

URLS = [
    "https://arb.example.org/v2/PATHSECRET12345",
    "https://rpc.example.net/?apikey=QUERYSECRET6789",
    "https://user:PASSSECRET0123@node.example.io/rpc",
]
SECRETS = ("PATHSECRET12345", "QUERYSECRET6789", "PASSSECRET0123")


def client():
    return ChainClient(ChainCfg(name="chain", chain_id=1, rpc_urls=URLS))


def _fail_with_url(c, idx):
    def fn(w3):
        i = c._w3s.index(w3)
        if i in idx:
            raise ConnectionError(f"cannot connect to {URLS[i]}")
        return i

    return fn


def _clean(text):
    for s in SECRETS:
        assert s not in text


def test_failover_logs_labels_only(caplog):
    c = client()
    with caplog.at_level(logging.WARNING):
        assert c.with_failover(_fail_with_url(c, {0})) == 1
    _clean(caplog.text)
    assert c.labels[0] in caplog.text and c.labels[1] in caplog.text
    st = c.provider_stats()
    assert st[0].failures == 1 and st[0].last_error_ts is not None
    assert st[1].failures == 0


def test_all_failed_message_clean(caplog):
    c = client()
    with caplog.at_level(logging.WARNING), pytest.raises(AllProvidersFailed) as ei:
        c.with_failover(_fail_with_url(c, {0, 1, 2}))
    _clean(str(ei.value))
    _clean(caplog.text)
    assert [s.failures for s in c.provider_stats()] == [1, 1, 1]


def test_quorum_split_message(caplog):
    c = client()
    with caplog.at_level(logging.WARNING), pytest.raises(QuorumError) as ei:
        c.read_quorum(lambda w3: "x" if c._w3s.index(w3) < 2 else f"y{URLS[2]}")
    msg = str(ei.value)
    _clean(msg)
    _clean(caplog.text)
    # each label is paired with its own result
    assert f"{c.labels[0]}: 'x'" in msg
    assert f"{c.labels[1]}: 'x'" in msg
    assert f"{c.labels[2]}: 'y" in msg
    st = c.provider_stats()
    assert [s.quorum_disagreements for s in st] == [0, 0, 1]


def test_quorum_tie_counts_everyone_and_failures():
    c = client()
    with pytest.raises(QuorumError):
        c.read_quorum(lambda w3: c._w3s.index(w3) % 2 if c._w3s.index(w3) < 2 else 1 / 0)
    st = c.provider_stats()
    assert [s.quorum_disagreements for s in st] == [1, 1, 0]
    assert st[2].failures == 1


def test_getlogs_retry_clean(caplog, monkeypatch):
    c = client()
    monkeypatch.setattr("vea_challenger.chain.time.sleep", lambda s: None)
    calls = {"n": 0}

    def get_logs(p):
        raise ConnectionError(f"429 for {URLS[0]} {URLS[1]} {URLS[2]}")

    for w3 in c._w3s:
        w3.eth.get_logs = get_logs  # type: ignore[assignment]
    with caplog.at_level(logging.WARNING), pytest.raises(AllProvidersFailed) as ei:
        c.get_logs_chunked(
            address="0x" + "11" * 20, topics=None, from_block=1, to_block=2, retries=2
        )
    _clean(caplog.text)
    _clean(str(ei.value))
    assert "retrying" in caplog.text and c.labels[0] in caplog.text
    # every attempt of the chunk failed on every provider, and the counters moved
    assert [s.failures for s in c.provider_stats()] == [2, 2, 2]


# -- receipt_or_none (f10) ---------------------------------------------------------


def _receipts(c, answers):
    """answers: per provider, a receipt, 'nf' (TransactionNotFound) or 'err'."""
    for w3, ans in zip(c._w3s, answers):

        def get(tx, ans=ans):
            if ans == "nf":
                raise TransactionNotFound(f"not found {tx}")
            if ans == "err":
                raise ConnectionError(f"down {URLS[0]}")
            return ans

        w3.eth.get_transaction_receipt = get  # type: ignore[assignment]


def test_receipt_all_not_found_is_none():
    c = client()
    _receipts(c, ["nf", "nf", "nf"])
    assert c.receipt_or_none("0xab") is None
    assert [s.failures for s in c.provider_stats()] == [0, 0, 0]


def test_receipt_one_error_one_not_found_is_none():
    c = client()
    _receipts(c, ["err", "nf", "err"])
    assert c.receipt_or_none("0xab") is None
    assert [s.failures for s in c.provider_stats()] == [1, 0, 1]


def test_receipt_all_erroring_raises(caplog):
    c = client()
    _receipts(c, ["err", "err", "err"])
    with caplog.at_level(logging.WARNING), pytest.raises(AllProvidersFailed) as ei:
        c.receipt_or_none("0xab")
    _clean(str(ei.value))
    _clean(caplog.text)


def test_receipt_returned_when_one_has_it():
    c = client()
    _receipts(c, ["err", "nf", {"status": 1}])
    assert c.receipt_or_none("0xab") == {"status": 1}


def test_receipt_after_a_not_found_provider_still_found():
    c = client()
    _receipts(c, ["nf", {"status": 1}, "nf"])
    assert c.receipt_or_none("0xab") == {"status": 1}
