"""snapshot_quorum: one pinned block for every provider (PRD 1.3, 1.4)."""

import logging
from types import SimpleNamespace

from vea_challenger.chain import FINALIZED, LATEST, ChainClient
from vea_challenger.config import ChainCfg
from vea_challenger.contracts import InboxContract

A, B = b"\xaa" * 32, b"\xbb" * 32
ADDR = "0x" + "11" * 20


class FakeProvider:
    """head: block number for any tag; roots: {block: root} (missing -> error)."""

    def __init__(self, head, roots, ts_per_block=10):
        self.head, self.roots, self.tsb = head, roots, ts_per_block
        self.eth = SimpleNamespace(get_block=self._block, contract=self._contract)

    def _block(self, tag):
        n = self.head if isinstance(tag, str) else tag
        if n > self.head:
            raise ValueError("block not found")
        return {"number": n, "timestamp": n * self.tsb}

    def _contract(self, address, abi):
        prov = self

        class Fn:
            def __init__(self, epoch):
                pass

            def call(self, block_identifier):
                if block_identifier not in prov.roots:
                    raise ValueError("missing trie node")
                return prov.roots[block_identifier]

        return SimpleNamespace(functions=SimpleNamespace(snapshots=Fn))


def make(providers, confirmations=3):
    client = ChainClient(
        ChainCfg(
            name="inbox",
            chain_id=1,
            rpc_urls=[f"https://h{i}.example.org/key{i}secretkey" for i in range(len(providers))],
        )
    )
    client._w3s = providers
    route = SimpleNamespace(
        inbox_address=ADDR, inbox_chain=SimpleNamespace(confirmations=confirmations)
    )
    return InboxContract(client, route), client


def test_lower_height_agreement():
    p0 = FakeProvider(100, {100: A, 90: B})
    p1 = FakeProvider(90, {90: B, 100: A})
    inbox, _ = make([p0, p1])
    q = inbox.snapshot_quorum(1, FINALIZED)
    assert q.root == B and q.view.number == 90 and q.view.timestamp == 900
    assert not q.missing and not q.split


def test_real_split_same_block(caplog):
    inbox, client = make([FakeProvider(50, {50: A}), FakeProvider(50, {50: B})])
    with caplog.at_level(logging.WARNING):
        q = inbox.snapshot_quorum(1, FINALIZED)
    assert q.root is None and q.split
    assert {r.root for r in q.reads} == {A, B}
    assert all(s.quorum_disagreements == 1 for s in client.provider_stats())
    # the split log names each label with its root, never the keyed URL
    assert f"{client.labels[0]}=0x{A.hex()}" in caplog.text
    assert f"{client.labels[1]}=0x{B.hex()}" in caplog.text
    assert "secretkey" not in caplog.text


def test_provider_without_block_is_missing():
    inbox, client = make([FakeProvider(100, {90: A}), FakeProvider(90, {90: A})])
    q = inbox.snapshot_quorum(1, FINALIZED)
    assert q.root == A and q.missing == ()
    inbox, client = make([FakeProvider(100, {}), FakeProvider(90, {90: A})])
    q = inbox.snapshot_quorum(1, FINALIZED)
    assert q.missing == (client.labels[0],) and q.root == A
    assert client.provider_stats()[0].failures == 1


def test_all_fail_raises():
    inbox, _ = make([FakeProvider(10, {}), FakeProvider(10, {})])
    try:
        inbox.snapshot_quorum(1, FINALIZED)
    except RuntimeError:
        pass
    else:
        raise AssertionError


def test_latest_confirmation_depth():
    boundary = 1000
    inbox, _ = make([FakeProvider(101, {101: A, 98: A}), FakeProvider(101, {101: A, 98: A})])
    # head ts 1010 >= boundary, head - 3 = 98 -> ts 980 < boundary
    fin = inbox.snapshot_quorum(1, FINALIZED)
    lat = inbox.snapshot_quorum(1, LATEST)
    assert fin.view.timestamp >= boundary
    assert lat.view.number == 98 and lat.view.timestamp < boundary


def test_lagging_provider_named(caplog):
    inbox, client = make(
        [FakeProvider(1000, {10: A}), FakeProvider(10, {10: A})]
    )
    with caplog.at_level(logging.WARNING):
        q = inbox.snapshot_quorum(1, FINALIZED)
    assert q.view.number == 10
    assert client.labels[1] in caplog.text
    # finality lag is not a failure: no counter moves
    assert client.provider_stats()[1].failures == 0
    assert "secretkey" not in caplog.text


def test_pin_spread_warning_at_most_once_per_hour_per_provider(caplog, monkeypatch):
    inbox, client = make([FakeProvider(1000, {10: A}), FakeProvider(10, {10: A})])
    now = [1_000_000.0]
    monkeypatch.setattr("vea_challenger.contracts.time.time", lambda: now[0])

    def warnings():
        return [r for r in caplog.records if "blocks behind" in r.getMessage()]

    with caplog.at_level(logging.WARNING):
        inbox.snapshot_quorum(1, FINALIZED)
        inbox.snapshot_quorum(2, FINALIZED)
        assert len(warnings()) == 1
        now[0] += 3_599
        inbox.snapshot_quorum(3, FINALIZED)
        assert len(warnings()) == 1
        now[0] += 2
        inbox.snapshot_quorum(4, FINALIZED)
        assert len(warnings()) == 2
    assert [s.failures for s in client.provider_stats()] == [0, 0]


def test_tag_lookup_failure_log_names_label_not_url(caplog):
    class Broken(FakeProvider):
        def _block(self, tag):
            if isinstance(tag, str):
                raise ConnectionError("down: https://h0.example.org/key0secretkey")
            return super()._block(tag)

    inbox, client = make([Broken(100, {90: A}), FakeProvider(90, {90: A})])
    with caplog.at_level(logging.WARNING):
        q = inbox.snapshot_quorum(1, FINALIZED)
    assert q.missing == (client.labels[0],)
    assert f"{client.labels[0]}: inbox finalized block lookup failed" in caplog.text
    assert "secretkey" not in caplog.text


def test_pinned_read_failure_log_names_label_not_url(caplog):
    class BrokenRead(FakeProvider):
        def _contract(self, address, abi):
            class Fn:
                def __init__(self, epoch):
                    pass

                def call(self, block_identifier):
                    raise ConnectionError("down: https://h0.example.org/key0secretkey")

            return SimpleNamespace(functions=SimpleNamespace(snapshots=Fn))

    inbox, client = make([BrokenRead(90, {}), FakeProvider(90, {90: A})])
    with caplog.at_level(logging.WARNING):
        q = inbox.snapshot_quorum(1, FINALIZED)
    assert q.missing == (client.labels[0],)
    assert f"{client.labels[0]}: inbox quorum read at block 90 failed" in caplog.text
    assert "secretkey" not in caplog.text


def test_claim_hash_reads_at_the_given_block_and_fails_over():
    from vea_challenger.contracts import OutboxContract

    H_LATEST, H_AT = b"\x01" * 32, b"\x02" * 32
    calls = []

    class Prov:
        def __init__(self, serves_block):
            self.serves_block = serves_block
            self.eth = SimpleNamespace(contract=self._contract)

        def _contract(self, address, abi):
            prov = self

            class Fn:
                def __init__(self, epoch):
                    pass

                def call(self, block_identifier=None):
                    calls.append(block_identifier)
                    if block_identifier is None:
                        return H_LATEST
                    if not prov.serves_block:
                        raise ValueError("missing trie node")
                    return H_AT

            return SimpleNamespace(functions=SimpleNamespace(claimHashes=Fn))

    client = ChainClient(
        ChainCfg(name="outbox", chain_id=1, rpc_urls=["https://a.example.org/k1xxxxxxx", "https://b.example.org/k2xxxxxxx"])
    )
    client._w3s = [Prov(False), Prov(True)]
    route = SimpleNamespace(outbox_address=ADDR)
    outbox = OutboxContract(client, route)
    assert outbox.claim_hash(1) == H_LATEST
    assert outbox.claim_hash(1, block=123) == H_AT  # provider 0 cannot serve it: failover
    assert calls[-2:] == [123, 123]
    assert client.provider_stats()[0].failures == 1
