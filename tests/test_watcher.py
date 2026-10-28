"""Watcher tick: deadline alerts, startup checks, per-row isolation, 3.3 alarms."""

import threading
from types import SimpleNamespace

import pytest

from vea_challenger.chain import ChainClient
from vea_challenger.challenger import Challenger
from vea_challenger.claims import Claim
from vea_challenger.config import BUILTIN_ROUTES, ChainCfg, Settings
from vea_challenger.contracts import OutboxParams
from vea_challenger.store import CHALLENGE_PENDING, SEEN, UNDECIDED, ClaimRow, Store
from vea_challenger.verdict import Verdict
from vea_challenger import watcher
from vea_challenger.watcher import App, startup_checks, tick

from conftest import FakeNotifier, FakeOutbox

CLAIMER = "0x00000000000000000000000000000000000000A1"
PERIOD = 7_200
SEQ = 86_400
MIN_CP = 10_800
CLAIMED = 1_000_000
DEADLINE = CLAIMED + PERIOD + SEQ + MIN_CP


class FakeDetector:
    def __init__(self, params):
        self.params = params
        self.reconcile_raises: set[int] = set()
        self.evaluated: list[int] = []

    sync_error: Exception | None = None

    def sync_events(self):
        if self.sync_error is not None:
            raise self.sync_error

    def reconcile(self, row):
        if row.epoch in self.reconcile_raises:
            raise RuntimeError("boom")
        return row

    def evaluate(self, row):
        self.evaluated.append(row.epoch)
        return Verdict.CHALLENGE if row.epoch in getattr(self, "fraud", ()) else Verdict.WAIT


class FakeChallenger:
    def __init__(self):
        self.challenged: list[int] = []

    def challenge(self, row):
        self.challenged.append(row.epoch)
        return True


def _claim(ts=CLAIMED):
    return Claim(
        state_root=b"\xaa" * 32, claimer=CLAIMER, timestamp_claimed=ts,
        timestamp_verification=0, blocknumber_verification=0, honest=0,
        challenger="0x" + "0" * 40,
    )


def make_app(tmp_path, devnet=False, settings=None, challenger=None, db="t.db"):
    params = OutboxParams(deposit=10**18, epoch_period=PERIOD,
                          min_challenge_period=MIN_CP, timeout_epochs=100)
    outbox = FakeOutbox()
    outbox._now = CLAIMED
    outbox.latest_verified = 10**9  # far in the future: no shutdown countdown
    notifier = FakeNotifier()
    app = App(
        settings=settings or Settings(liveness_epochs=None),
        route=SimpleNamespace(devnet=devnet, name="t"),
        store=Store(tmp_path / db),
        notifier=notifier,
        outbox=outbox,
        inbox=None,
        detector=FakeDetector(params),
        challenger=challenger,
        resolver=None,
    )
    return app


def add_row(app, epoch, status=UNDECIDED, note="undecided: finality lagging", ts=CLAIMED):
    app.store.upsert_claim(ClaimRow(epoch=epoch, status=status, claim=_claim(ts), note=note))


def count(app, level, needle):
    return sum(1 for l, m in app.notifier.messages if l == level and needle in m)


def test_deadline_alerts_once_each_and_survive_reopen(tmp_path):
    app = make_app(tmp_path)
    add_row(app, 100)
    tick(app)
    assert app.notifier.messages == []
    app.outbox._now = DEADLINE - 4 * 3600
    for _ in range(3):
        tick(app)
    assert count(app, "WARNING", "epoch 100") == 1
    assert "finality lagging" in app.notifier.messages[0][1]
    assert str(4 * 3600) in app.notifier.messages[0][1]
    assert count(app, "CRITICAL", "epoch 100") == 0
    app.outbox._now = DEADLINE - 3600
    for _ in range(3):
        tick(app)
    assert count(app, "CRITICAL", "epoch 100") == 1
    assert count(app, "WARNING", "epoch 100") == 1
    app.store.close()

    app2 = make_app(tmp_path)
    app2.outbox._now = DEADLINE - 3000
    tick(app2)
    assert app2.notifier.messages == []


def test_no_deadline_alert_on_devnet(tmp_path):
    app = make_app(tmp_path, devnet=True)
    add_row(app, 100)
    app.outbox._now = DEADLINE
    tick(app)
    assert app.notifier.messages == []


def test_decided_rows_get_no_deadline_alert(tmp_path):
    app = make_app(tmp_path)
    add_row(app, 100, status="CHALLENGED")
    app.outbox._now = DEADLINE
    tick(app)
    assert app.notifier.messages == []


def test_startup_refuses_bad_agreement(tmp_path):
    def app_for(n, urls):
        route = BUILTIN_ROUTES["arb-sepolia-to-sepolia-testnet"].model_copy(deep=True)
        route.inbox_chain.rpc_urls = urls
        return SimpleNamespace(route=route, settings=Settings(min_challenge_agreement=n))

    with pytest.raises(SystemExit, match="min_challenge_agreement"):
        startup_checks(app_for(0, ["http://a", "http://b"]))
    with pytest.raises(SystemExit, match="min_challenge_agreement"):
        startup_checks(app_for(3, ["http://a", "http://b"]))
    with pytest.raises(SystemExit, match="at least 2"):
        startup_checks(app_for(1, ["http://a"]))


def test_failing_row_does_not_block_later_rows(tmp_path):
    ch = FakeChallenger()
    app = make_app(tmp_path, challenger=ch)
    add_row(app, 100, status=SEEN)
    add_row(app, 101, status=SEEN)
    app.detector.reconcile_raises = {100}
    app.detector.fraud = {101}
    tick(app)
    assert app.detector.evaluated == [101]
    assert ch.challenged == [101]
    assert count(app, "CRITICAL", "epoch 100: processing failed") == 1
    tick(app)  # rate limited: once per epoch per hour
    assert count(app, "CRITICAL", "epoch 100: processing failed") == 1


def test_row_error_repeats_after_an_hour(tmp_path, monkeypatch):
    app = make_app(tmp_path)
    add_row(app, 100, status=SEEN)
    app.detector.reconcile_raises = {100}
    now = [10_000.0]
    monkeypatch.setattr(watcher.time, "time", lambda: now[0])
    tick(app)
    now[0] += 3601
    tick(app)
    assert count(app, "CRITICAL", "epoch 100: processing failed") == 2


def test_stop_request_ends_row_loop(tmp_path):
    app = make_app(tmp_path)
    add_row(app, 100, status=SEEN)
    add_row(app, 101, status=SEEN)
    app.stop.set()
    tick(app)
    assert app.detector.evaluated == []


def test_shutdown_countdown_thresholds(tmp_path):
    app = make_app(tmp_path)  # timeout_epochs = 100
    app.outbox.latest_verified = 10
    base = 10 * PERIOD

    def at(since):
        app.outbox._now = base + since * PERIOD
        tick(app)

    at(49)
    assert app.notifier.messages == []
    at(50)
    at(50)
    assert count(app, "WARNING", "50%") == 1
    at(75)
    at(80)
    assert count(app, "CRITICAL", "75%") == 1
    at(90)
    at(95)
    assert count(app, "CRITICAL", "90%") == 1
    assert len(app.notifier.messages) == 3
    first, second = app.notifier.messages[0][1], app.notifier.messages[1][1]
    assert "claim must be made and verified" in first
    # 50 of 100 epochs gone: 50 left, 50 * 7200 s = 4.2 days
    assert "50 of 100 epochs" in first and "50 epochs (~4.2 days) left" in first
    assert "75 of 100 epochs" in second and "25 epochs (~2.1 days) left" in second
    app.store.close()

    app2 = make_app(tmp_path)
    app2.outbox.latest_verified = 10
    app2.outbox._now = base + 95 * PERIOD
    tick(app2)
    assert app2.notifier.messages == []

    # an advance resets the thresholds
    app2.outbox.latest_verified = 20
    app2.outbox._now = 20 * PERIOD + 50 * PERIOD
    tick(app2)
    assert count(app2, "WARNING", "50%") == 1


def test_liveness_alarm_after_n_epochs_and_daily(tmp_path):
    app = make_app(tmp_path, settings=Settings(liveness_epochs=12))
    app.outbox.latest_verified = CLAIMED // PERIOD
    tick(app)  # first tick: liveness:start
    app.outbox._now = CLAIMED + 11 * PERIOD
    app.outbox.latest_verified = app.outbox._now // PERIOD
    tick(app)
    assert app.notifier.messages == []
    app.outbox._now = CLAIMED + 12 * PERIOD
    app.outbox.latest_verified = app.outbox._now // PERIOD
    tick(app)
    tick(app)
    assert count(app, "WARNING", "no claim for 12 epochs — quiet bridge") == 1
    app.outbox._now += 86_400
    app.outbox.latest_verified = app.outbox._now // PERIOD
    tick(app)
    assert count(app, "WARNING", "no claim for 12 epochs") == 2


def test_liveness_uses_newest_tracked_claim(tmp_path):
    app = make_app(tmp_path, settings=Settings(liveness_epochs=12))
    add_row(app, 5, status="HONEST", ts=CLAIMED + 100 * PERIOD)
    app.outbox._now = CLAIMED + 105 * PERIOD
    app.outbox.latest_verified = app.outbox._now // PERIOD
    tick(app)
    assert app.notifier.messages == []


def test_liveness_never_on_devnet(tmp_path):
    app = make_app(tmp_path, devnet=True, settings=Settings(liveness_epochs=12))
    tick(app)
    app.outbox._now = CLAIMED + 50 * PERIOD
    app.outbox.latest_verified = app.outbox._now // PERIOD
    tick(app)
    assert app.notifier.messages == []


# -- f6: deadline wording for a fraud row ---------------------------------------------------


def test_deadline_alert_words_a_fraud_row_as_fraud(tmp_path):
    app = make_app(tmp_path)
    note = "fraud: finalized root 0xbb differs from the claim; challenge not confirmed yet"
    add_row(app, 100, note=note)
    app.outbox._now = DEADLINE - 3000
    tick(app)
    msgs = [m for _, m in app.notifier.messages]
    text = f"FRAUD for epoch 100 not challenged yet: {note}; 3000 s left"
    assert msgs == [text, text]  # inside both windows: the 4 h and the 1 h page
    assert [l for l, _ in app.notifier.messages] == ["WARNING", "CRITICAL"]
    assert not any("still undecided" in m for m in msgs)


# -- V3-04: a fraud whose challenge keeps failing still gets the deadline pages -------------


def test_challenge_pending_row_gets_deadline_alerts_once_each(tmp_path):
    app = make_app(tmp_path)  # no challenger: the row just sits in CHALLENGE_PENDING
    note = "challenge attempt failed: insufficient funds for gas"
    add_row(app, 100, status=CHALLENGE_PENDING, note=note)
    tick(app)
    assert app.notifier.messages == []
    app.outbox._now = DEADLINE - 3 * 3600
    for _ in range(3):
        tick(app)
    text = f"FRAUD for epoch 100 not challenged yet (challenge pending): {note}; {3 * 3600} s left"
    assert app.notifier.messages == [("WARNING", text)]
    app.outbox._now = DEADLINE - 50 * 60
    for _ in range(3):
        tick(app)
    assert count(app, "WARNING", "FRAUD for epoch 100") == 1
    assert count(app, "CRITICAL", "FRAUD for epoch 100 not challenged yet (challenge pending)") == 1
    assert app.store.alert_sent("deadline:100:4h") is not None
    assert app.store.alert_sent("deadline:100:1h") is not None


def test_no_challenge_pending_deadline_alert_on_devnet(tmp_path):
    app = make_app(tmp_path, devnet=True)
    add_row(app, 100, status=CHALLENGE_PENDING, note="challenge attempt failed: x")
    app.outbox._now = DEADLINE - 50 * 60
    tick(app)
    assert app.notifier.messages == []


# -- C2: pages that repeat every tick are hourly ---------------------------------------------


def _fraud_app(tmp_path, challenger=None, monkeypatch=None):
    app = make_app(tmp_path, challenger=challenger)
    add_row(app, 100, status=SEEN)
    app.detector.fraud = {100}
    return app


def test_fraud_and_watch_only_pages_are_hourly_per_epoch(tmp_path, monkeypatch):
    app = _fraud_app(tmp_path)  # no challenger: watch-only
    now = [50_000.0]
    monkeypatch.setattr(watcher.time, "time", lambda: now[0])
    for _ in range(4):
        tick(app)
    assert count(app, "CRITICAL", "FRAUDULENT CLAIM epoch 100") == 1
    assert count(app, "CRITICAL", "watch-only mode: CANNOT challenge") == 1
    assert app.store.alert_sent("fraud:100") is not None
    assert app.store.alert_sent("watch-only:100") is not None
    now[0] += 3_601
    tick(app)
    assert count(app, "CRITICAL", "FRAUDULENT CLAIM epoch 100") == 2
    assert count(app, "CRITICAL", "watch-only mode: CANNOT challenge") == 2


def test_fraud_page_is_hourly_in_dry_run(tmp_path, params):
    outbox = FakeOutbox()
    notifier = FakeNotifier()
    app = _fraud_app(tmp_path)
    app.outbox = outbox
    outbox.claim_hashes[100] = _claim().hash()
    app.notifier = notifier
    app.challenger = Challenger(
        app.store, outbox, params, sender=None, notifier=notifier, weth=None,
        gas_reserve_wei=1, devnet=False, dry_run=True,
    )
    outbox._now = CLAIMED
    outbox.latest_verified = 10**9
    for _ in range(4):
        tick(app)
    assert count(app, "CRITICAL", "FRAUDULENT CLAIM epoch 100") == 1
    assert count(app, "CRITICAL", "DRY-RUN: would challenge epoch 100") == 1
    assert count(app, "CRITICAL", "watch-only") == 0


# -- G5/f12: a failing event scan does not silence the rest of the tick -----------------------


def test_failing_event_scan_still_processes_rows_and_deadlines(tmp_path, monkeypatch):
    c = ChainClient(
        ChainCfg(name="eth", chain_id=1, rpc_urls=["https://h1.example.org/v2/SCANSECRET12345"])
    )
    app = make_app(tmp_path)
    add_row(app, 100, status=SEEN)
    app.detector.sync_error = RuntimeError(
        "getLogs failed on https://h1.example.org/v2/SCANSECRET12345"
    )
    app.outbox._now = DEADLINE - 3000
    now = [70_000.0]
    monkeypatch.setattr(watcher.time, "time", lambda: now[0])
    for _ in range(3):
        tick(app)
    assert app.detector.evaluated == [100, 100, 100]  # the tracked row was evaluated
    assert count(app, "WARNING", "epoch 100 is still undecided") == 1  # deadline alerts ran
    assert count(app, "CRITICAL", "epoch 100 is still undecided") == 1
    failing = [m for l, m in app.notifier.messages if m.startswith("event scan failing: ")]
    assert len(failing) == 1  # once per hour
    assert "SCANSECRET12345" not in failing[0] and c.labels[0] in failing[0]
    now[0] += 3_601
    tick(app)
    assert count(app, "CRITICAL", "event scan failing") == 2
    assert app.store.alert_sent("sync-failed") is not None


def test_failing_event_scan_still_runs_the_resolver_and_monitors(tmp_path):
    app = make_app(tmp_path)
    app.detector.sync_error = RuntimeError("boom")
    app.outbox.latest_verified = 10
    app.outbox._now = 10 * PERIOD + 50 * PERIOD
    ticked = []
    app.resolver = SimpleNamespace(
        bridge_shutdown=lambda: False, tick=lambda rows: ticked.append(rows)
    )
    tick(app)
    assert count(app, "WARNING", "bridge shutdown countdown at 50%") == 1
    assert ticked == [[]]  # no active rows, but the resolver stage was reached


def test_failing_event_scan_still_runs_the_liveness_alarm(tmp_path):
    app = make_app(tmp_path, settings=Settings(liveness_epochs=12))
    app.detector.sync_error = RuntimeError("boom")
    add_row(app, 5, status="HONEST", ts=CLAIMED)  # last claim seen 12 epochs ago
    app.outbox._now = CLAIMED + 12 * PERIOD
    app.outbox.latest_verified = app.outbox._now // PERIOD
    tick(app)
    assert count(app, "CRITICAL", "event scan failing") == 1
    assert count(app, "WARNING", "no claim for 12 epochs — quiet bridge") == 1
    assert app.store.alert_sent("liveness:no-claim") is not None
