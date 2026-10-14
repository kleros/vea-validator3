"""Notifier redaction (PRD 3.1)."""

import logging

from vea_challenger.chain import ChainClient
from vea_challenger.config import ChainCfg
from vea_challenger.notify import CRITICAL, Notifier

URL = "https://arb-sepolia.g.alchemy.com/v2/SECRETPATHKEY123"


def test_message_is_redacted_when_logged_and_posted(caplog):
    client = ChainClient(ChainCfg(name="arbitrum-sepolia", chain_id=1, rpc_urls=[URL]))
    n = Notifier(None, "r")
    posted = []
    n.webhook_url = "http://hook.invalid"
    n._post = posted.append  # capture the line that would be POSTed
    import vea_challenger.notify as mod

    class Inline:
        def __init__(self, target, args, **kw):
            self.target, self.args = target, args

        def start(self):
            self.target(*self.args)

    orig = mod.threading.Thread
    mod.threading.Thread = Inline
    try:
        with caplog.at_level(logging.INFO):
            n.send(CRITICAL, f"provider failed at {URL}")
    finally:
        mod.threading.Thread = orig
    assert posted and "SECRETPATHKEY123" not in posted[0]
    assert client.labels[0] in posted[0]
    assert "SECRETPATHKEY123" not in caplog.text
    assert client.labels[0] in caplog.text


HOOK = "https://hooks.slack.com/services/T0AAAA/B0BBBB/WEBHOOKTOKEN987"


def test_failed_webhook_delivery_log_hides_url_and_token(caplog, monkeypatch):
    import urllib.error

    import vea_challenger.notify as mod

    def boom(req, timeout):
        raise urllib.error.URLError(f"cannot reach {req.full_url}")

    monkeypatch.setattr(mod.urllib.request, "urlopen", boom)
    n = Notifier(HOOK, "r")
    with caplog.at_level(logging.WARNING):
        n._post("line")
    assert "webhook delivery failed" in caplog.text
    assert "WEBHOOKTOKEN987" not in caplog.text
    assert "hooks.slack.com" not in caplog.text
    assert "URLError" in caplog.text
