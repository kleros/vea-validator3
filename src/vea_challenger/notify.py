"""Webhook notifications. Fire-and-forget: alerting must never stall the loop."""

from __future__ import annotations

import json
import logging
import threading
import urllib.request

from .chain import redact, register_endpoint

log = logging.getLogger(__name__)

INFO = "INFO"
WARNING = "WARNING"
CRITICAL = "CRITICAL"


class Notifier:
    """POSTs ``{"text": "..."}`` JSON (Slack/Discord/Mattermost compatible)."""

    def __init__(self, webhook_url: str | None, route_name: str):
        self.webhook_url = webhook_url
        self.route_name = route_name
        if webhook_url:
            # The URL carries the webhook token: redact() (and the log filter) hide it.
            register_endpoint(webhook_url, "<webhook>", hide_host=True)

    def send(self, level: str, message: str) -> None:
        message = redact(message)
        line = f"[vea-challenger:{self.route_name}] {level}: {message}"
        if level == CRITICAL:
            log.critical("%s", message)
        elif level == WARNING:
            log.warning("%s", message)
        else:
            log.info("%s", message)
        if not self.webhook_url:
            return
        threading.Thread(
            target=self._post, args=(line,), daemon=True, name="notify"
        ).start()

    def _post(self, line: str) -> None:
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps({"text": line, "content": line}).encode(),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "webhook delivery failed: %s: %s", type(exc).__name__, redact(str(exc))
            )
