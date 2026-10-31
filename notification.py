"""Opt-in webhook notifications containing scan summaries only."""
from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


class NotificationError(RuntimeError):
    """Raised when an opted-in webhook notification cannot be delivered."""


def build_notification_payload(report: dict[str, Any]) -> dict[str, str]:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    history = report.get("history") if isinstance(report.get("history"), dict) else {}
    lines = [
        f"QUOTES {report.get('version', '')} scan completed.",
        f"Solidity files scanned: {summary.get('solidity_files_scanned', report.get('solidity_files_scanned', 0))}",
        f"Source heuristic leads: {summary.get('heuristic_finding_count', 0)}",
        f"Bytecode indicators: {summary.get('bytecode_indicator_count', 0)}",
        f"High-severity source leads: {summary.get('high', 0)}",
    ]
    if history:
        lines.append(
            f"History: {history.get('new_findings', 0)} new, "
            f"{history.get('repeat_findings', 0)} repeated"
        )
    message = "\n".join(lines)
    # Both keys allow common Slack and Discord incoming webhooks to consume
    # the summary; no source code, bytecode, secrets, or full report is sent.
    return {"text": message, "content": message}


def send_notification(
    report: dict[str, Any],
    webhook_url: str,
    timeout: int = 10,
) -> dict[str, Any]:
    """Send a summary-only notification to an explicitly configured HTTPS webhook."""
    parsed = urlsplit(webhook_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise NotificationError("Webhook URL must be HTTPS and must not embed username/password credentials.")
    payload = json.dumps(build_notification_payload(report)).encode("utf-8")
    request = Request(
        webhook_url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "QUOTES-Security-Scanner/0.4",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            if not 200 <= status < 300:
                raise NotificationError(f"Webhook returned HTTP status {status}.")
    except NotificationError:
        raise
    except HTTPError as exc:
        raise NotificationError(f"Webhook returned HTTP status {exc.code}.") from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise NotificationError(f"Webhook request failed: {exc}") from exc
    return {"status": "sent", "http_status": status, "payload_type": "summary_only"}
