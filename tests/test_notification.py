import json
from io import BytesIO

import pytest

import notification


def test_webhook_sends_summary_without_source_or_bytecode(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return BytesIO(b"ok")

    monkeypatch.setattr(notification, "urlopen", fake_urlopen)
    report = {
        "version": "0.4.0",
        "target": "/private/project/Secret.sol",
        "heuristic_findings": [{"description": "secret source content"}],
        "bytecode_analysis": {"bytecode": "0xdeadbeef"},
        "summary": {
            "heuristic_finding_count": 2,
            "bytecode_indicator_count": 1,
            "high": 1,
        },
        "solidity_files_scanned": 3,
        "history": {"new_findings": 1, "repeat_findings": 1},
    }

    result = notification.send_notification(report, "https://hooks.example.test/abc")

    assert result["status"] == "sent"
    assert captured["timeout"] == 10
    assert "QUOTES 0.4.0 scan completed." in captured["payload"]["text"]
    assert "private/project" not in json.dumps(captured["payload"])
    assert "secret source content" not in json.dumps(captured["payload"])
    assert "deadbeef" not in json.dumps(captured["payload"])


@pytest.mark.parametrize("url", [
    "http://hooks.example.test/abc",
    "file:///tmp/webhook",
    "https://user:password@hooks.example.test/abc",
])
def test_webhook_rejects_unsafe_urls(url):
    with pytest.raises(notification.NotificationError):
        notification.send_notification({}, url)


def test_webhook_reports_http_errors(monkeypatch):
    from urllib.error import HTTPError

    def fake_urlopen(request, timeout):
        raise HTTPError(request.full_url, 503, "unavailable", {}, None)

    monkeypatch.setattr(notification, "urlopen", fake_urlopen)
    with pytest.raises(notification.NotificationError, match="503"):
        notification.send_notification({}, "https://hooks.example.test/abc")
