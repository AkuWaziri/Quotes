import json
from pathlib import Path

import quotes


def test_cli_notification_is_opt_in_and_status_is_in_report(monkeypatch, tmp_path):
    source = tmp_path / "Contract.sol"
    source.write_text("pragma solidity ^0.8.20; contract Contract {}", encoding="utf-8")
    output = tmp_path / "report.json"
    called = {}

    def fake_send(report, webhook_url):
        called["url"] = webhook_url
        called["finding_count"] = report["summary"]["heuristic_finding_count"]
        return {"status": "sent", "payload_type": "summary_only"}

    monkeypatch.setattr(quotes, "send_notification", fake_send)
    result = quotes.main([
        "--target", str(source), "--out", str(output), "--heuristics-only",
        "--notify", "--webhook-url", "https://hooks.example.test/secret",
    ])
    report = json.loads(output.read_text(encoding="utf-8"))

    assert result == 0
    assert called["url"] == "https://hooks.example.test/secret"
    assert report["notification"]["status"] == "sent"
    assert report["notification"]["payload_type"] == "summary_only"
