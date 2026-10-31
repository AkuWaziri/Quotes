import json
from pathlib import Path

import quotes


def test_cli_can_write_html_and_history_without_changing_default_scan(tmp_path):
    source = tmp_path / "Contract.sol"
    source.write_text(
        "pragma solidity ^0.8.20; contract Contract { function t() external view returns(uint) { return block.timestamp; } }",
        encoding="utf-8",
    )
    database = tmp_path / "history.sqlite3"
    html_path = tmp_path / "report.html"
    first_json = tmp_path / "first.json"
    second_json = tmp_path / "second.json"

    assert quotes.main([
        "--target", str(source), "--out", str(first_json),
        "--history-db", str(database), "--html-out", str(html_path),
        "--heuristics-only",
    ]) == 0
    first = json.loads(first_json.read_text(encoding="utf-8"))
    assert first["history"]["new_findings"] == 1
    assert first["heuristic_findings"][0]["history_status"] == "new"
    assert "QUOTES scan report" in html_path.read_text(encoding="utf-8")

    assert quotes.main([
        "--target", str(source), "--out", str(second_json),
        "--history-db", str(database), "--heuristics-only",
    ]) == 0
    second = json.loads(second_json.read_text(encoding="utf-8"))
    assert second["history"]["repeat_findings"] == 1
    assert second["heuristic_findings"][0]["history_status"] == "repeat"


def test_default_scan_does_not_create_history_or_html(tmp_path):
    source = tmp_path / "Contract.sol"
    source.write_text("pragma solidity ^0.8.20; contract Contract {}", encoding="utf-8")
    output = tmp_path / "report.json"
    assert quotes.main(["--target", str(source), "--out", str(output), "--heuristics-only"]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert "history" not in report
    assert not (tmp_path / "quotes-history.sqlite3").exists()
