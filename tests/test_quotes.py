import json
from pathlib import Path

import quotes


def test_heuristic_detects_tx_origin_and_line(tmp_path: Path):
    source = tmp_path / "Vault.sol"
    source.write_text(
        "pragma solidity ^0.8.20;\ncontract Vault {\n"
        "function withdraw() external { require(tx.origin == owner); }\n}\n",
        encoding="utf-8",
    )
    findings = quotes.heuristic_scan([source])
    matches = [f for f in findings if f["id"] == "QH001"]
    assert len(matches) == 1
    assert matches[0]["line"] == 3
    assert matches[0]["confidence"] == "low"


def test_comments_do_not_trigger(tmp_path: Path):
    source = tmp_path / "Comment.sol"
    source.write_text("// tx.origin should not trigger\ncontract Safe {}\n", encoding="utf-8")
    assert quotes.heuristic_scan([source]) == []


def test_cli_writes_report(tmp_path: Path):
    source = tmp_path / "Test.sol"
    source.write_text("pragma solidity ^0.8.20; contract Test { function f() external view returns(uint) { return block.timestamp; } }", encoding="utf-8")
    output = tmp_path / "report.json"
    assert quotes.main(["--target", str(source), "--out", str(output), "--heuristics-only"]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["tool"] == "QUOTES"
    assert report["solidity_files_scanned"] == 1
    assert report["summary"]["heuristic_finding_count"] == 1


def test_rejects_missing_target(tmp_path: Path):
    assert quotes.main(["--target", str(tmp_path / "missing.sol"), "--out", str(tmp_path / "x.json")]) == 1
