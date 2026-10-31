import json

from history import record_scan


def make_report(target="/project/Contract.sol"):
    return {
        "tool": "QUOTES",
        "version": "0.4.0",
        "generated_at": "2026-10-31T00:00:00+00:00",
        "target": target,
        "source": None,
        "heuristic_findings": [{
            "id": "QH001",
            "title": "Use of tx.origin for authorization",
            "severity": "medium",
            "confidence": "low",
            "file": target,
            "line": 10,
            "source": "heuristic",
            "status": "needs_manual_review",
        }],
        "bytecode_analysis": None,
    }


def test_history_marks_first_occurrence_new_and_second_repeat(tmp_path):
    database = tmp_path / "history.sqlite3"
    first = make_report()
    first_result = record_scan(first, database)
    second = make_report()
    second["generated_at"] = "2026-10-31T00:05:00+00:00"
    second_result = record_scan(second, database)

    assert first_result["new_findings"] == 1
    assert first_result["repeat_findings"] == 0
    assert first["heuristic_findings"][0]["history_status"] == "new"
    assert second_result["new_findings"] == 0
    assert second_result["repeat_findings"] == 1
    assert second["heuristic_findings"][0]["history_status"] == "repeat"
    assert second_result["scan_id"] > first_result["scan_id"]


def test_history_deduplication_is_scoped_to_target(tmp_path):
    database = tmp_path / "history.sqlite3"
    record_scan(make_report("/project/A.sol"), database)
    other = make_report("/project/B.sol")
    result = record_scan(other, database)
    assert result["new_findings"] == 1
    assert result["repeat_findings"] == 0


def test_history_marks_bytecode_indicators(tmp_path):
    report = make_report()
    report["heuristic_findings"] = []
    report["bytecode_analysis"] = {"indicators": [{
        "id": "QB002", "title": "DELEGATECALL opcode present",
        "opcode": "DELEGATECALL", "count": 1, "confidence": "low",
    }]}
    result = record_scan(report, tmp_path / "history.sqlite3")
    assert result["finding_count"] == 1
    assert report["bytecode_analysis"]["indicators"][0]["history_status"] == "new"
