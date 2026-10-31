from pathlib import Path

import quotes


FIXTURES = Path(__file__).parent / "fixtures"


def test_deliberately_vulnerable_fixture_triggers_expected_heuristics():
    source = FIXTURES / "vulnerable" / "HeuristicFixture.sol"
    findings = quotes.heuristic_scan([source])
    found_ids = {finding["id"] for finding in findings}

    assert {"QH001", "QH002", "QH003", "QH004", "QH005"} <= found_ids
    assert all(finding["confidence"] == "low" for finding in findings)
    assert all(finding["status"] == "needs_manual_review" for finding in findings)


def test_safe_control_fixture_has_no_heuristic_findings():
    source = FIXTURES / "safe" / "CommentOnlyFixture.sol"
    assert quotes.heuristic_scan([source]) == []
