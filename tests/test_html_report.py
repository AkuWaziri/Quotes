from html_report import render_html_report


def test_html_report_escapes_untrusted_finding_text():
    report = {
        "version": "0.4.0",
        "generated_at": "today",
        "target": "<script>alert(1)</script>",
        "summary": {"heuristic_finding_count": 1, "bytecode_indicator_count": 0, "high": 0},
        "heuristic_findings": [{
            "id": "QH001",
            "title": "<img src=x onerror=alert(1)>",
            "description": "<script>bad()</script>",
            "severity": "medium",
            "file": "Contract.sol",
            "line": 4,
        }],
        "bytecode_analysis": None,
    }
    output = render_html_report(report)
    assert "<script>alert(1)</script>" not in output
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in output
    assert "&lt;img src=x onerror=alert(1)&gt;" in output
    assert "<script>bad()</script>" not in output


def test_html_report_handles_bytecode_only_report():
    output = render_html_report({
        "version": "0.4.0",
        "target": None,
        "source": {"address": "0x123"},
        "summary": {"heuristic_finding_count": 0, "bytecode_indicator_count": 1, "high": 0},
        "heuristic_findings": [],
        "bytecode_analysis": {"indicators": [{
            "id": "QB002", "title": "DELEGATECALL opcode present",
            "opcode": "DELEGATECALL", "count": 1,
        }]},
    })
    assert "DELEGATECALL opcode present" in output
    assert "Bytecode indicators" in output
