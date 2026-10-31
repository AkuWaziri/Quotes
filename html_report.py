"""Generate a self-contained, escaped HTML view of a QUOTES JSON report."""
from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def render_html_report(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    bytecode = report.get("bytecode_analysis") if isinstance(report.get("bytecode_analysis"), dict) else {}
    source_findings = report.get("heuristic_findings") if isinstance(report.get("heuristic_findings"), list) else []
    bytecode_findings = bytecode.get("indicators") if isinstance(bytecode.get("indicators"), list) else []
    findings = [
        ("Source", item) for item in source_findings if isinstance(item, dict)
    ] + [
        ("Bytecode", item) for item in bytecode_findings if isinstance(item, dict)
    ]

    rows = []
    for category, finding in findings:
        values = [
            category,
            finding.get("id", ""),
            finding.get("title", ""),
            finding.get("severity", finding.get("confidence", "review")),
            finding.get("file", finding.get("opcode", "")),
            finding.get("line", ""),
            finding.get("history_status", "not-recorded"),
            finding.get("description", ""),
        ]
        cells = "".join(f"<td>{html.escape(str(value))}</td>" for value in values)
        rows.append(f"<tr>{cells}</tr>")
    if not rows:
        rows.append('<tr><td colspan="8">No findings were recorded for this scan.</td></tr>')

    target = report.get("target") or (
        report.get("source", {}).get("address")
        if isinstance(report.get("source"), dict) else "On-chain bytecode"
    ) or "Not specified"
    generated = report.get("generated_at", "")
    history = report.get("history") if isinstance(report.get("history"), dict) else {}
    history_line = (
        f"Scan #{history.get('scan_id')} · {history.get('new_findings', 0)} new · "
        f"{history.get('repeat_findings', 0)} repeat findings"
        if history else "History was not enabled for this scan."
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>QUOTES scan report</title>
<style>
:root {{ color-scheme: light; font-family: Inter, system-ui, -apple-system, sans-serif; }}
body {{ margin: 0; background: #f4f7fb; color: #182230; }}
main {{ max-width: 1180px; margin: 0 auto; padding: 28px 18px 60px; }}
header, .panel {{ background: #fff; border: 1px solid #dfe6ef; border-radius: 14px; padding: 22px; margin-bottom: 16px; }}
h1 {{ margin: 0 0 6px; font-size: 1.7rem; }} h2 {{ margin-top: 0; font-size: 1.1rem; }}
.muted {{ color: #526176; overflow-wrap: anywhere; }}
.cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(145px, 1fr)); gap: 12px; margin-bottom: 16px; }}
.card {{ background: #fff; border: 1px solid #dfe6ef; border-radius: 12px; padding: 16px; }}
.card strong {{ display: block; font-size: 1.6rem; margin-top: 6px; }}
.table-wrap {{ overflow-x: auto; }} table {{ border-collapse: collapse; width: 100%; min-width: 820px; }}
th, td {{ text-align: left; vertical-align: top; border-bottom: 1px solid #e6ebf2; padding: 11px; font-size: .9rem; }}
th {{ background: #f7f9fc; }} .notice {{ background: #fff8e6; border-color: #f0dca2; }}
</style>
</head>
<body><main>
<header><h1>QUOTES scan report</h1><div class="muted">Version {html.escape(str(report.get('version', '')))} · {html.escape(str(generated))}</div><p class="muted">Target: {html.escape(str(target))}</p><p class="muted">{html.escape(history_line)}</p></header>
<section class="cards">
<div class="card">Source files<strong>{html.escape(str(report.get('solidity_files_scanned', 0)))}</strong></div>
<div class="card">Source leads<strong>{html.escape(str(summary.get('heuristic_finding_count', 0)))}</strong></div>
<div class="card">Bytecode indicators<strong>{html.escape(str(summary.get('bytecode_indicator_count', 0)))}</strong></div>
<div class="card">High severity source leads<strong>{html.escape(str(summary.get('high', 0)))}</strong></div>
</section>
<section class="panel"><h2>Findings</h2><div class="table-wrap"><table>
<thead><tr><th>Type</th><th>ID</th><th>Finding</th><th>Severity / confidence</th><th>Location / opcode</th><th>Line</th><th>History</th><th>Details</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div></section>
<section class="panel notice"><h2>Important limitation</h2><p>QUOTES is an early-stage scanner, not an audit. Source and opcode indicators are review leads; they do not prove exploitability, reachability, or safety. Review the JSON report and validate findings with appropriate tools.</p></section>
</main></body></html>"""


def write_html_report(report: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html_report(report), encoding="utf-8")
    return path
