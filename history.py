"""Optional SQLite scan history and cross-run finding deduplication."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


class HistoryError(RuntimeError):
    """Raised when scan history cannot be stored safely."""


def _target_key(report: dict[str, Any]) -> str:
    for source in (report.get("source"), report.get("bytecode")):
        if isinstance(source, dict) and source.get("address"):
            return f"{source.get('chain_id', 'unknown')}:{str(source['address']).lower()}"
    return str(report.get("target") or "unknown-target")


def _all_findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for finding in report.get("heuristic_findings", []):
        if isinstance(finding, dict):
            finding.setdefault("finding_source", "source")
            findings.append(finding)
    bytecode = report.get("bytecode_analysis")
    if isinstance(bytecode, dict):
        for finding in bytecode.get("indicators", []):
            if isinstance(finding, dict):
                finding.setdefault("finding_source", "bytecode")
                findings.append(finding)
    return findings


def _fingerprint(target_key: str, finding: dict[str, Any]) -> str:
    identity = {
        "target": target_key,
        "id": finding.get("id"),
        "finding_source": finding.get("finding_source", finding.get("source")),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "opcode": finding.get("opcode"),
        "title": finding.get("title"),
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def record_scan(report: dict[str, Any], database_path: str | Path) -> dict[str, Any]:
    """Persist a report and mark findings as new or repeats for this target."""
    path = Path(database_path).expanduser().resolve()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path, timeout=10) as db:
            db.execute("PRAGMA foreign_keys = ON")
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scanned_at TEXT NOT NULL,
                    target_key TEXT NOT NULL,
                    tool_version TEXT,
                    report_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target_key);
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    fingerprint TEXT NOT NULL,
                    finding_id TEXT,
                    title TEXT,
                    severity TEXT,
                    location TEXT,
                    finding_source TEXT,
                    history_status TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
                """
            )
            target_key = _target_key(report)
            prior = {
                row[0]
                for row in db.execute(
                    "SELECT DISTINCT f.fingerprint FROM findings f "
                    "JOIN scans s ON s.id = f.scan_id WHERE s.target_key = ?",
                    (target_key,),
                ).fetchall()
            }
            findings = _all_findings(report)
            seen_this_scan: set[str] = set()
            new_count = 0
            repeat_count = 0
            pending: list[tuple[str, dict[str, Any], str]] = []
            for finding in findings:
                fingerprint = _fingerprint(target_key, finding)
                is_repeat = fingerprint in prior or fingerprint in seen_this_scan
                status = "repeat" if is_repeat else "new"
                finding["history_status"] = status
                if is_repeat:
                    repeat_count += 1
                else:
                    new_count += 1
                seen_this_scan.add(fingerprint)
                pending.append((fingerprint, finding, status))

            cursor = db.execute(
                "INSERT INTO scans (scanned_at, target_key, tool_version, report_json) VALUES (?, ?, ?, ?)",
                (
                    str(report.get("generated_at") or ""),
                    target_key,
                    str(report.get("version") or ""),
                    "{}",
                ),
            )
            scan_id = int(cursor.lastrowid)
            for fingerprint, finding, status in pending:
                location = finding.get("file")
                if location is None and finding.get("line") is not None:
                    location = f"line {finding['line']}"
                db.execute(
                    "INSERT INTO findings "
                    "(scan_id, fingerprint, finding_id, title, severity, location, finding_source, history_status, details_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        scan_id,
                        fingerprint,
                        str(finding.get("id") or ""),
                        str(finding.get("title") or ""),
                        str(finding.get("severity") or ""),
                        str(location or finding.get("opcode") or ""),
                        str(finding.get("finding_source") or finding.get("source") or ""),
                        status,
                        json.dumps(finding, sort_keys=True),
                    ),
                )
            summary = {
                "database": str(path),
                "scan_id": scan_id,
                "target_key": target_key,
                "finding_count": len(findings),
                "new_findings": new_count,
                "repeat_findings": repeat_count,
            }
            report["history"] = summary
            db.execute(
                "UPDATE scans SET report_json = ? WHERE id = ?",
                (json.dumps(report, sort_keys=True), scan_id),
            )
            return summary
    except (OSError, sqlite3.Error, TypeError, ValueError) as exc:
        raise HistoryError(f"Could not save scan history: {exc}") from exc
