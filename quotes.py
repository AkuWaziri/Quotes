#!/usr/bin/env python3
"""QUOTES defensive EVM smart-contract scanner.

Slither is the primary static-analysis engine when installed. Built-in source
pattern checks are intentionally conservative and report leads, not confirmed
vulnerabilities.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from source_retrieval import SourceRetrievalError, fetch_verified_source

VERSION = "0.2.0"
SOLIDITY_SUFFIXES = {".sol"}

HEURISTICS: list[dict[str, Any]] = [
    {
        "id": "QH001",
        "title": "Use of tx.origin for authorization",
        "pattern": re.compile(r"\btx\s*\.\s*origin\b"),
        "severity": "medium",
        "confidence": "low",
        "description": "tx.origin appears in the source. If used for authorization, a malicious intermediary contract may be able to trick a user into triggering privileged behavior.",
        "recommendation": "Review the surrounding condition. Prefer explicit role checks or msg.sender-based authorization where appropriate.",
    },
    {
        "id": "QH002",
        "title": "Low-level call requires return-value review",
        "pattern": re.compile(r"\.\s*call\s*(?:\{[^}]*\})?\s*\("),
        "severity": "medium",
        "confidence": "low",
        "description": "A low-level call appears in the source. Its success result, target, calldata, and reentrancy implications require review.",
        "recommendation": "Check the returned success flag, validate the destination, and apply checks-effects-interactions or a suitable reentrancy guard when needed.",
    },
    {
        "id": "QH003",
        "title": "delegatecall requires target and storage review",
        "pattern": re.compile(r"\.\s*delegatecall\s*(?:\{[^}]*\})?\s*\("),
        "severity": "high",
        "confidence": "low",
        "description": "delegatecall appears in the source. An unsafe or user-controlled target can execute code in the caller's storage context.",
        "recommendation": "Ensure the target is trusted and constrained, review storage-layout compatibility, and protect upgrade/admin paths.",
    },
    {
        "id": "QH004",
        "title": "Timestamp-dependent logic",
        "pattern": re.compile(r"\bblock\s*\.\s*timestamp\b"),
        "severity": "low",
        "confidence": "low",
        "description": "The contract reads block.timestamp. This can be appropriate, but exact-time assumptions or timestamp-based randomness may be unsafe.",
        "recommendation": "Review whether small timestamp variation can affect value, fairness, deadlines, or randomness.",
    },
    {
        "id": "QH005",
        "title": "Contract destruction primitive requires review",
        "pattern": re.compile(r"\bselfdestruct\s*\("),
        "severity": "high",
        "confidence": "low",
        "description": "selfdestruct appears in the source. Its behavior depends on compiler and chain semantics and may create lifecycle or authorization risks.",
        "recommendation": "Verify the intended lifecycle behavior for the target chain and compiler; ensure any reachable path is correctly authorized.",
    },
]


def solidity_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix.lower() in SOLIDITY_SUFFIXES else []
    excluded = {".git", "node_modules", "lib", "vendor", ".venv", "venv", "out", "cache", "quotes-downloads"}
    return sorted(p for p in target.rglob("*.sol") if not any(part in excluded for part in p.parts))


def heuristic_scan(files: list[Path]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for file in files:
        try:
            source = file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # Strip comments to reduce trivial comment-only matches. This is not a Solidity parser.
        cleaned = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), source, flags=re.S)
        cleaned = re.sub(r"//[^\n]*", "", cleaned)
        for rule in HEURISTICS:
            for match in rule["pattern"].finditer(cleaned):
                line = cleaned.count("\n", 0, match.start()) + 1
                findings.append({
                    "id": rule["id"],
                    "source": "heuristic",
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "file": str(file),
                    "line": line,
                    "description": rule["description"],
                    "recommendation": rule["recommendation"],
                    "status": "needs_manual_review",
                })
    return findings


def run_slither(target: Path, report_path: Path) -> dict[str, Any]:
    executable = shutil.which("slither")
    if not executable:
        return {"available": False, "status": "not_installed", "message": "Slither was not found on PATH."}
    command = [executable, str(target), "--json", str(report_path)]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=300, check=False)
    except subprocess.TimeoutExpired:
        return {"available": True, "status": "timeout", "message": "Slither exceeded the 300-second timeout."}
    except OSError as exc:
        return {"available": True, "status": "error", "message": str(exc)}
    status: dict[str, Any] = {
        "available": True,
        "status": "completed" if report_path.exists() else "error",
        "return_code": proc.returncode,
        "stderr_excerpt": (proc.stderr or "")[-3000:],
        "stdout_excerpt": (proc.stdout or "")[-1500:],
    }
    if report_path.exists():
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
            results = data.get("results", {}) if isinstance(data, dict) else {}
            status["findings"] = results.get("detectors", []) if isinstance(results, dict) else []
        except (OSError, json.JSONDecodeError) as exc:
            status["parse_error"] = str(exc)
    return status


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="QUOTES smart-contract security scanner")
    parser.add_argument("--target", help="Local Solidity file or Hardhat/Foundry project directory")
    parser.add_argument("--address", help="Retrieve verified contract source from Etherscan API V2")
    parser.add_argument("--chain-id", type=int, help="EVM chain ID for --address (for example, 1 for Ethereum)")
    parser.add_argument("--source-dir", default="quotes-downloads", help="Directory for retrieved verified source")
    parser.add_argument("--api-key", default=os.getenv("ETHERSCAN_API_KEY"), help="Etherscan API key; defaults to ETHERSCAN_API_KEY")
    parser.add_argument("--out", default="quotes-report.json", help="JSON report path (default: quotes-report.json)")
    parser.add_argument("--heuristics-only", action="store_true", help="Skip Slither and run built-in pattern checks only")
    args = parser.parse_args(argv)

    if bool(args.address) != (args.chain_id is not None):
        parser.error("--address and --chain-id must be supplied together")
    if args.address and args.target:
        parser.error("choose either --target or --address, not both")
    if not args.address and not args.target:
        parser.error("provide --target for local scanning or --address with --chain-id for explorer retrieval")

    output = Path(args.out).expanduser().resolve()
    source_metadata: dict[str, Any] | None = None
    if args.address:
        try:
            source_metadata = fetch_verified_source(
                args.address, args.chain_id, args.source_dir, api_key=args.api_key
            )
        except SourceRetrievalError as exc:
            print(f"Error retrieving verified source: {exc}", file=sys.stderr)
            return 1
        target = Path(args.source_dir).expanduser().resolve()
    else:
        target = Path(args.target).expanduser().resolve()

    if not target.exists():
        print(f"Error: target does not exist: {target}", file=sys.stderr)
        return 1
    if not (target.is_file() or target.is_dir()):
        print("Error: target must be a file or directory", file=sys.stderr)
        return 1
    files = solidity_files(target)
    if not files:
        print("Error: no Solidity (.sol) files found in target", file=sys.stderr)
        return 1

    findings = heuristic_scan(files)
    slither_status: dict[str, Any] = {"available": False, "status": "skipped"}
    if not args.heuristics_only:
        slither_report = output.with_suffix(".slither-raw.json")
        slither_status = run_slither(target, slither_report)
        slither_report.unlink(missing_ok=True)

    report = {
        "tool": "QUOTES",
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": str(target),
        "source": source_metadata,
        "solidity_files_scanned": len(files),
        "analysis": {
            "slither": slither_status,
            "heuristics": "completed",
            "limitations": [
                "Pattern matches are leads for manual review, not confirmed vulnerabilities.",
                "This version does not run bytecode analysis, symbolic execution, fuzzing, fork simulation, or exploit validation.",
                "No findings does not mean a contract is secure.",
            ],
        },
        "heuristic_findings": findings,
        "summary": {
            "heuristic_finding_count": len(findings),
            "high": sum(f["severity"] == "high" for f in findings),
            "medium": sum(f["severity"] == "medium" for f in findings),
            "low": sum(f["severity"] == "low" for f in findings),
            "slither_status": slither_status.get("status"),
        },
    }
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    except OSError as exc:
        print(f"Error writing report: {exc}", file=sys.stderr)
        return 1

    print(f"QUOTES {VERSION}: scanned {len(files)} Solidity file(s)")
    print(f"Heuristic leads: {len(findings)}")
    print(f"Slither: {slither_status.get('status')}")
    print(f"Report: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
