import json
from pathlib import Path

import quotes
from source_retrieval import SourceRetrievalError


def test_address_scan_falls_back_to_bytecode_when_source_is_unverified(monkeypatch, tmp_path):
    address = "0x" + "1" * 40

    def no_verified_source(*args, **kwargs):
        raise SourceRetrievalError("Explorer API rejected the request: Contract source code not verified")

    def fake_bytecode(address_arg, chain_id, rpc_url=None, timeout=30):
        assert address_arg == address
        assert chain_id == 8453
        return {
            "provider": "json-rpc",
            "chain_id": 8453,
            "address": address,
            "bytecode": "0x32f442f1ff",
            "runtime_bytecode_bytes": 5,
            "retrieval": "read_only",
        }

    monkeypatch.setattr(quotes, "fetch_verified_source", no_verified_source)
    monkeypatch.setattr(quotes, "fetch_runtime_bytecode", fake_bytecode)
    output = tmp_path / "bytecode-report.json"

    result = quotes.main([
        "--address", address,
        "--chain-id", "8453",
        "--out", str(output),
        "--heuristics-only",
    ])
    report = json.loads(output.read_text(encoding="utf-8"))

    assert result == 0
    assert report["solidity_files_scanned"] == 0
    assert report["source"]["verified_source"] is False
    assert report["analysis"]["bytecode"] == "completed"
    assert report["summary"]["bytecode_indicator_count"] == 5
    assert report["bytecode"]["runtime_bytecode_bytes"] == 5


def test_local_source_scan_remains_supported(tmp_path):
    source = tmp_path / "Local.sol"
    source.write_text(
        "pragma solidity ^0.8.20; contract Local { function nowish() external view returns(uint) { return block.timestamp; } }",
        encoding="utf-8",
    )
    output = tmp_path / "local-report.json"

    assert quotes.main([
        "--target", str(source), "--out", str(output), "--heuristics-only"
    ]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["solidity_files_scanned"] == 1
    assert report["summary"]["heuristic_finding_count"] == 1
    assert report["bytecode_analysis"] is None
