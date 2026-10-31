import json
from pathlib import Path

import pytest

import source_retrieval as source


def test_extracts_plain_single_file_source():
    files = source.extract_source_files("pragma solidity ^0.8.20; contract Safe {}", "Safe")
    assert files == {"Safe.sol": "pragma solidity ^0.8.20; contract Safe {}"}


def test_extracts_standard_json_multiple_files():
    payload = {
        "language": "Solidity",
        "sources": {
            "contracts/Vault.sol": {"content": "contract Vault {}"},
            "contracts/Token.sol": {"content": "contract Token {}"},
        },
    }
    files = source.extract_source_files(json.dumps(payload), "Vault")
    assert files == {
        "contracts/Vault.sol": "contract Vault {}",
        "contracts/Token.sol": "contract Token {}",
    }


def test_extracts_etherscan_double_brace_standard_json():
    payload = {"sources": {"Vault.sol": {"content": "contract Vault {}"}}}
    wrapped = "{" + json.dumps(payload) + "}"
    assert source.extract_source_files(wrapped)["Vault.sol"] == "contract Vault {}"


@pytest.mark.parametrize("bad_name", ["../escape.sol", "/tmp/escape.sol", "C:\\escape.sol"])
def test_rejects_unsafe_source_paths(bad_name):
    with pytest.raises(source.SourceRetrievalError):
        source.extract_source_files(json.dumps({"sources": {bad_name: {"content": "contract X {}"}}}))


def test_rejects_unverified_source():
    with pytest.raises(source.SourceRetrievalError, match="not verified"):
        source.extract_source_files("Contract source code not verified")


def test_rejects_invalid_address():
    with pytest.raises(source.SourceRetrievalError, match="Address"):
        source.fetch_verified_source("0x123", 1, Path("unused"), api_key="test")


def test_requires_api_key(monkeypatch, tmp_path):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    with pytest.raises(source.SourceRetrievalError, match="ETHERSCAN_API_KEY"):
        source.fetch_verified_source("0x" + "1" * 40, 1, tmp_path, api_key=None)


def test_fetch_writes_verified_source_and_metadata(monkeypatch, tmp_path):
    from io import BytesIO

    response = {
        "status": "1",
        "message": "OK",
        "result": [{
            "SourceCode": "pragma solidity ^0.8.20; contract Demo {}",
            "ContractName": "Demo",
            "CompilerVersion": "v0.8.20+commit.a1b79de6",
            "OptimizationUsed": "1",
            "Runs": "200",
            "Proxy": "0",
            "Implementation": "",
        }],
    }

    def fake_urlopen(request, timeout):
        assert "chainid=8453" in request.full_url
        assert "action=getsourcecode" in request.full_url
        return BytesIO(json.dumps(response).encode("utf-8"))

    monkeypatch.setattr(source, "urlopen", fake_urlopen)
    output_dir = tmp_path / "retrieved"
    metadata = source.fetch_verified_source(
        "0x" + "a" * 40, 8453, output_dir, api_key="test-key"
    )

    assert metadata["verified_source"] is True
    assert metadata["chain_id"] == 8453
    assert metadata["contract_name"] == "Demo"
    assert len(metadata["source_files"]) == 1
    assert Path(metadata["source_files"][0]).read_text(encoding="utf-8") == response["result"][0]["SourceCode"]


def test_cli_scans_retrieved_source_and_records_metadata(monkeypatch, tmp_path):
    import quotes

    def fake_fetch(address, chain_id, output_dir, api_key=None):
        destination = Path(output_dir).resolve()
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "Fetched.sol").write_text(
            "pragma solidity ^0.8.20; contract Fetched { function time() external view returns(uint) { return block.timestamp; } }",
            encoding="utf-8",
        )
        return {
            "provider": "etherscan-api-v2",
            "chain_id": chain_id,
            "address": address,
            "contract_name": "Fetched",
            "source_files": [str(destination / "Fetched.sol")],
            "verified_source": True,
        }

    monkeypatch.setattr(quotes, "fetch_verified_source", fake_fetch)
    output = tmp_path / "report.json"
    source_dir = tmp_path / "source"
    result = quotes.main([
        "--address", "0x" + "b" * 40,
        "--chain-id", "8453",
        "--source-dir", str(source_dir),
        "--out", str(output),
        "--heuristics-only",
    ])
    report = json.loads(output.read_text(encoding="utf-8"))

    assert result == 0
    assert report["source"]["chain_id"] == 8453
    assert report["source"]["verified_source"] is True
    assert report["summary"]["heuristic_finding_count"] == 1
