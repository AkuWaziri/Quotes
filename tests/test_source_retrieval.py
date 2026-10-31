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
