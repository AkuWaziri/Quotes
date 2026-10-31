"""Retrieve verified Solidity source from Etherscan API V2.

The module only performs read-only explorer API requests. It never submits
transactions, executes retrieved source, or interacts with a contract.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ETHERSCAN_V2_API = "https://api.etherscan.io/v2/api"
ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")


class SourceRetrievalError(RuntimeError):
    """Raised when verified source cannot be retrieved safely."""


def _decode_standard_json(source_code: str) -> dict[str, Any] | None:
    candidate = source_code.strip()
    # Etherscan V2 sometimes wraps Standard JSON input in an extra brace pair.
    if candidate.startswith("{{") and candidate.endswith("}}"):
        candidate = candidate[1:-1]
    if not candidate.startswith("{"):
        return None
    try:
        decoded = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return decoded if isinstance(decoded, dict) else None


def _safe_source_path(name: str) -> Path:
    """Reject absolute paths and traversal before writing explorer source."""
    posix = PurePosixPath(name.replace("\\", "/"))
    if not name or posix.is_absolute() or any(part in {"", ".", ".."} for part in posix.parts):
        raise SourceRetrievalError(f"Unsafe source path returned by explorer: {name!r}")
    if posix.parts and re.match(r"^[A-Za-z]:", posix.parts[0]):
        raise SourceRetrievalError(f"Unsafe source path returned by explorer: {name!r}")
    return Path(*posix.parts)


def extract_source_files(source_code: str, contract_name: str = "Contract") -> dict[str, str]:
    """Convert Etherscan's single-file or Standard JSON source into file contents."""
    if not source_code or source_code.strip() in {"", "Contract source code not verified"}:
        raise SourceRetrievalError("Explorer reports that source code is not verified.")

    standard_json = _decode_standard_json(source_code)
    if standard_json is not None:
        sources = standard_json.get("sources")
        if isinstance(sources, dict) and sources:
            result: dict[str, str] = {}
            for name, entry in sources.items():
                if not isinstance(name, str) or not isinstance(entry, dict):
                    continue
                content = entry.get("content")
                if isinstance(content, str):
                    safe_path = _safe_source_path(name).as_posix()
                    result[safe_path] = content
            if result:
                return result
            raise SourceRetrievalError("Verified Standard JSON did not contain readable source files.")

    # Etherscan's single-file response is raw Solidity text.
    filename = contract_name if contract_name.endswith(".sol") else f"{contract_name}.sol"
    return { _safe_source_path(filename).as_posix(): source_code }


def fetch_verified_source(
    address: str,
    chain_id: int,
    output_dir: str | Path,
    api_key: str | None = None,
    timeout: int = 30,
) -> dict[str, Any]:
    """Fetch verified source and metadata using Etherscan API V2."""
    if not ADDRESS_RE.fullmatch(address):
        raise SourceRetrievalError("Address must be a 20-byte EVM address (0x + 40 hex characters).")
    if isinstance(chain_id, bool) or not isinstance(chain_id, int) or chain_id <= 0:
        raise SourceRetrievalError("Chain ID must be a positive integer.")

    key = api_key or os.getenv("ETHERSCAN_API_KEY")
    if not key:
        raise SourceRetrievalError(
            "ETHERSCAN_API_KEY is missing. Set it in your environment or pass --api-key."
        )

    query = urlencode({
        "chainid": chain_id,
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": key,
    })
    request = Request(
        f"{ETHERSCAN_V2_API}?{query}",
        headers={"Accept": "application/json", "User-Agent": "QUOTES-Security-Scanner/0.2"},
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise SourceRetrievalError(f"Explorer request failed: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SourceRetrievalError(f"Explorer returned invalid JSON: {exc}") from exc

    if not isinstance(payload, dict) or payload.get("status") != "1":
        message = payload.get("result") if isinstance(payload, dict) else "invalid response"
        raise SourceRetrievalError(f"Explorer API rejected the request: {message}")
    rows = payload.get("result")
    if not isinstance(rows, list) or not rows or not isinstance(rows[0], dict):
        raise SourceRetrievalError("Explorer response did not include contract metadata.")

    metadata = rows[0]
    contract_name = str(metadata.get("ContractName") or "Contract")
    source_files = extract_source_files(str(metadata.get("SourceCode") or ""), contract_name)
    root = Path(output_dir).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    for relative_name, contents in source_files.items():
        safe_relative = _safe_source_path(relative_name)
        destination = (root / safe_relative).resolve()
        if root != destination and root not in destination.parents:
            raise SourceRetrievalError(f"Source path escapes output directory: {relative_name!r}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(contents, encoding="utf-8")
        written.append(str(destination))

    return {
        "provider": "etherscan-api-v2",
        "chain_id": chain_id,
        "address": address,
        "contract_name": contract_name,
        "compiler_version": metadata.get("CompilerVersion") or None,
        "optimization_used": metadata.get("OptimizationUsed") or None,
        "runs": metadata.get("Runs") or None,
        "proxy": metadata.get("Proxy") or None,
        "implementation": metadata.get("Implementation") or None,
        "source_files": written,
        "verified_source": True,
    }
