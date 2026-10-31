"""Conservative runtime-bytecode inspection for EVM contracts.

This module disassembles instructions without interpreting PUSH immediate bytes,
then reports opcode indicators as review leads rather than vulnerability claims.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from typing import Any

_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]*$")
_MINIMAL_PROXY_RE = re.compile(
    r"^363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3$",
    re.IGNORECASE,
)
_OPCODE_NAMES = {
    0x00: "STOP", 0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV",
    0x05: "SDIV", 0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
    0x0A: "EXP", 0x0B: "SIGNEXTEND", 0x10: "LT", 0x11: "GT", 0x12: "SLT",
    0x13: "SGT", 0x14: "EQ", 0x15: "ISZERO", 0x16: "AND", 0x17: "OR",
    0x18: "XOR", 0x19: "NOT", 0x1A: "BYTE", 0x1B: "SHL", 0x1C: "SHR",
    0x1D: "SAR", 0x20: "KECCAK256", 0x30: "ADDRESS", 0x31: "BALANCE",
    0x32: "ORIGIN", 0x33: "CALLER", 0x34: "CALLVALUE", 0x35: "CALLDATALOAD",
    0x36: "CALLDATASIZE", 0x37: "CALLDATACOPY", 0x38: "CODESIZE",
    0x39: "CODECOPY", 0x3A: "GASPRICE", 0x3B: "EXTCODESIZE",
    0x3C: "EXTCODECOPY", 0x3D: "RETURNDATASIZE", 0x3E: "RETURNDATACOPY",
    0x3F: "EXTCODEHASH", 0x40: "BLOCKHASH", 0x41: "COINBASE",
    0x42: "TIMESTAMP", 0x43: "NUMBER", 0x44: "PREVRANDAO", 0x45: "GASLIMIT",
    0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE", 0x50: "POP",
    0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x54: "SLOAD",
    0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI", 0x58: "PC", 0x59: "MSIZE",
    0x5A: "GAS", 0x5B: "JUMPDEST", 0x5F: "PUSH0", 0xF0: "CREATE",
    0xF1: "CALL", 0xF2: "CALLCODE", 0xF3: "RETURN", 0xF4: "DELEGATECALL",
    0xF5: "CREATE2", 0xFA: "STATICCALL", 0xFD: "REVERT", 0xFE: "INVALID",
    0xFF: "SELFDESTRUCT",
}


class BytecodeAnalysisError(ValueError):
    """Raised when runtime bytecode is malformed or empty."""


def disassemble_opcodes(bytecode: str) -> list[str]:
    """Return opcode names while correctly skipping PUSH1..PUSH32 data."""
    if not isinstance(bytecode, str):
        raise BytecodeAnalysisError("Bytecode must be a hex string.")
    value = bytecode[2:] if bytecode.startswith(("0x", "0X")) else bytecode
    if not value or not _HEX_RE.fullmatch(value):
        raise BytecodeAnalysisError("Bytecode must contain non-empty hexadecimal data.")
    if len(value) % 2:
        raise BytecodeAnalysisError("Bytecode must contain an even number of hex characters.")

    raw = bytes.fromhex(value)
    opcodes: list[str] = []
    pc = 0
    while pc < len(raw):
        opcode = raw[pc]
        pc += 1
        opcodes.append(_OPCODE_NAMES.get(opcode, f"UNKNOWN_0x{opcode:02x}"))
        if 0x60 <= opcode <= 0x7F:
            pc += opcode - 0x5F
    return opcodes


def analyze_runtime_bytecode(bytecode: str) -> dict[str, Any]:
    """Summarize runtime bytecode and flag notable opcodes for manual review."""
    value = bytecode[2:] if isinstance(bytecode, str) and bytecode.startswith(("0x", "0X")) else bytecode
    if not isinstance(value, str) or not value or not _HEX_RE.fullmatch(value) or len(value) % 2:
        raise BytecodeAnalysisError("Bytecode must contain non-empty, even-length hexadecimal data.")

    normalized = value.lower()
    raw = bytes.fromhex(normalized)
    opcodes = disassemble_opcodes(normalized)
    counts = Counter(opcodes)
    indicators: list[dict[str, str]] = []

    rules = [
        ("QB001", "ORIGIN opcode present", "ORIGIN appears in runtime bytecode. This alone does not establish that it controls authorization.", "ORIGIN"),
        ("QB002", "DELEGATECALL opcode present", "DELEGATECALL is common in proxies and libraries; review target constraints and storage context.", "DELEGATECALL"),
        ("QB003", "SELFDESTRUCT opcode present", "SELFDESTRUCT appears in runtime bytecode. Review reachability, authorization, and target-chain semantics.", "SELFDESTRUCT"),
        ("QB004", "TIMESTAMP opcode present", "TIMESTAMP appears in runtime bytecode. Review any value, fairness, or randomness dependency.", "TIMESTAMP"),
        ("QB005", "External call opcode present", "One or more CALL-family opcodes appear. Review call targets, return handling, and reentrancy protections.", "CALL"),
    ]
    for rule_id, title, description, opcode in rules:
        matches = counts.get(opcode, 0)
        if opcode == "CALL":
            matches = sum(counts.get(name, 0) for name in ("CALL", "CALLCODE", "STATICCALL"))
        if matches:
            indicators.append({
                "id": rule_id,
                "title": title,
                "opcode": opcode,
                "count": matches,
                "confidence": "low",
                "status": "needs_manual_review",
                "description": description,
            })

    proxy_match = _MINIMAL_PROXY_RE.fullmatch(normalized)
    return {
        "runtime_bytecode_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "opcode_count": len(opcodes),
        "opcode_counts": dict(sorted(counts.items())),
        "minimal_proxy_detected": bool(proxy_match),
        "minimal_proxy_implementation": f"0x{proxy_match.group(1)}" if proxy_match else None,
        "eip170_size_limit_exceeded": len(raw) > 24_576,
        "indicators": indicators,
        "limitations": [
            "Opcode indicators do not prove a vulnerability or establish reachability.",
            "PUSH data is skipped, but this is not full symbolic execution or control-flow analysis.",
            "Proxy and compiler metadata patterns can vary; verify results with chain metadata and source.",
        ],
    }
