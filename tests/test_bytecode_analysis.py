import pytest

from bytecode_analysis import BytecodeAnalysisError, analyze_runtime_bytecode, disassemble_opcodes


def test_disassembler_skips_opcode_like_bytes_inside_push_data():
    # PUSH2 contains bytes F4 FF; neither is an executed opcode.
    assert disassemble_opcodes("0x61f4ff00") == ["PUSH2", "STOP"]


def test_disassembler_detects_actual_review_opcodes():
    result = analyze_runtime_bytecode("0x32f442f1ff")
    ids = {item["id"] for item in result["indicators"]}
    assert {"QB001", "QB002", "QB003", "QB004", "QB005"} <= ids
    assert result["runtime_bytecode_bytes"] == 5
    assert result["sha256"]


def test_detects_eip1167_minimal_proxy():
    implementation = "11" * 20
    code = "0x363d3d373d3d3d363d73" + implementation + "5af43d82803e903d91602b57fd5bf3"
    result = analyze_runtime_bytecode(code)
    assert result["minimal_proxy_detected"] is True
    assert result["minimal_proxy_implementation"] == "0x" + implementation


@pytest.mark.parametrize("code", ["", "0x", "0x123", "0xzz", None])
def test_rejects_malformed_or_empty_bytecode(code):
    with pytest.raises(BytecodeAnalysisError):
        analyze_runtime_bytecode(code)


def test_push_data_does_not_trigger_false_positive_indicators():
    result = analyze_runtime_bytecode("0x63f432f1ff00")
    assert result["indicators"] == []
