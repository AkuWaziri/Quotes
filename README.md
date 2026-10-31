# QUOTES — Smart Contract Security Scanner

QUOTES is an early-stage, defensive security scanner for EVM smart-contract code. It combines established static analysis (Slither) with a small set of clearly labelled heuristic checks and emits a JSON report.

> **Status:** MVP foundation. This is not an audit and cannot prove a contract is safe. Heuristic matches are leads for manual review, not confirmed vulnerabilities.

## What works in this first version
- Scan a local Solidity file or a Hardhat/Foundry project directory.
- Run Slither when installed and available.
- Run lightweight source-pattern checks even when Slither is unavailable.
- Write machine-readable JSON results with severity, confidence, location and remediation notes.
- Run tests in GitHub Actions.

## Regression tests
The test suite includes deliberately vulnerable and safe-control Solidity fixtures. It checks that the built-in heuristics flag expected patterns in the vulnerable fixture and ignore matching text that appears only in comments. These tests validate pattern behavior only; they do not prove exploitability or measure detection coverage across real-world contracts.

Run the tests with:
```bash
pip install pytest
python -m pytest -q
```

## Requirements
- Python 3.10+
- Recommended: Slither and a compatible Solidity compiler for deeper static analysis. Slither's official setup and supported workflows are documented at https://github.com/crytic/slither.
- Project dependencies/imports must be available when scanning a full project.

## Run locally
```bash
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
# source .venv/bin/activate
pip install -r requirements.txt
python quotes.py --target path/to/Contract.sol --out quotes-report.json
```

For a Hardhat/Foundry project, point `--target` at the project root:
```bash
python quotes.py --target . --out quotes-report.json
```

To run only the built-in pattern checks:
```bash
python quotes.py --target path/to/Contract.sol --heuristics-only
```

Exit codes:
- `0`: scan completed; no high-confidence tool error.
- `1`: invalid input or scan could not run.
- Findings do not currently change the exit code; this makes the tool usable for exploratory scans.

## Output
The JSON report includes scan metadata, tool status, findings, and limitations. Slither findings are retained as tool output and parsed where possible; heuristic findings are marked `heuristic` and `low` confidence.

## Roadmap
1. Add explorer-based verified source retrieval and chain-aware contract metadata.
2. Add bytecode/ABI metadata analysis for contracts without verified source.
3. Add isolated fork-based tests and fuzzing/property-testing integrations.
4. Add duplicate suppression, historical finding storage, and optional notifications.
5. Add a web dashboard only after the CLI scanner is reliable.

## Safety
Only scan contracts you are authorized to assess. Validation must use local tests or isolated forks; never attempt to exploit or alter live contracts. Do not upload secrets, private keys, or production credentials into scan targets.
