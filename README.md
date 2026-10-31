# QUOTES — Smart Contract Security Scanner

QUOTES is an early-stage, defensive scanner for EVM smart-contract source. It combines five lightweight source heuristics with optional Slither static analysis and emits a JSON report. It can also retrieve verified source and metadata from Etherscan API V2.

> **Status:** early-stage scanner, not an audit. Heuristic matches are leads for manual review, not confirmed vulnerabilities. A clean result does not establish that a contract is secure.

## Current features

- Scan a local Solidity file or Hardhat/Foundry project.
- Retrieve verified source files and contract metadata from Etherscan API V2.
- Reject unverified source and unsafe source paths before writing files.
- Run Slither when installed; keep source heuristics available if Slither is absent.
- Produce JSON output with findings, confidence, severity, recommendations, source metadata, and tool status.
- Regression tests for vulnerable patterns, comment-only controls, explorer source parsing, path traversal, and CLI behavior.
- GitHub Actions test matrix for Python 3.10–3.13.

## Environment setup

Python 3.10 or newer is required.

### Windows PowerShell
```powershell
git clone https://github.com/AkuWaziri/Quotes.git
cd Quotes
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
python -m pytest -q
```

If PowerShell blocks activation, run `.\.venv\Scripts\python.exe -m pytest -q` or use Command Prompt activation instead.

### macOS / Linux
```bash
git clone https://github.com/AkuWaziri/Quotes.git
cd Quotes
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
python -m pytest -q
```

### Optional Slither
Slither is optional; local heuristic checks still run without it.
```bash
python -m pip install -e ".[slither]"
slither --version
```
For projects that require a specific compiler, install and configure that Solidity compiler and project dependencies separately. Slither may need a compatible compiler and project configuration.

## Scan local source

Single Solidity file:
```bash
python quotes.py --target path/to/Contract.sol --out quotes-report.json
```

Hardhat or Foundry project:
```bash
python quotes.py --target . --out quotes-report.json
```

Skip Slither and run only built-in heuristics:
```bash
python quotes.py --target path/to/Contract.sol --heuristics-only
```

## Retrieve and scan verified source

Create an API key at Etherscan and set it as an environment variable. Never commit a real key or paste it into source code.

Windows PowerShell:
```powershell
$env:ETHERSCAN_API_KEY = "YOUR_ETHERSCAN_API_KEY"
python quotes.py --address 0xYourContractAddress --chain-id 1 --out reports/contract.json --heuristics-only
```

macOS / Linux:
```bash
export ETHERSCAN_API_KEY="YOUR_ETHERSCAN_API_KEY"
python quotes.py --address 0xYourContractAddress --chain-id 1 --out reports/contract.json --heuristics-only
```

Replace chain ID `1` with the chain ID for the contract. Etherscan API V2 supports multiple EVM networks through its `chainid` parameter; the selected network must be supported by Etherscan. The command downloads verified source into `quotes-downloads/` by default. To choose another directory, pass `--source-dir path/to/downloads`. The JSON report records chain ID, address, contract name, compiler metadata, proxy metadata, and downloaded source paths.

The retrieval feature is read-only. It does not call contract functions or submit transactions. Source verification by an explorer confirms publication/matching metadata, not that the contract is safe.

## Output and exit codes

The JSON report includes scan timestamp, target, verified-source metadata (when applicable), Solidity file count, Slither status, heuristic findings, and summary counts.

- `0`: scan completed and report written.
- `1`: invalid target, no Solidity files, explorer failure, or report write failure.
- `2`: invalid command-line arguments.

A heuristic finding does not change the exit code. The scanner currently does not implement bytecode analysis, symbolic execution, fuzzing, fork simulation, historical finding storage, notifications, or a dashboard. These are future modules and should be added behind tests without changing working scan behavior.

## Safety and limitations

Only scan contracts you are authorized to assess. Use local tests or isolated forks for validation; do not attempt to exploit or alter live contracts. Do not upload secrets, private keys, or production credentials into scan targets. Review findings manually and use independent audit processes for consequential deployments.
