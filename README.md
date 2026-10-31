# QUOTES — Smart Contract Security Scanner

QUOTES is an early-stage, defensive EVM contract scanner. It combines five Solidity source heuristics, optional Slither static analysis, and a conservative runtime-bytecode opcode pass. It can retrieve verified source from Etherscan API V2 and read deployed runtime bytecode from a JSON-RPC endpoint.

> **Status:** scanner, not an audit. Source-pattern and opcode matches are review leads, not confirmed vulnerabilities. A clean result does not establish that a contract is secure.

## Current features

- Scan local Solidity files and Hardhat/Foundry projects.
- Retrieve verified source and compiler/proxy metadata from Etherscan API V2.
- Retrieve deployed runtime bytecode using read-only JSON-RPC calls.
- Check that the RPC endpoint's reported chain ID matches the requested chain before reading bytecode.
- Disassemble EVM opcodes while skipping PUSH immediate data, reducing false positives from bytes that are not executed as opcodes.
- Flag ORIGIN, DELEGATECALL, SELFDESTRUCT, TIMESTAMP, and CALL-family opcodes as low-confidence review indicators.
- Recognize the standard EIP-1167 minimal proxy runtime pattern.
- Analyse bytecode even when verified source is unavailable.
- Optional Slither analysis for source-enabled scans.
- JSON reports, path-safe source retrieval, regression tests, and GitHub Actions on Python 3.10–3.13.

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

If PowerShell blocks activation, run `.\.venv\Scripts\python.exe -m pytest -q` or use Command Prompt activation.

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
```bash
python -m pip install -e ".[slither]"
slither --version
```
Slither may require a compatible Solidity compiler and the target project's dependencies/configuration.

## Scan local source

```bash
python quotes.py --target path/to/Contract.sol --out reports/contract.json
```

For a Hardhat/Foundry project:
```bash
python quotes.py --target . --out reports/project.json
```

Run only the built-in source checks:
```bash
python quotes.py --target path/to/Contract.sol --heuristics-only
```

## Scan a deployed contract by address

Set an RPC endpoint for the target chain. Use HTTPS for remote endpoints; HTTP is allowed only for loopback development endpoints. QUOTES calls `eth_chainId` and refuses to read bytecode if the endpoint reports a different chain ID.

Windows PowerShell:
```powershell
$env:QUOTES_RPC_URL = "https://YOUR_CHAIN_RPC_ENDPOINT"
$env:ETHERSCAN_API_KEY = "YOUR_ETHERSCAN_API_KEY"
python quotes.py --address 0xYourContractAddress --chain-id 8453 --out reports/contract.json
```

macOS / Linux:
```bash
export QUOTES_RPC_URL="https://YOUR_CHAIN_RPC_ENDPOINT"
export ETHERSCAN_API_KEY="YOUR_ETHERSCAN_API_KEY"
python quotes.py --address 0xYourContractAddress --chain-id 8453 --out reports/contract.json
```

Replace `8453` with the actual chain ID. `QUOTES_RPC_URL` is required for on-chain bytecode analysis. `ETHERSCAN_API_KEY` is required for verified source retrieval; if source is unverified or the explorer request fails, the scanner can still produce a bytecode-only report when RPC access succeeds. Retrieved Solidity files are written to `quotes-downloads/` by default; use `--source-dir` to change that directory.

The address workflow is read-only. It does not submit transactions, call contract methods, or attempt to exploit the target. Do not place API keys directly in source files or commit a real `.env` file.

## Report contents

Reports include chain/address metadata, source retrieval status, Solidity file count, Slither status, heuristic findings, bytecode size and SHA-256 fingerprint, opcode counts, minimal-proxy detection, bytecode indicators, and summary counts. Raw bytecode is not copied into the report.

- Exit code `0`: at least source or bytecode analysis completed and the report was written.
- Exit code `1`: invalid target, no analysable source/bytecode, retrieval failure, or report write failure.
- Exit code `2`: invalid command-line arguments.

## Current limitations

- Bytecode indicators are not control-flow analysis and do not prove an opcode is reachable.
- The minimal-proxy recognizer covers the common EIP-1167 runtime pattern; other proxy implementations need separate analysis.
- No symbolic execution, fuzzing, fork simulation, exploit validation, historical finding database, notifications, or dashboard is implemented yet.
- Source heuristics are not a Solidity parser. Slither is recommended for deeper source analysis.

Only scan contracts you are authorized to assess. Validate behavior with tests and isolated forks; do not attempt to exploit or alter live contracts.
