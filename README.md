# QUOTES — Smart Contract Security Scanner

QUOTES is an early-stage, defensive EVM contract scanner. It combines Solidity source heuristics, optional Slither static analysis, conservative runtime-bytecode inspection, optional SQLite scan history, and a self-contained HTML report.

> **Status:** scanner, not an audit. Source-pattern and opcode matches are review leads, not confirmed vulnerabilities. A clean result does not establish that a contract is secure.

## Current features

- Scan local Solidity files and Hardhat/Foundry projects.
- Retrieve verified source and compiler/proxy metadata from Etherscan API V2.
- Read deployed runtime bytecode through read-only JSON-RPC and verify the endpoint's chain ID.
- Disassemble EVM opcodes while skipping PUSH immediate data.
- Flag ORIGIN, DELEGATECALL, SELFDESTRUCT, TIMESTAMP, and CALL-family opcodes as low-confidence review indicators.
- Recognize the standard EIP-1167 minimal-proxy runtime pattern.
- Produce bytecode-only reports when source is unverified or unavailable.
- Run Slither when installed.
- Optionally store scan history in SQLite and mark findings as new or repeated per target.
- Optionally create a self-contained HTML report with escaped finding text.
- Optionally send a summary-only notification to a Slack/Discord-compatible HTTPS webhook.
- Run regression tests in GitHub Actions on Python 3.10–3.13.

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

Skip Slither and run only the built-in source checks (address scans still include bytecode inspection):
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

Replace `8453` with the actual chain ID. `QUOTES_RPC_URL` is required for on-chain bytecode analysis. `ETHERSCAN_API_KEY` is required for verified source retrieval; if source is unverified or the explorer request fails, the scanner can still produce a bytecode-only report when RPC access succeeds. Retrieved Solidity files are written under `quotes-downloads/<chain-id>/<lowercase-address>/` by default; use `--source-dir` to change the root.

## Optional scan history

History is opt-in and does not change default scan behavior:
```bash
python quotes.py --target path/to/Contract.sol --history-db quotes-history.sqlite3 --out reports/contract.json
```

Repeated findings are fingerprinted per target and marked `new` or `repeat` in the report. The SQLite database stays local. Keep it out of source control if it contains private project paths or assessment details.

## Optional HTML report

```bash
python quotes.py --target path/to/Contract.sol --out reports/contract.json --html-out reports/contract.html
```

The HTML file is self-contained and escapes finding text before rendering. It can be opened locally in a browser and shared as a static report. Do not share reports containing private contract paths or sensitive assessment details without reviewing them first.

## Optional webhook notifications

Notifications are disabled unless you explicitly pass `--notify`. Configure a Slack or Discord-compatible incoming HTTPS webhook in `QUOTES_WEBHOOK_URL`, or pass `--webhook-url` directly. The message contains only scanner version and finding counts; it does not send source code, bytecode, or the full report.

PowerShell:
```powershell
$env:QUOTES_WEBHOOK_URL = "https://YOUR_WEBHOOK_URL"
python quotes.py --target path/to/Contract.sol --notify --out reports/contract.json
```

macOS / Linux:
```bash
export QUOTES_WEBHOOK_URL="https://YOUR_WEBHOOK_URL"
python quotes.py --target path/to/Contract.sol --notify --out reports/contract.json
```

Treat the webhook URL as a secret. QUOTES refuses non-HTTPS remote webhook URLs. A delivery failure is recorded in the report and does not discard completed scan results.

History and HTML can be combined:
```bash
python quotes.py --target path/to/Contract.sol --history-db quotes-history.sqlite3 --out reports/contract.json --html-out reports/contract.html
```

## Report contents and exit codes

Reports include target metadata, source retrieval status, Solidity file count, Slither status, source findings, bytecode size and SHA-256 fingerprint, opcode indicators, and summary counts. When enabled, reports also include a history scan ID and new/repeat counts.

- Exit code `0`: at least source or bytecode analysis completed and the report was written.
- Exit code `1`: invalid target, no analysable source/bytecode, retrieval failure, or report write failure.
- Exit code `2`: invalid command-line arguments.

## Current limitations

- Bytecode indicators are not control-flow analysis and do not prove an opcode is reachable.
- The minimal-proxy recognizer covers the common EIP-1167 runtime pattern; other proxy implementations need separate analysis.
- No symbolic execution, fuzzing, fork simulation, exploit validation, or interactive web dashboard is implemented yet.
- Source heuristics are not a Solidity parser. Slither is recommended for deeper source analysis.

Only scan contracts you are authorized to assess. Validate behavior with tests and isolated forks; do not attempt to exploit or alter live contracts.
