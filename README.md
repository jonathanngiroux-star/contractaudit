# Smart Contract Continuous Audit

Monthly coverage of new deployments, upgrades, dependency changes — not one-shot audits.

## Service Description

ContractAudit provides continuous smart contract security monitoring. Instead of expensive one-shot audits, it offers:

- **Continuous scanning** of deployed contracts on every block
- **Upgrade detection** — alerts when proxy implementations change
- **Dependency monitoring** — tracks library upgrades and vulnerability disclosures
- **Bytecode & source analysis** — 8 built-in vulnerability rules (reentrancy, unchecked returns, tx.origin, delegatecall, selfdestruct, access control, timestamp dependence, integer overflow)
- **Custom rules** — YAML-based rule engine for project-specific patterns
- **Multi-chain support** — Ethereum, Polygon, Arbitrum, Optimism, Base, Gnosis
- **Historical tracking** — vulnerability timeline with new/resolved counts
- **Webhook alerts** — real-time notifications for critical findings

Pricing: **$199–500/mo** (Specialty tier with SLA)

## Installation

```bash
# Build from source
go build -o contractaudit .

# Or install directly
go install github.com/jonathanngiroux-star/contractaudit@latest
```

## Configuration

Create a config file at `./config.yaml`:

```yaml
chains:
  ethereum:
    name: "Ethereum Mainnet"
    rpc_url: "https://eth.llamarpc.com"
    explorer: "https://etherscan.io"
    chain_id: 1
  polygon:
    name: "Polygon"
    rpc_url: "https://polygon-rpc.com"
    explorer: "https://polygonscan.com"
    chain_id: 137
  # ... more chains

rules_path: "./rules"
output_dir: "./reports"
scan_interval: "24h"
alert_webhook: "https://your-webhook.example.com/alerts"

contracts:
  - id: "uuid"
    address: "0x..."
    chain: "ethereum"
    name: "MyToken"
    abi: "[...]"
    source_url: "https://etherscan.io/address/0x...#code"
    enabled: true
```

## CLI Interface

```bash
# Add a contract to monitor
contractaudit -action add -address 0x123... -chain ethereum -name "MyToken" -abi ./abi.json -source "https://etherscan.io/address/0x123...#code"

# List monitored contracts
contractaudit -action list

# Scan a specific contract
contractaudit -action scan -id <contract-id>

# Scan all contracts
contractaudit -action scan-all

# View contract report
contractaudit -action report -id <contract-id>

# Remove a contract
contractaudit -action remove -id <contract-id>

# Run as daemon (continuous scanning)
contractaudit -action serve -port 8080
```

## Vulnerability Rules (Built-in)

| Rule ID | Name | Severity | Category |
|---------|------|----------|----------|
| `reentrancy` | Reentrancy Vulnerability | critical | reentrancy |
| `unchecked-return` | Unchecked Return Value | medium | error-handling |
| `tx-origin` | tx.origin Authentication | high | authentication |
| `delegatecall` | Dangerous Delegatecall | critical | proxy |
| `selfdestruct` | Selfdestruct Usage | high | destruct |
| `unprotected-function` | Unprotected Critical Function | high | access-control |
| `timestamp-dependence` | Timestamp Dependence | medium | time |
| `integer-overflow` | Integer Overflow/Underflow | high | arithmetic |

## Custom Rules

Add YAML files to `./rules/`:

```yaml
id: "custom-rule-1"
name: "Custom Pattern"
severity: "high"
category: "custom"
pattern: "require\(msg\.sender == owner\)"
bytecode_sig: ""
description: "Custom authorization check pattern"
remediation: "Use OpenZeppelin Ownable"
references:
  - "https://example.com"
```

## API Interface (when running as daemon)

```
GET  /api/contracts          - List all contracts
GET  /api/contracts/:id      - Get contract details
POST /api/contracts          - Add new contract
DELETE /api/contracts/:id    - Remove contract
POST /api/contracts/:id/scan - Trigger scan
GET  /api/contracts/:id/report - Get latest report
GET  /api/scan-results       - List recent scans
GET  /api/metrics            - Prometheus metrics
```

## Pricing

| Tier | Price | Includes |
|------|-------|----------|
| Starter | $199/mo | Up to 10 contracts, daily scans, email alerts |
| Professional | $349/mo | Up to 50 contracts, hourly scans, Slack/PagerDuty, upgrade detection |
| Enterprise | $500/mo | Unlimited contracts, 15-min scans, custom rules, SLA with credits, on-call |

## Hosted Version

Managed continuous auditing at **katsironni.com/contractaudit** — includes SLA, managed infrastructure, and 24/7 security team.

## License

MIT — see [LICENSE](LICENSE)