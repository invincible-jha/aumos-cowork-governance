# aumos-cowork-governance

Governance plugin for multi-agent collaboration environments

[![CI](https://github.com/aumos-ai/aumos-cowork-governance/actions/workflows/ci.yaml/badge.svg)](https://github.com/aumos-ai/aumos-cowork-governance/actions/workflows/ci.yaml)
[![PyPI version](https://img.shields.io/pypi/v/aumos-cowork-governance.svg)](https://pypi.org/project/aumos-cowork-governance/)
[![Python versions](https://img.shields.io/pypi/pyversions/aumos-cowork-governance.svg)](https://pypi.org/project/aumos-cowork-governance/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Part of the [AumOS](https://github.com/aumos-ai) open-source agent infrastructure portfolio.

---

## Features

- `PolicyEngine` loads governance policies from YAML and evaluates them against agent action contexts using ten built-in condition operators including `contains_pii`, `matches` (regex), and `greater_than`
- ALLOW, BLOCK, WARN, LOG, and APPROVE actions — the engine short-circuits on the first BLOCK and accumulates APPROVE policies to drive human-in-the-loop approval queues
- PII detection with regex pattern libraries for US, EU, and India identifiers, plus a `Redactor` that masks sensitive data before it leaves the governance boundary
- Cost tracker and budget manager with daily/weekly/monthly limits, configurable alerts, and a cost reporter for per-agent spend breakdowns
- Append-only audit logger with log rotation, structured search, and exporters for downstream SIEM ingestion
- Policy template library with pre-built rule sets for common governance patterns (data residency, cost control, PII handling)
- Governance dashboard server (`dashboard.api`) that exposes policy status, audit summaries, and budget utilization over HTTP

## Quick Start

Install from PyPI:

```bash
pip install aumos-cowork-governance
```

Verify the installation:

```bash
aumos-cowork-governance version
```

Basic usage:

```python
import aumos_cowork_governance

# See examples/01_quickstart.py for a working example
```

## Documentation

- [Architecture](docs/architecture.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Examples](examples/README.md)

## Enterprise Upgrade

The open-source edition provides the core foundation. For production
deployments requiring SLA-backed support, advanced integrations, and the full
AgentGov platform, see [docs/UPGRADE_TO_AgentGov.md](docs/UPGRADE_TO_AgentGov.md).

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
before opening a pull request.

## License

Apache 2.0 — see [LICENSE](LICENSE) for full terms.

---

Part of [AumOS](https://github.com/aumos-ai) — open-source agent infrastructure.
