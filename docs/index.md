# aumos-cowork-governance

Multi-Agent Governance Plugin — compliance policies, workflow guardrails, and constitution framework.

[![CI](https://github.com/invincible-jha/aumos-cowork-governance/actions/workflows/ci.yaml/badge.svg)](https://github.com/invincible-jha/aumos-cowork-governance/actions/workflows/ci.yaml)
[![PyPI version](https://img.shields.io/pypi/v/aumos-cowork-governance.svg)](https://pypi.org/project/aumos-cowork-governance/)
[![Python versions](https://img.shields.io/pypi/pyversions/aumos-cowork-governance.svg)](https://pypi.org/project/aumos-cowork-governance/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## Installation

```bash
pip install aumos-cowork-governance
```

Verify the installation:

```bash
aumos-cowork-governance version
```

---

## Quick Start

```python
from aumos_cowork_governance import PolicyEngine, BudgetManager, AuditLogger

# Load and evaluate a governance policy
engine = PolicyEngine()
engine.load_from_yaml("governance_policy.yaml")

action_context = {
    "agent_id": "agent-alpha",
    "action_type": "api_call",
    "data": {"endpoint": "/api/users", "payload": "john.doe@example.com"},
    "cost": 0.05,
}

result = engine.evaluate(action_context)
print(f"Decision: {result.decision}")   # ALLOW, BLOCK, WARN, LOG, or APPROVE
if result.decision == "BLOCK":
    print(f"Reason: {result.reason}")

# Track agent spend against a daily budget
budget = BudgetManager(daily_limit=10.00, agent_id="agent-alpha")
budget.record_spend(0.05)
print(f"Remaining today: ${budget.remaining:.2f}")

# Write to the append-only audit log
logger = AuditLogger(log_path="audit.jsonl")
logger.log_decision(action_context, result)
```

---

## Key Features

- **`PolicyEngine`** — loads governance policies from YAML and evaluates them against agent action contexts using ten built-in condition operators including `contains_pii`, `matches` (regex), and `greater_than`
- **Five decision actions** — ALLOW, BLOCK, WARN, LOG, and APPROVE; the engine short-circuits on the first BLOCK and accumulates APPROVE policies to drive human-in-the-loop approval queues
- **PII detection and redaction** — regex pattern libraries for US, EU, and India identifiers, plus a `Redactor` that masks sensitive data before it leaves the governance boundary
- **Cost tracking and budget management** — daily/weekly/monthly limits, configurable alerts, and a cost reporter for per-agent spend breakdowns
- **Append-only audit logger** — log rotation, structured search, and exporters for downstream SIEM ingestion
- **Policy template library** — pre-built rule sets for common governance patterns (data residency, cost control, PII handling)
- **Governance dashboard** — `dashboard.api` exposes policy status, audit summaries, and budget utilization over HTTP

---

## Links

- [GitHub Repository](https://github.com/invincible-jha/aumos-cowork-governance)
- [PyPI Package](https://pypi.org/project/aumos-cowork-governance/)
- [Architecture](architecture.md)
- [Changelog](https://github.com/invincible-jha/aumos-cowork-governance/blob/main/CHANGELOG.md)
- [Contributing](https://github.com/invincible-jha/aumos-cowork-governance/blob/main/CONTRIBUTING.md)

---

> Part of the [AumOS](https://github.com/aumos-ai) open-source agent infrastructure portfolio.
