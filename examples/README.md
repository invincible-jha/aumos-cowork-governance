# Examples

| # | Example | Description |
|---|---------|-------------|
| 01 | [Quickstart](01_quickstart.py) | Define a policy, evaluate actions, and audit results |
| 02 | [Policy Engine](02_policy_engine.py) | Load templates, parse policies, handle blocked actions |
| 03 | [PII Detection](03_pii_detection.py) | Detect, redact PII, and classify file sensitivity |
| 04 | [Approval Workflows](04_approval_workflows.py) | Approval queue, gate decisions, multi-step workflows |
| 05 | [Constitution and Voting](05_constitution_voting.py) | Multi-agent constitution enforcement and conflict voting |
| 06 | [Cost and Budget](06_cost_budget.py) | Track agent costs, manage budgets, enforce cost limits |
| 07 | [LangChain Governance](07_langchain_governance.py) | Gate LangChain tool calls with policy engine and auditing |

## Running the examples

```bash
pip install aumos-cowork-governance
python examples/01_quickstart.py
```

For framework integrations:

```bash
pip install langchain   # for example 07
```
