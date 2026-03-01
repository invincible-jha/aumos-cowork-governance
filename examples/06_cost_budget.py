#!/usr/bin/env python3
"""Example: Cost Tracking and Budget Management

Demonstrates tracking agent usage costs, managing budgets per
agent or workspace, and enforcing cost limits.

Usage:
    python examples/06_cost_budget.py

Requirements:
    pip install aumos-cowork-governance
"""
from __future__ import annotations

import aumos_cowork_governance as gov
from aumos_cowork_governance import (
    BudgetManager,
    BudgetStatus,
    CostLimiter,
    CostRecord,
    CostTracker,
    UsageRecord,
)


def main() -> None:
    print(f"aumos-cowork-governance version: {gov.__version__}")

    # Step 1: Track costs across multiple agents
    tracker = CostTracker()
    usage_records = [
        UsageRecord(agent_id="agent-nlp", model="gpt-4o",
                    tokens_used=1500, cost_usd=0.015),
        UsageRecord(agent_id="agent-nlp", model="gpt-4o",
                    tokens_used=2000, cost_usd=0.020),
        UsageRecord(agent_id="agent-code", model="claude-3-sonnet",
                    tokens_used=800, cost_usd=0.008),
        UsageRecord(agent_id="agent-analyst", model="gpt-4o-mini",
                    tokens_used=5000, cost_usd=0.005),
    ]
    for record in usage_records:
        tracker.record(record)

    print("Cost summary per agent:")
    for agent_id in ["agent-nlp", "agent-code", "agent-analyst"]:
        summary = tracker.summary(agent_id=agent_id)
        print(f"  {agent_id}: "
              f"calls={summary.total_calls}, "
              f"tokens={summary.total_tokens:,}, "
              f"cost=${summary.total_cost_usd:.4f}")

    # Step 2: Manage budgets
    budget_manager = BudgetManager()
    budget_manager.set_budget(agent_id="agent-nlp", limit_usd=0.050)
    budget_manager.set_budget(agent_id="agent-code", limit_usd=0.020)
    budget_manager.set_budget(agent_id="agent-analyst", limit_usd=0.010)

    budget_manager.record_spend(agent_id="agent-nlp", amount_usd=0.035)
    budget_manager.record_spend(agent_id="agent-code", amount_usd=0.008)
    budget_manager.record_spend(agent_id="agent-analyst", amount_usd=0.009)

    print("\nBudget status:")
    for agent_id in ["agent-nlp", "agent-code", "agent-analyst"]:
        status: BudgetStatus = budget_manager.status(agent_id)
        used_pct = status.used_usd / status.limit_usd * 100
        print(f"  {agent_id}: ${status.used_usd:.3f} / "
              f"${status.limit_usd:.3f} ({used_pct:.0f}%)")
        if status.over_budget:
            print(f"    WARNING: over budget by ${status.overage_usd:.4f}")

    # Step 3: Cost limiter enforcement
    limiter = CostLimiter(limit_usd=0.010)
    calls = [
        CostRecord(action="llm-call", estimated_cost_usd=0.003),
        CostRecord(action="llm-call", estimated_cost_usd=0.004),
        CostRecord(action="llm-call", estimated_cost_usd=0.005),  # should be blocked
    ]

    print("\nCost limiter enforcement:")
    for record in calls:
        result = limiter.check(record)
        icon = "ALLOW" if result.allowed else "DENY"
        print(f"  [{icon}] {record.action} ${record.estimated_cost_usd:.3f} "
              f"(cumulative=${limiter.total_spent():.3f})")
        if result.allowed:
            limiter.record(record)


if __name__ == "__main__":
    main()
