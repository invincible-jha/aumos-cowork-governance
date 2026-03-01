#!/usr/bin/env python3
"""Example: LangChain Governance Integration

Demonstrates applying cowork governance policies as a gate before
LangChain tool calls and tracking costs.

Usage:
    python examples/07_langchain_governance.py

Requirements:
    pip install aumos-cowork-governance
    pip install langchain   # optional — example degrades gracefully
"""
from __future__ import annotations

import aumos_cowork_governance as gov
from aumos_cowork_governance import (
    AuditLogger,
    CostTracker,
    PolicyBlockedError,
    PolicyEngine,
    UsageRecord,
)

try:
    from langchain.schema.runnable import RunnableLambda
    _LANGCHAIN_AVAILABLE = True
except ImportError:
    _LANGCHAIN_AVAILABLE = False


def governed_tool_call(
    engine: PolicyEngine,
    logger: AuditLogger,
    tracker: CostTracker,
    agent_id: str,
    action: str,
    context: dict[str, object],
) -> str:
    """Evaluate policy, log, track cost, then run the tool."""
    result = engine.evaluate(context)
    logger.log(action=action, context=context, result=result)

    if not result.allowed:
        raise PolicyBlockedError(
            f"Action '{action}' blocked by policy '{result.policy_id}'"
        )

    # Simulate tool execution cost
    tracker.record(UsageRecord(
        agent_id=agent_id,
        model="gpt-4o",
        tokens_used=200,
        cost_usd=0.002,
    ))
    return f"[{agent_id}] executed '{action}' successfully"


def main() -> None:
    print(f"aumos-cowork-governance version: {gov.__version__}")

    if not _LANGCHAIN_AVAILABLE:
        print("LangChain not installed — demonstrating governance layer only.")
        print("Install with: pip install langchain")

    # Set up governance
    engine = PolicyEngine()
    engine.load_from_dict({
        "policies": [
            {
                "id": "block-external-http",
                "condition": {"action": "http_request",
                              "url_pattern": "^(?!https://internal\\.)"},
                "effect": "deny",
            }
        ]
    })
    logger = AuditLogger()
    tracker = CostTracker()

    # Tool calls to govern
    tool_calls = [
        {
            "agent_id": "langchain-agent",
            "action": "http_request",
            "context": {"action": "http_request", "url": "https://internal.api/data"},
        },
        {
            "agent_id": "langchain-agent",
            "action": "http_request",
            "context": {"action": "http_request", "url": "https://external.site.com"},
        },
        {
            "agent_id": "langchain-agent",
            "action": "db_query",
            "context": {"action": "db_query", "table": "users"},
        },
    ]

    print("\nGoverned tool calls:")
    for call in tool_calls:
        try:
            output = governed_tool_call(
                engine=engine,
                logger=logger,
                tracker=tracker,
                agent_id=str(call["agent_id"]),
                action=str(call["action"]),
                context=dict(call["context"]),  # type: ignore[arg-type]
            )
            print(f"  [OK] {output}")
        except PolicyBlockedError as error:
            print(f"  [BLOCKED] {error}")

    # Summarise
    audit_entries = logger.get_all()
    print(f"\nAudit entries: {len(audit_entries)}")
    summary = tracker.summary(agent_id="langchain-agent")
    print(f"Total cost: ${summary.total_cost_usd:.4f} "
          f"({summary.total_calls} calls)")


if __name__ == "__main__":
    main()
