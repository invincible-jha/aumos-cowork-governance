#!/usr/bin/env python3
"""Example: Quickstart — aumos-cowork-governance

Minimal working example: define a policy, evaluate agent actions,
and audit the results.

Usage:
    python examples/01_quickstart.py

Requirements:
    pip install aumos-cowork-governance
"""
from __future__ import annotations

import aumos_cowork_governance as gov


def main() -> None:
    print(f"aumos-cowork-governance version: {gov.__version__}")

    # Step 1: Create policy engine and load a policy
    engine = gov.PolicyEngine()
    engine.load_from_dict({
        "policies": [
            {
                "id": "no-sensitive-read",
                "description": "Block reading sensitive files.",
                "condition": {
                    "action": "file_read",
                    "path_pattern": "/sensitive/.*",
                },
                "effect": "deny",
            }
        ]
    })
    print(f"Policy engine ready: {engine.count()} policies loaded")

    # Step 2: Evaluate agent actions
    actions = [
        {"action": "file_read", "path": "/tmp/data.csv"},
        {"action": "file_read", "path": "/sensitive/credentials.json"},
        {"action": "http_request", "url": "https://api.example.com"},
    ]

    print("\nPolicy evaluation:")
    for action_ctx in actions:
        result = engine.evaluate(action_ctx)
        icon = "ALLOW" if result.allowed else "DENY"
        print(f"  [{icon}] {action_ctx}")
        if not result.allowed and result.policy_id:
            print(f"    Triggered by policy: {result.policy_id}")

    # Step 3: Audit actions
    audit_logger = gov.AuditLogger()
    for action_ctx in actions:
        result = engine.evaluate(action_ctx)
        audit_logger.log(
            action=str(action_ctx.get("action")),
            context=action_ctx,
            result=result,
        )

    entries = audit_logger.get_all()
    print(f"\nAudit log: {len(entries)} entries")
    for entry in entries:
        print(f"  [{entry.allowed}] {entry.action} | policy={entry.policy_id}")


if __name__ == "__main__":
    main()
