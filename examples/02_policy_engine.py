#!/usr/bin/env python3
"""Example: Policy Engine and Templates

Demonstrates loading policies from templates, evaluating complex
conditions, and using the policy action handler.

Usage:
    python examples/02_policy_engine.py

Requirements:
    pip install aumos-cowork-governance
"""
from __future__ import annotations

import aumos_cowork_governance as gov
from aumos_cowork_governance import (
    PolicyBlockedError,
    PolicyEngine,
    PolicyParser,
    get_template,
    list_templates,
)


def main() -> None:
    print(f"aumos-cowork-governance version: {gov.__version__}")

    # Step 1: List available policy templates
    templates = list_templates()
    print(f"Policy templates available ({len(templates)}):")
    for tmpl in templates:
        print(f"  {tmpl}")

    # Step 2: Load a template and inspect
    if templates:
        tmpl_name = templates[0]
        template = get_template(tmpl_name)
        print(f"\nTemplate '{tmpl_name}':")
        print(f"  {str(template)[:200]}")

    # Step 3: Parse policy from YAML-like dict
    parser = PolicyParser()
    policy_dict = {
        "version": "1.0",
        "policies": [
            {
                "id": "block-external-calls",
                "description": "Block HTTP to non-allowlisted domains.",
                "condition": {
                    "action": "http_request",
                    "url_pattern": "^(?!https://api\\.internal\\.)",
                },
                "effect": "deny",
                "message": "External HTTP calls require approval.",
            },
            {
                "id": "allow-internal-db",
                "description": "Allow internal database reads.",
                "condition": {"action": "db_read", "database": "internal"},
                "effect": "allow",
            },
        ]
    }
    parsed = parser.parse(policy_dict)
    print(f"\nParsed {len(parsed)} policies")

    # Step 4: Build engine and evaluate
    engine = PolicyEngine()
    for policy in parsed:
        engine.add_policy(policy)

    test_actions = [
        {"action": "http_request", "url": "https://external.site.com/data"},
        {"action": "http_request", "url": "https://api.internal.example.com/v1"},
        {"action": "db_read", "database": "internal", "table": "users"},
    ]

    print("\nPolicy evaluation:")
    handler = gov.PolicyActionHandler()
    for action_ctx in test_actions:
        result = engine.evaluate(action_ctx)
        try:
            handler.handle(result, context=action_ctx)
            print(f"  [ALLOW] {action_ctx['action']}: {str(action_ctx)[:50]}")
        except PolicyBlockedError as error:
            print(f"  [DENY] {action_ctx['action']}: {error}")


if __name__ == "__main__":
    main()
