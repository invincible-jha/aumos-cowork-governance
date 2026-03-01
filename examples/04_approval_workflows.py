#!/usr/bin/env python3
"""Example: Approval Workflows

Demonstrates the approval queue, gate decisions, and multi-step
approval workflows for sensitive agent actions.

Usage:
    python examples/04_approval_workflows.py

Requirements:
    pip install aumos-cowork-governance
"""
from __future__ import annotations

import aumos_cowork_governance as gov
from aumos_cowork_governance import (
    ApprovalGate,
    ApprovalOutcome,
    ApprovalQueue,
    ApprovalRequest,
    ApprovalStatus,
    ApprovalWorkflow,
)


def main() -> None:
    print(f"aumos-cowork-governance version: {gov.__version__}")

    # Step 1: Create approval queue and submit requests
    queue = ApprovalQueue()
    requests = [
        ApprovalRequest(
            request_id="req-001",
            agent_id="analysis-agent",
            action="file_delete",
            context={"path": "/data/sensitive/report.pdf"},
            urgency="high",
        ),
        ApprovalRequest(
            request_id="req-002",
            agent_id="finance-agent",
            action="external_transfer",
            context={"amount_usd": 5000, "recipient": "vendor-bank"},
            urgency="normal",
        ),
        ApprovalRequest(
            request_id="req-003",
            agent_id="admin-agent",
            action="user_delete",
            context={"user_id": "user-xyz"},
            urgency="low",
        ),
    ]

    for req in requests:
        queue.enqueue(req)
    print(f"Approval queue: {queue.depth()} pending requests")

    # Step 2: Approval gate — auto-approve/deny based on rules
    gate = ApprovalGate(auto_approve_low_risk=True)
    print("\nApproval gate decisions:")
    while not queue.empty():
        req = queue.dequeue()
        outcome: ApprovalOutcome = gate.decide(req)
        print(f"  [req-{req.request_id}] action={req.action} -> "
              f"{outcome.status.value}")
        if outcome.reason:
            print(f"    Reason: {outcome.reason[:60]}")

    # Step 3: Multi-step approval workflow
    workflow = ApprovalWorkflow(steps=[
        {"step": "risk-assessment", "handler": "risk-scorer"},
        {"step": "manager-review", "handler": "human-manager"},
        {"step": "security-sign-off", "handler": "security-team"},
    ])
    sensitive_req = ApprovalRequest(
        request_id="req-sensitive-001",
        agent_id="deployment-agent",
        action="production_deploy",
        context={"service": "payment-gateway", "version": "v2.1.0"},
        urgency="high",
    )
    workflow_result = workflow.process(sensitive_req)
    print(f"\nWorkflow for '{sensitive_req.action}':")
    print(f"  Steps: {len(workflow_result.step_results)}")
    for step_result in workflow_result.step_results:
        print(f"  [{step_result.step}] status={step_result.status.value}")
    print(f"  Final: {workflow_result.final_status.value}")


if __name__ == "__main__":
    main()
