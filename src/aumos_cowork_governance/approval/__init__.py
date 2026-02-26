"""Human approval gate package for aumos-cowork-governance.

Provides middleware for pausing agent execution pending human review,
notification delivery, timeout handling, an in-memory approval queue,
a configurable approval workflow with lifecycle management, and pattern-
based approval gates.
"""
from __future__ import annotations

from aumos_cowork_governance.approval.gate import ApprovalGate, ApprovalOutcome
from aumos_cowork_governance.approval.gates import GateConfig
from aumos_cowork_governance.approval.gates import ApprovalGate as ApprovalGateV2
from aumos_cowork_governance.approval.notifier import ApprovalNotifier
from aumos_cowork_governance.approval.queue import ApprovalQueue, ApprovalRequest, ApprovalStatus
from aumos_cowork_governance.approval.timeout import TimeoutHandler
from aumos_cowork_governance.approval.workflow import (
    ApprovalRequest as ApprovalWorkflowRequest,
    ApprovalStatus as ApprovalWorkflowStatus,
    ApprovalWorkflow,
)

__all__ = [
    "ApprovalGate",
    "ApprovalGateV2",
    "ApprovalNotifier",
    "ApprovalOutcome",
    "ApprovalQueue",
    "ApprovalRequest",
    "ApprovalStatus",
    "ApprovalWorkflow",
    "ApprovalWorkflowRequest",
    "ApprovalWorkflowStatus",
    "GateConfig",
    "TimeoutHandler",
]
