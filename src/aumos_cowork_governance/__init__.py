"""aumos-cowork-governance — Governance plugin for multi-agent collaboration environments.

Public API
----------
The stable public surface is everything exported from this module.
Anything inside submodules not re-exported here is considered private
and may change without notice.

Example
-------
>>> import aumos_cowork_governance as gov
>>> gov.__version__
'0.1.0'
>>> engine = gov.PolicyEngine()
>>> engine.load_from_dict({"policies": []})
>>> result = engine.evaluate({"action": "file_read", "path": "/tmp/data.csv"})
>>> result.allowed
True
"""
from __future__ import annotations

__version__: str = "0.1.0"

from aumos_cowork_governance.convenience import CoworkGovernor

# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
from aumos_cowork_governance.policies.engine import (
    EvaluationResult,
    PolicyAction,
    PolicyEngine,
    PolicyResult,
)
from aumos_cowork_governance.policies.evaluator import RuleEvaluator
from aumos_cowork_governance.policies.actions import PolicyActionHandler, PolicyBlockedError
from aumos_cowork_governance.policies.parser import PolicyParser

# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------
from aumos_cowork_governance.audit.logger import AuditLogger
from aumos_cowork_governance.audit.rotator import LogRotator
from aumos_cowork_governance.audit.search import AuditSearch
from aumos_cowork_governance.audit.exporter import AuditExporter

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
from aumos_cowork_governance.detection.pii_detector import PiiDetector, PiiMatch
from aumos_cowork_governance.detection.classifier import FileClassifier, SensitivityLevel
from aumos_cowork_governance.detection.compliance_checker import (
    ComplianceChecker,
    ComplianceResult,
    ComplianceViolation,
)
from aumos_cowork_governance.detection.redactor import PiiRedactor

# ---------------------------------------------------------------------------
# Cost
# ---------------------------------------------------------------------------
from aumos_cowork_governance.cost.tracker import CostTracker, UsageRecord
from aumos_cowork_governance.cost.budget import BudgetManager, BudgetStatus
from aumos_cowork_governance.cost.limiter import CostLimiter, CostLimitResult, CostRecord

# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------
from aumos_cowork_governance.approval.queue import (
    ApprovalQueue,
    ApprovalRequest,
    ApprovalStatus,
)
from aumos_cowork_governance.approval.gate import ApprovalGate, ApprovalOutcome
from aumos_cowork_governance.approval.workflow import ApprovalWorkflow
from aumos_cowork_governance.approval.gates import GateConfig
from aumos_cowork_governance.approval.gates import ApprovalGate as ApprovalGateV2

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
from aumos_cowork_governance.dashboard.renderer import DashboardRenderer, DashboardData

# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
from aumos_cowork_governance.templates.policy_templates import (
    get_template,
    list_templates,
    write_template,
)

__all__ = [
    "__version__",
    "CoworkGovernor",
    # Policies
    "EvaluationResult",
    "PolicyAction",
    "PolicyActionHandler",
    "PolicyBlockedError",
    "PolicyEngine",
    "PolicyParser",
    "PolicyResult",
    "RuleEvaluator",
    # Audit
    "AuditExporter",
    "AuditLogger",
    "AuditSearch",
    "LogRotator",
    # Detection
    "ComplianceChecker",
    "ComplianceResult",
    "ComplianceViolation",
    "FileClassifier",
    "PiiDetector",
    "PiiMatch",
    "PiiRedactor",
    "SensitivityLevel",
    # Cost
    "BudgetManager",
    "BudgetStatus",
    "CostLimitResult",
    "CostLimiter",
    "CostRecord",
    "CostTracker",
    "UsageRecord",
    # Approval
    "ApprovalGate",
    "ApprovalGateV2",
    "ApprovalOutcome",
    "ApprovalQueue",
    "ApprovalRequest",
    "ApprovalStatus",
    "ApprovalWorkflow",
    "GateConfig",
    # Dashboard
    "DashboardData",
    "DashboardRenderer",
    # Templates
    "get_template",
    "list_templates",
    "write_template",
]
