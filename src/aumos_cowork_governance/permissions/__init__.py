"""Action-level permission system for cowork governance (E8.1).

Provides a PermissionMatrix that maps (action, resource_path) pairs to
PermissionResult outcomes (allowed/denied) using composable constraints.

Example
-------
::

    from aumos_cowork_governance.permissions import PermissionMatrix, PermissionResult
    from aumos_cowork_governance.permissions.action_permission import ActionType

    matrix = PermissionMatrix.from_rules([
        {
            "action": "file_read",
            "allow": True,
            "constraints": [{"type": "region", "allowed_paths": ["/workspace"]}],
        }
    ])
    result = matrix.check("file_read", "/workspace/notes.txt")
    assert result.allowed
"""
from __future__ import annotations

from aumos_cowork_governance.permissions.action_permission import (
    ActionType,
    PermissionMatrix,
    PermissionResult,
    PermissionRule,
)
from aumos_cowork_governance.permissions.constraint_evaluator import (
    ConstraintEvaluator,
    GlobPatternConstraint,
    RegexPatternConstraint,
    RegionConstraint,
    SizeLimitConstraint,
    TimeWindowConstraint,
)
from aumos_cowork_governance.permissions.permission_loader import (
    PermissionConfigError,
    PermissionLoader,
)

__all__ = [
    # Core types
    "ActionType",
    "PermissionMatrix",
    "PermissionResult",
    "PermissionRule",
    # Constraint evaluators
    "ConstraintEvaluator",
    "GlobPatternConstraint",
    "RegexPatternConstraint",
    "RegionConstraint",
    "SizeLimitConstraint",
    "TimeWindowConstraint",
    # Loader
    "PermissionConfigError",
    "PermissionLoader",
]
