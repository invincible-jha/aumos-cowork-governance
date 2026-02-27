"""Constitution package — multi-agent governance framework.

Provides schema definitions, enforcement logic, and conflict resolution
for multi-agent team constitutions.

Public API
----------
- ``Constitution`` — top-level governance document for a team
- ``RoleDefinition`` — capabilities and budget limits for an agent role
- ``Constraint`` — parameterised rule applied to roles
- ``EscalationRule`` — trigger-based escalation between roles
- ``Permission`` — granular permission enum
- ``ConflictStrategy`` — strategy for resolving agent disagreements
- ``ConstitutionEnforcer`` — checks agent actions against the constitution
- ``ConflictResolver`` — detects and resolves conflicts between agents

Example
-------
>>> from aumos_cowork_governance.constitution import Constitution, ConstitutionEnforcer
>>> constitution = Constitution.from_yaml(yaml_text)
>>> enforcer = ConstitutionEnforcer(constitution)
>>> result = enforcer.evaluate(action)
>>> result.allowed
True
"""
from __future__ import annotations

from aumos_cowork_governance.constitution.schema import (
    ConflictStrategy,
    Constitution,
    Constraint,
    EscalationRule,
    Permission,
    RoleDefinition,
)
from aumos_cowork_governance.constitution.enforcer import (
    ActionType,
    AgentAction,
    ConstitutionEnforcer,
    EnforcementResult,
)
from aumos_cowork_governance.constitution.conflict_resolver import (
    Conflict,
    ConflictResolution,
    ConflictResolver,
)

__all__ = [
    # Schema
    "ConflictStrategy",
    "Constitution",
    "Constraint",
    "EscalationRule",
    "Permission",
    "RoleDefinition",
    # Enforcer
    "ActionType",
    "AgentAction",
    "ConstitutionEnforcer",
    "EnforcementResult",
    # Conflict resolver
    "Conflict",
    "ConflictResolution",
    "ConflictResolver",
]
