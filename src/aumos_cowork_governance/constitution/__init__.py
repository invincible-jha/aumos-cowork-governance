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
- ``VotingMethod`` — voting algorithm enum (majority / weighted / supermajority)
- ``VotingConfig`` — configuration for consensus voting mechanics
- ``Vote`` — a single cast vote from one participant
- ``VoteResult`` — outcome of tallying a collection of votes
- ``MajorityVote`` — simple majority voting mechanism
- ``WeightedVote`` — weight-based voting mechanism
- ``SupermajorityVote`` — supermajority threshold voting mechanism
- ``get_mechanism`` — factory for selecting the correct voting mechanism
- ``DeliberationEngine`` — multi-round deliberation with elimination
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
    VotingConfig,
    VotingMethod,
)
from aumos_cowork_governance.constitution.voting import (
    Vote,
    VoteResult,
    MajorityVote,
    WeightedVote,
    SupermajorityVote,
    get_mechanism,
)
from aumos_cowork_governance.constitution.deliberation import DeliberationEngine
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
    "VotingConfig",
    "VotingMethod",
    # Voting
    "Vote",
    "VoteResult",
    "MajorityVote",
    "WeightedVote",
    "SupermajorityVote",
    "get_mechanism",
    # Deliberation
    "DeliberationEngine",
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
