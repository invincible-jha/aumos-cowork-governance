"""Shared bootstrap for aumos-cowork-governance benchmarks."""
from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent
_SRC = _REPO_ROOT / "src"
_BENCHMARKS = _REPO_ROOT / "benchmarks"

for _path in [str(_SRC), str(_BENCHMARKS)]:
    if _path not in sys.path:
        sys.path.insert(0, _path)

from aumos_cowork_governance.constitution.enforcer import (
    ActionType,
    AgentAction,
    ConstitutionEnforcer,
)
from aumos_cowork_governance.constitution.schema import (
    ConflictStrategy,
    Constitution,
    Permission,
    RoleDefinition,
    VotingConfig,
    VotingMethod,
)
from aumos_cowork_governance.constitution.voting import MajorityVote, Vote

__all__ = [
    "ActionType",
    "AgentAction",
    "ConstitutionEnforcer",
    "ConflictStrategy",
    "Constitution",
    "Permission",
    "RoleDefinition",
    "VotingConfig",
    "VotingMethod",
    "MajorityVote",
    "Vote",
]
