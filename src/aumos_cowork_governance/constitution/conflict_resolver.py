"""ConflictResolver — detects and resolves conflicts between agent actions.

When multiple agents propose actions simultaneously, they may conflict
(e.g. two agents trying to write to the same resource).  The resolver uses
the constitution's ``conflict_strategy`` to determine an outcome.

Example
-------
>>> from aumos_cowork_governance.constitution.conflict_resolver import (
...     ConflictResolver
... )
>>> resolver = ConflictResolver(constitution)
>>> conflicts = resolver.detect_conflict(actions)
>>> for conflict in conflicts:
...     resolution = resolver.resolve(conflict)
...     print(resolution.resolution)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from aumos_cowork_governance.constitution.enforcer import AgentAction, ActionType
from aumos_cowork_governance.constitution.schema import ConflictStrategy, Constitution

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Conflict:
    """Represents a detected conflict between two or more agents.

    Attributes
    ----------
    agent_a:
        ID of the first agent involved.
    agent_b:
        ID of the second agent involved.
    description:
        Human-readable explanation of what the conflict is.
    conflicting_actions:
        The actions that are in conflict.
    """

    agent_a: str
    agent_b: str
    description: str
    conflicting_actions: list[AgentAction]


@dataclass(frozen=True)
class ConflictResolution:
    """The outcome of applying a resolution strategy to a ``Conflict``.

    Attributes
    ----------
    conflict:
        The ``Conflict`` that was resolved.
    strategy_used:
        Which ``ConflictStrategy`` was applied.
    resolution:
        Human-readable description of the decision.
    winner:
        The agent ID whose action was selected, or ``None`` when no single
        winner was chosen (e.g. consensus with no agreement).
    details:
        Additional strategy-specific context.
    """

    conflict: Conflict
    strategy_used: ConflictStrategy
    resolution: str
    winner: str | None
    details: dict[str, Any]


# ---------------------------------------------------------------------------
# ConflictResolver
# ---------------------------------------------------------------------------


class ConflictResolver:
    """Detects and resolves conflicts between agent actions.

    Parameters
    ----------
    constitution:
        The ``Constitution`` that governs the team.  Its ``roles`` list
        ordering determines priority (index 0 = highest priority).
    """

    def __init__(self, constitution: Constitution) -> None:
        self._constitution = constitution

    # ------------------------------------------------------------------
    # Conflict detection
    # ------------------------------------------------------------------

    def detect_conflict(self, actions: list[AgentAction]) -> list[Conflict]:
        """Scan *actions* for conflicts and return all found ``Conflict`` objects.

        Detection heuristics
        --------------------
        1. **Resource write conflict** — two agents with different roles both
           propose a ``TOOL_CALL`` or ``DATA_ACCESS`` targeting the same
           ``resource`` key in their ``details`` dict.
        2. **Budget conflict** — two agents propose ``BUDGET_SPEND`` actions
           for the same ``budget_key`` (defaults to role name).
        3. **Delegation overlap** — two agents delegate to the same target role.
        4. **Permission overlap** — two agents with different roles both try
           to perform an ``ESCALATION`` action simultaneously.
        """
        conflicts: list[Conflict] = []
        seen_pairs: set[frozenset[int]] = set()

        for i, action_a in enumerate(actions):
            for j, action_b in enumerate(actions):
                if j <= i:
                    continue
                pair_key: frozenset[int] = frozenset({i, j})
                if pair_key in seen_pairs:
                    continue

                conflict = self._check_pair(action_a, action_b)
                if conflict is not None:
                    seen_pairs.add(pair_key)
                    conflicts.append(conflict)

        return conflicts

    def _check_pair(
        self, action_a: AgentAction, action_b: AgentAction
    ) -> Conflict | None:
        """Return a ``Conflict`` if *action_a* and *action_b* conflict, else ``None``."""
        # Agents with the same ID are not in conflict with themselves.
        if action_a.agent_id == action_b.agent_id:
            return None

        # --- Resource write conflict ---
        write_types = {ActionType.TOOL_CALL, ActionType.DATA_ACCESS}
        if action_a.action_type in write_types and action_b.action_type in write_types:
            resource_a = action_a.details.get("resource")
            resource_b = action_b.details.get("resource")
            if resource_a and resource_a == resource_b:
                return Conflict(
                    agent_a=action_a.agent_id,
                    agent_b=action_b.agent_id,
                    description=(
                        f"Resource conflict: both agents targeting resource "
                        f"'{resource_a}'"
                    ),
                    conflicting_actions=[action_a, action_b],
                )

        # --- Budget conflict ---
        if (
            action_a.action_type == ActionType.BUDGET_SPEND
            and action_b.action_type == ActionType.BUDGET_SPEND
        ):
            budget_key_a = action_a.details.get("budget_key", action_a.role)
            budget_key_b = action_b.details.get("budget_key", action_b.role)
            if budget_key_a == budget_key_b:
                return Conflict(
                    agent_a=action_a.agent_id,
                    agent_b=action_b.agent_id,
                    description=(
                        f"Budget conflict: both agents spending from budget "
                        f"'{budget_key_a}'"
                    ),
                    conflicting_actions=[action_a, action_b],
                )

        # --- Delegation overlap ---
        if (
            action_a.action_type == ActionType.DELEGATION
            and action_b.action_type == ActionType.DELEGATION
        ):
            target_a = action_a.details.get("target_role")
            target_b = action_b.details.get("target_role")
            if target_a and target_a == target_b:
                return Conflict(
                    agent_a=action_a.agent_id,
                    agent_b=action_b.agent_id,
                    description=(
                        f"Delegation conflict: both agents delegating to "
                        f"'{target_a}'"
                    ),
                    conflicting_actions=[action_a, action_b],
                )

        # --- Escalation overlap ---
        if (
            action_a.action_type == ActionType.ESCALATION
            and action_b.action_type == ActionType.ESCALATION
        ):
            return Conflict(
                agent_a=action_a.agent_id,
                agent_b=action_b.agent_id,
                description="Escalation conflict: multiple agents escalating simultaneously",
                conflicting_actions=[action_a, action_b],
            )

        return None

    # ------------------------------------------------------------------
    # Resolution dispatch
    # ------------------------------------------------------------------

    def resolve(self, conflict: Conflict) -> ConflictResolution:
        """Apply the constitution's default ``conflict_strategy`` to *conflict*.

        Delegates to the strategy-specific method.
        """
        strategy = self._constitution.conflict_strategy
        if strategy == ConflictStrategy.PRIORITY_BASED:
            return self.resolve_by_priority(conflict)
        if strategy == ConflictStrategy.MOST_RESTRICTIVE:
            return self.resolve_most_restrictive(conflict)
        if strategy == ConflictStrategy.LEADER_DECIDES:
            return self._resolve_leader_decides(conflict)
        # CONSENSUS — attempt to find agreement; fall back to priority.
        return self._resolve_consensus(conflict)

    # ------------------------------------------------------------------
    # Strategy implementations
    # ------------------------------------------------------------------

    def resolve_by_priority(self, conflict: Conflict) -> ConflictResolution:
        """Resolve by role priority (earlier in ``constitution.roles`` = higher).

        When roles have equal priority, the first action (by timestamp) wins.
        When a role is unknown it is assigned the lowest priority.
        """
        role_priority = self._role_priority_map()

        def sort_key(action: AgentAction) -> tuple[int, float]:
            priority = role_priority.get(action.role, len(self._constitution.roles))
            ts = action.timestamp.timestamp()
            return (priority, ts)

        sorted_actions = sorted(conflict.conflicting_actions, key=sort_key)
        winner_action = sorted_actions[0]
        loser_actions = sorted_actions[1:]

        details: dict[str, Any] = {
            "role_priorities": {
                action.agent_id: role_priority.get(action.role, len(self._constitution.roles))
                for action in conflict.conflicting_actions
            },
            "winner_role": winner_action.role,
            "loser_agents": [a.agent_id for a in loser_actions],
        }

        return ConflictResolution(
            conflict=conflict,
            strategy_used=ConflictStrategy.PRIORITY_BASED,
            resolution=(
                f"Agent '{winner_action.agent_id}' (role '{winner_action.role}') "
                f"wins by priority."
            ),
            winner=winner_action.agent_id,
            details=details,
        )

    def resolve_most_restrictive(self, conflict: Conflict) -> ConflictResolution:
        """Resolve by choosing the most restrictive (smallest budget / fewest permissions) action.

        Restrictiveness is measured by:
        1. The number of permissions on the role (fewer = more restrictive).
        2. The budget cap (lower = more restrictive; ``None`` treated as infinity).
        3. Tie-break: alphabetical order of agent_id.
        """
        def restrictiveness_key(action: AgentAction) -> tuple[int, float, str]:
            role_def = self._constitution.get_role(action.role)
            if role_def is None:
                # Unknown roles are treated as most restrictive.
                return (0, 0.0, action.agent_id)
            permission_count = len(role_def.permissions)
            budget = role_def.max_budget_usd if role_def.max_budget_usd is not None else float("inf")
            return (permission_count, budget, action.agent_id)

        sorted_actions = sorted(conflict.conflicting_actions, key=restrictiveness_key)
        winner_action = sorted_actions[0]

        details: dict[str, Any] = {
            "restrictiveness_scores": {
                action.agent_id: restrictiveness_key(action)
                for action in conflict.conflicting_actions
            },
        }

        return ConflictResolution(
            conflict=conflict,
            strategy_used=ConflictStrategy.MOST_RESTRICTIVE,
            resolution=(
                f"Most restrictive action by agent '{winner_action.agent_id}' "
                f"(role '{winner_action.role}') selected."
            ),
            winner=winner_action.agent_id,
            details=details,
        )

    def _resolve_leader_decides(self, conflict: Conflict) -> ConflictResolution:
        """Resolve by deferring to the highest-priority role (the 'leader').

        The leader is the role at index 0 in ``constitution.roles``.  If an
        agent in the conflict holds the leader role, that agent wins.
        Otherwise falls back to priority-based resolution.
        """
        if not self._constitution.roles:
            return self.resolve_by_priority(conflict)

        leader_role = self._constitution.roles[0].name
        for action in conflict.conflicting_actions:
            if action.role == leader_role:
                return ConflictResolution(
                    conflict=conflict,
                    strategy_used=ConflictStrategy.LEADER_DECIDES,
                    resolution=(
                        f"Leader agent '{action.agent_id}' (role '{leader_role}') decides."
                    ),
                    winner=action.agent_id,
                    details={"leader_role": leader_role},
                )

        # No leader in the conflict — fall back to priority.
        fallback = self.resolve_by_priority(conflict)
        return ConflictResolution(
            conflict=conflict,
            strategy_used=ConflictStrategy.LEADER_DECIDES,
            resolution=(
                f"No leader in conflict. Fell back to priority. "
                f"Winner: '{fallback.winner}'."
            ),
            winner=fallback.winner,
            details={"leader_role": leader_role, "fallback": "priority_based"},
        )

    def _resolve_consensus(self, conflict: Conflict) -> ConflictResolution:
        """Attempt consensus: if all agents propose the same action type, agree.

        When actions differ, falls back to ``PRIORITY_BASED``.
        """
        action_types = {action.action_type for action in conflict.conflicting_actions}
        if len(action_types) == 1:
            # All agents agree on the action type; pick the earliest timestamp.
            earliest = min(
                conflict.conflicting_actions, key=lambda a: a.timestamp
            )
            return ConflictResolution(
                conflict=conflict,
                strategy_used=ConflictStrategy.CONSENSUS,
                resolution=(
                    f"Consensus reached: all agents agree on action type "
                    f"'{list(action_types)[0].value}'. "
                    f"Agent '{earliest.agent_id}' proceeds first."
                ),
                winner=earliest.agent_id,
                details={"consensus_action_type": list(action_types)[0].value},
            )

        # No consensus — fall back to priority.
        fallback = self.resolve_by_priority(conflict)
        return ConflictResolution(
            conflict=conflict,
            strategy_used=ConflictStrategy.CONSENSUS,
            resolution=(
                f"No consensus reached (different action types). "
                f"Fell back to priority. Winner: '{fallback.winner}'."
            ),
            winner=fallback.winner,
            details={
                "action_types_seen": [t.value for t in sorted(action_types, key=lambda x: x.value)],
                "fallback": "priority_based",
            },
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _role_priority_map(self) -> dict[str, int]:
        """Return a mapping of role name -> priority index (0 = highest)."""
        return {role.name: idx for idx, role in enumerate(self._constitution.roles)}
