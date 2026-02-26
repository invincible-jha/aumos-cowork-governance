"""Configurable approval gates based on action type, cost, and actor role.

ApprovalGate evaluates whether a proposed action requires human approval by
matching the action type against fnmatch-style patterns and checking cost and
role conditions.  Multiple GateConfig entries can be registered; the most
restrictive match wins.

Example
-------
>>> from aumos_cowork_governance.approval.gates import ApprovalGate, GateConfig
>>> gate = ApprovalGate(gates=[
...     GateConfig(action_patterns=["file_delete*"], require_approval=True),
...     GateConfig(action_patterns=["llm_call"], require_approval=False,
...                auto_approve_below_cost=0.10),
... ])
>>> gate.needs_approval("file_delete_recursive")
True
>>> gate.needs_approval("llm_call", estimated_cost=0.05)
False
>>> gate.needs_approval("llm_call", estimated_cost=0.20)
True
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class GateConfig:
    """Configuration for a single approval gate rule.

    Attributes
    ----------
    action_patterns:
        List of fnmatch-style glob patterns matched against the action type
        (e.g. ``["file_delete*", "shell_exec"]``).
    require_approval:
        When ``True``, matching actions require human approval unless
        overridden by ``auto_approve_below_cost`` or ``required_role``.
    auto_approve_below_cost:
        When > 0, actions with an estimated cost strictly below this
        threshold are auto-approved even if ``require_approval`` is ``True``.
        Set to ``0.0`` (default) to disable automatic cost-based approval.
    required_role:
        When set, only actors with this role bypass approval.  Actors without
        the role must obtain approval even if ``require_approval`` is ``False``.
    """

    action_patterns: list[str]
    require_approval: bool
    auto_approve_below_cost: float = 0.0
    required_role: str | None = None


class ApprovalGate:
    """Evaluates whether an action requires human approval.

    Checks are performed against all registered :class:`GateConfig` entries.
    The first pattern match determines the gate configuration to apply.
    If no pattern matches, the action is considered *not* to require approval
    (allow-by-default behaviour; operators should add explicit BLOCK policies
    for actions that should never be permitted).

    Parameters
    ----------
    gates:
        List of :class:`GateConfig` entries evaluated in declaration order.
    """

    def __init__(self, gates: list[GateConfig] | None = None) -> None:
        self._gates: list[GateConfig] = list(gates or [])

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def add_gate(self, config: GateConfig) -> None:
        """Append a gate configuration to the evaluation list.

        Parameters
        ----------
        config:
            The gate configuration to add.  Evaluated after any previously
            added gates.
        """
        self._gates.append(config)
        logger.debug(
            "Added approval gate for patterns %r (require_approval=%s)",
            config.action_patterns,
            config.require_approval,
        )

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def needs_approval(
        self,
        action_type: str,
        estimated_cost: float = 0.0,
        actor_role: str | None = None,
    ) -> bool:
        """Determine whether ``action_type`` requires human approval.

        Evaluation logic
        ----------------
        1. Iterate gates in order; find the first whose ``action_patterns``
           match ``action_type`` via :func:`fnmatch.fnmatch`.
        2. If no gate matches, return ``False`` (allow by default).
        3. If the gate has ``require_approval=False``:
           - If ``required_role`` is set and ``actor_role`` does not match,
             return ``True`` (actor lacks the bypass role).
           - Otherwise return ``False``.
        4. If the gate has ``require_approval=True``:
           - If ``auto_approve_below_cost > 0`` and
             ``estimated_cost < auto_approve_below_cost``, return ``False``
             (cost is low enough to auto-approve).
           - If ``required_role`` is set and ``actor_role`` matches,
             return ``False`` (role bypasses approval).
           - Otherwise return ``True``.

        Parameters
        ----------
        action_type:
            The action category string to evaluate.
        estimated_cost:
            Estimated cost in USD of the proposed action.
        actor_role:
            Optional role label of the requesting actor.

        Returns
        -------
        bool
            ``True`` when approval is required, ``False`` otherwise.
        """
        matched_gate: GateConfig | None = None

        for gate in self._gates:
            for pattern in gate.action_patterns:
                if fnmatch.fnmatch(action_type, pattern):
                    matched_gate = gate
                    break
            if matched_gate is not None:
                break

        if matched_gate is None:
            logger.debug(
                "No approval gate matched action_type=%r; allowing by default.",
                action_type,
            )
            return False

        gate = matched_gate

        if not gate.require_approval:
            # Gate says no approval needed, unless actor lacks required role.
            if gate.required_role is not None and actor_role != gate.required_role:
                logger.debug(
                    "Action %r matched non-approval gate but actor role %r != required %r; requiring approval.",
                    action_type,
                    actor_role,
                    gate.required_role,
                )
                return True
            return False

        # Gate says approval is required — check escape hatches.

        # Cost-based auto-approval.
        if gate.auto_approve_below_cost > 0.0 and estimated_cost < gate.auto_approve_below_cost:
            logger.debug(
                "Action %r auto-approved: cost $%.4f < threshold $%.4f.",
                action_type,
                estimated_cost,
                gate.auto_approve_below_cost,
            )
            return False

        # Role-based bypass.
        if gate.required_role is not None and actor_role == gate.required_role:
            logger.debug(
                "Action %r approval bypassed: actor role %r matches required role.",
                action_type,
                actor_role,
            )
            return False

        logger.debug(
            "Action %r requires approval (cost=$%.4f, actor_role=%r).",
            action_type,
            estimated_cost,
            actor_role,
        )
        return True

    @property
    def gates(self) -> list[GateConfig]:
        """Read-only snapshot of the current gate configurations."""
        return list(self._gates)
