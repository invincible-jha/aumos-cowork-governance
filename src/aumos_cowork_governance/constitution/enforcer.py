"""ConstitutionEnforcer — runtime enforcement of multi-agent constitutions.

The enforcer is the runtime component that decides whether a given
``AgentAction`` is allowed under the team's ``Constitution``.  It checks:

- Role permissions
- Tool access (allowed/denied patterns using ``fnmatch``)
- Budget limits
- Required approvals for sensitive actions

Example
-------
>>> from aumos_cowork_governance.constitution.enforcer import (
...     ConstitutionEnforcer, AgentAction, ActionType
... )
>>> from datetime import datetime, timezone
>>> action = AgentAction(
...     agent_id="agent-1",
...     role="worker",
...     action_type=ActionType.TOOL_CALL,
...     details={"tool_name": "read_file"},
...     timestamp=datetime.now(tz=timezone.utc),
... )
>>> enforcer = ConstitutionEnforcer(constitution)
>>> result = enforcer.evaluate(action)
>>> result.allowed
True
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aumos_cowork_governance.constitution.schema import Constitution, Permission

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums and value objects
# ---------------------------------------------------------------------------


class ActionType(str, Enum):
    """Classifies the kind of action an agent wants to perform."""

    TOOL_CALL = "tool_call"
    BUDGET_SPEND = "budget_spend"
    DELEGATION = "delegation"
    DATA_ACCESS = "data_access"
    ESCALATION = "escalation"


@dataclass(frozen=True)
class AgentAction:
    """Represents a single action proposed by an agent.

    Attributes
    ----------
    agent_id:
        Unique identifier of the agent proposing this action.
    role:
        The role the agent is acting under (must match a ``RoleDefinition.name``).
    action_type:
        Category of the action.
    details:
        Arbitrary key/value pairs providing action-specific context.
        For ``TOOL_CALL`` include ``{"tool_name": "..."}``.
        For ``BUDGET_SPEND`` include ``{"amount_usd": 42.0}``.
        For ``DELEGATION`` include ``{"target_role": "..."}``.
    timestamp:
        UTC timestamp when the action was proposed.
    """

    agent_id: str
    role: str
    action_type: ActionType
    details: dict[str, object]
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )


@dataclass(frozen=True)
class EnforcementResult:
    """Outcome of evaluating an ``AgentAction`` against the constitution.

    Attributes
    ----------
    allowed:
        ``True`` when the action may proceed.
    action:
        The ``AgentAction`` that was evaluated.
    violations:
        List of constraint/permission violation descriptions.  Non-empty
        only when ``allowed`` is ``False``.
    warnings:
        Non-blocking issues (e.g. approaching budget limit).
    applied_constraints:
        Names of constraints that were checked during this evaluation.
    """

    allowed: bool
    action: AgentAction
    violations: list[str]
    warnings: list[str]
    applied_constraints: list[str]


# ---------------------------------------------------------------------------
# ConstitutionEnforcer
# ---------------------------------------------------------------------------


class ConstitutionEnforcer:
    """Evaluates agent actions against a loaded ``Constitution``.

    Parameters
    ----------
    constitution:
        The ``Constitution`` instance to enforce.

    Notes
    -----
    The enforcer keeps an in-memory audit log accessible via the
    ``audit_log`` property.  This is intentionally lightweight; for
    persistent storage use ``AuditLogger`` from the audit module.
    """

    def __init__(self, constitution: "Constitution") -> None:
        from aumos_cowork_governance.constitution.schema import Constitution

        if not isinstance(constitution, Constitution):
            raise TypeError(f"Expected Constitution, got {type(constitution).__name__}")
        self._constitution = constitution
        self._audit: list[EnforcementResult] = []

    # ------------------------------------------------------------------
    # Public evaluation entry point
    # ------------------------------------------------------------------

    def evaluate(self, action: AgentAction) -> EnforcementResult:
        """Check *action* against the constitution and return an ``EnforcementResult``.

        The evaluation order is:
        1. Verify the role exists.
        2. Check role-level permissions for the action type.
        3. Check tool access (for ``TOOL_CALL`` actions).
        4. Check budget (for ``BUDGET_SPEND`` actions).
        5. Check delegation target validity (for ``DELEGATION`` actions).
        6. Apply matching constraints.

        Any ``critical`` or ``error`` constraint violation sets ``allowed=False``.
        ``warning``-severity violations appear in ``warnings`` but do not block.
        """
        violations: list[str] = []
        warnings: list[str] = []
        applied_constraints: list[str] = []

        role_definition = self._constitution.get_role(action.role)
        if role_definition is None:
            violations.append(f"Unknown role: '{action.role}'")
            result = EnforcementResult(
                allowed=False,
                action=action,
                violations=violations,
                warnings=warnings,
                applied_constraints=applied_constraints,
            )
            self._audit.append(result)
            return result

        # --- Permission check ---
        required_permission = self._permission_for_action_type(action.action_type)
        if required_permission is not None:
            if not self.check_permission(action.role, required_permission):
                violations.append(
                    f"Role '{action.role}' lacks permission '{required_permission.value}'"
                )

        # --- Tool access check ---
        if action.action_type == ActionType.TOOL_CALL:
            tool_name = str(action.details.get("tool_name", ""))
            if tool_name and not self.check_tool_access(action.role, tool_name):
                violations.append(
                    f"Role '{action.role}' is not permitted to call tool '{tool_name}'"
                )

        # --- Budget check ---
        if action.action_type == ActionType.BUDGET_SPEND:
            amount_raw = action.details.get("amount_usd", 0.0)
            try:
                amount = float(amount_raw)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                amount = 0.0
            if not self.check_budget(action.role, amount):
                violations.append(
                    f"Role '{action.role}' budget exceeded: requested ${amount:.4f} "
                    f"exceeds max_budget_usd={role_definition.max_budget_usd}"
                )

        # --- Delegation validity check ---
        if action.action_type == ActionType.DELEGATION:
            target_role = str(action.details.get("target_role", ""))
            if target_role not in role_definition.can_delegate_to:
                violations.append(
                    f"Role '{action.role}' is not permitted to delegate to '{target_role}'"
                )

        # --- Constraint evaluation ---
        for constraint in self._constitution.constraints:
            applies = (
                "*" in constraint.applies_to or action.role in constraint.applies_to
            )
            if not applies:
                continue
            applied_constraints.append(constraint.name)
            constraint_violation = self._evaluate_constraint(constraint, action)
            if constraint_violation:
                if constraint.severity in ("error", "critical"):
                    violations.append(constraint_violation)
                else:
                    warnings.append(constraint_violation)

        allowed = len(violations) == 0
        result = EnforcementResult(
            allowed=allowed,
            action=action,
            violations=violations,
            warnings=warnings,
            applied_constraints=applied_constraints,
        )
        self._audit.append(result)
        logger.debug(
            "enforce action=%s role=%s allowed=%s",
            action.action_type.value,
            action.role,
            allowed,
        )
        return result

    # ------------------------------------------------------------------
    # Granular check helpers
    # ------------------------------------------------------------------

    def check_permission(self, role: str, permission: "Permission") -> bool:
        """Return ``True`` when *role* holds *permission*.

        Returns ``False`` for unknown roles.
        """
        role_definition = self._constitution.get_role(role)
        if role_definition is None:
            return False
        return permission in role_definition.permissions

    def check_tool_access(self, role: str, tool_name: str) -> bool:
        """Return ``True`` when *role* is allowed to call *tool_name*.

        Evaluation order
        ----------------
        1. If *tool_name* matches any ``denied_tools`` pattern — deny.
        2. If ``allowed_tools`` is empty — allow (no restriction).
        3. If *tool_name* matches any ``allowed_tools`` pattern — allow.
        4. Otherwise — deny.

        Patterns follow ``fnmatch`` semantics (``*`` matches anything).
        """
        role_definition = self._constitution.get_role(role)
        if role_definition is None:
            return False

        # Denied patterns take absolute priority.
        for pattern in role_definition.denied_tools:
            if fnmatch.fnmatch(tool_name, pattern):
                return False

        # Empty allowed_tools means all tools are permitted.
        if not role_definition.allowed_tools:
            return True

        for pattern in role_definition.allowed_tools:
            if fnmatch.fnmatch(tool_name, pattern):
                return True

        return False

    def check_budget(self, role: str, amount: float) -> bool:
        """Return ``True`` when *role* may spend *amount* USD.

        A role with ``max_budget_usd=None`` has no cap and always passes.
        A role with ``max_budget_usd=0`` blocks all spending.
        """
        role_definition = self._constitution.get_role(role)
        if role_definition is None:
            return False
        if role_definition.max_budget_usd is None:
            return True
        return amount <= role_definition.max_budget_usd

    def get_required_approvals(
        self, role: str, action_type: ActionType
    ) -> list[str]:
        """Return the list of roles whose approval is needed before *role* may
        perform *action_type*.

        Returns an empty list when no approval is required, or when *role* is
        unknown.
        """
        role_definition = self._constitution.get_role(role)
        if role_definition is None:
            return []

        # Approval is required for write, execute, and delegation actions.
        sensitive_types = {ActionType.BUDGET_SPEND, ActionType.DELEGATION, ActionType.DATA_ACCESS}
        if action_type in sensitive_types:
            return list(role_definition.requires_approval_from)
        return []

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    @property
    def audit_log(self) -> list[EnforcementResult]:
        """Return a copy of all ``EnforcementResult`` records accumulated so far."""
        return list(self._audit)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _permission_for_action_type(
        self, action_type: ActionType
    ) -> "Permission | None":
        """Map an ``ActionType`` to the ``Permission`` it requires, or ``None``."""
        from aumos_cowork_governance.constitution.schema import Permission

        mapping: dict[ActionType, Permission] = {
            ActionType.TOOL_CALL: Permission.EXECUTE,
            ActionType.BUDGET_SPEND: Permission.APPROVE,
            ActionType.DELEGATION: Permission.DELEGATE,
            ActionType.DATA_ACCESS: Permission.READ,
            ActionType.ESCALATION: Permission.ESCALATE,
        }
        return mapping.get(action_type)

    def _evaluate_constraint(
        self,
        constraint: "object",
        action: AgentAction,
    ) -> str | None:
        """Evaluate a single constraint against *action*.

        Returns a violation message string, or ``None`` if the constraint passes.
        """
        from aumos_cowork_governance.constitution.schema import Constraint

        if not isinstance(constraint, Constraint):
            return None

        if constraint.constraint_type == "budget_limit":
            return self._check_budget_limit_constraint(constraint, action)
        if constraint.constraint_type == "rate_limit":
            # Rate limiting requires external state; flag a warning only when
            # the constraint has a ``calls_per_minute`` of 0 (disabled).
            calls_per_minute = constraint.parameters.get("calls_per_minute", None)
            if calls_per_minute is not None and calls_per_minute == 0:
                return (
                    f"Constraint '{constraint.name}': rate limit set to 0 — "
                    "all calls blocked"
                )
            return None
        if constraint.constraint_type == "scope_limit":
            return self._check_scope_limit_constraint(constraint, action)
        if constraint.constraint_type == "safety_rule":
            return self._check_safety_rule_constraint(constraint, action)
        return None

    def _check_budget_limit_constraint(
        self,
        constraint: "object",
        action: AgentAction,
    ) -> str | None:
        from aumos_cowork_governance.constitution.schema import Constraint

        if not isinstance(constraint, Constraint):
            return None
        if action.action_type != ActionType.BUDGET_SPEND:
            return None
        limit = constraint.parameters.get("limit_usd")
        if limit is None:
            return None
        try:
            limit_float = float(limit)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None
        amount_raw = action.details.get("amount_usd", 0.0)
        try:
            amount = float(amount_raw)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            amount = 0.0
        if amount > limit_float:
            return (
                f"Constraint '{constraint.name}': spend ${amount:.4f} exceeds "
                f"limit ${limit_float:.4f}"
            )
        return None

    def _check_scope_limit_constraint(
        self,
        constraint: "object",
        action: AgentAction,
    ) -> str | None:
        from aumos_cowork_governance.constitution.schema import Constraint

        if not isinstance(constraint, Constraint):
            return None
        allowed_actions_raw = constraint.parameters.get("allowed_action_types", [])
        if not allowed_actions_raw:
            return None
        allowed_action_types: list[str] = [str(a) for a in allowed_actions_raw]  # type: ignore[union-attr]
        if action.action_type.value not in allowed_action_types:
            return (
                f"Constraint '{constraint.name}': action type "
                f"'{action.action_type.value}' is outside allowed scope "
                f"{allowed_action_types}"
            )
        return None

    def _check_safety_rule_constraint(
        self,
        constraint: "object",
        action: AgentAction,
    ) -> str | None:
        from aumos_cowork_governance.constitution.schema import Constraint

        if not isinstance(constraint, Constraint):
            return None
        # Evaluate blocked_tools list in parameters.
        blocked_tools_raw = constraint.parameters.get("blocked_tools", [])
        if not blocked_tools_raw:
            return None
        blocked_tools: list[str] = [str(t) for t in blocked_tools_raw]  # type: ignore[union-attr]
        if action.action_type != ActionType.TOOL_CALL:
            return None
        tool_name = str(action.details.get("tool_name", ""))
        for pattern in blocked_tools:
            if fnmatch.fnmatch(tool_name, pattern):
                return (
                    f"Constraint '{constraint.name}' (safety_rule): "
                    f"tool '{tool_name}' is blocked"
                )
        return None
