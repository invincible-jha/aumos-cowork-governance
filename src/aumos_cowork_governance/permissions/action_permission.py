"""Action-level permission matrix for cowork governance (E8.1).

PermissionMatrix maps (action, resource_path) tuples to PermissionResult
outcomes. Rules are evaluated in declaration order — the first matching
rule determines the outcome. If no rule matches, the default is to deny.

Supported action types:
- file_read
- file_write
- file_delete
- command_execute
- network_access
- clipboard_access

Each rule may carry a list of composable constraints (region, pattern,
time-based, size limit) evaluated by ConstraintEvaluator.

Example
-------
::

    matrix = PermissionMatrix.from_rules([
        {
            "action": "file_read",
            "allow": True,
            "reason": "Allow reads within /workspace",
            "constraints": [
                {"type": "region", "allowed_paths": ["/workspace"]},
            ],
        },
        {
            "action": "file_write",
            "allow": False,
            "reason": "Writes to /etc are forbidden",
            "constraints": [
                {"type": "region", "allowed_paths": ["/etc"]},
            ],
        },
    ])
    result = matrix.check("file_read", "/workspace/data.csv")
    assert result.allowed is True
    assert result.matched_rule is not None
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Literal

from aumos_cowork_governance.permissions.constraint_evaluator import (
    ConstraintEvaluator,
    _build_constraint_from_dict,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

ActionType = Literal[
    "file_read",
    "file_write",
    "file_delete",
    "command_execute",
    "network_access",
    "clipboard_access",
]

_KNOWN_ACTIONS: frozenset[str] = frozenset(
    [
        "file_read",
        "file_write",
        "file_delete",
        "command_execute",
        "network_access",
        "clipboard_access",
    ]
)


# ---------------------------------------------------------------------------
# PermissionResult
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PermissionResult:
    """Immutable result of a permission check.

    Attributes
    ----------
    allowed:
        Whether the action is permitted.
    reason:
        Human-readable explanation of the decision.
    action:
        The action type that was checked.
    resource_path:
        The resource path that was evaluated.
    matched_rule:
        The name/identifier of the rule that determined the outcome,
        or ``None`` if the default-deny was applied.
    """

    allowed: bool
    reason: str
    action: str
    resource_path: str
    matched_rule: str | None = None

    def __bool__(self) -> bool:
        """Return True if the action is allowed."""
        return self.allowed


# ---------------------------------------------------------------------------
# PermissionRule
# ---------------------------------------------------------------------------


@dataclass
class PermissionRule:
    """A single permission rule in the matrix.

    Attributes
    ----------
    action:
        The action this rule applies to (e.g. ``"file_read"``).
    allow:
        Whether a constraint match results in allow (True) or deny (False).
    reason:
        Human-readable description of why this rule exists.
    constraints:
        List of ConstraintEvaluator instances. If empty, the rule matches
        all resource paths unconditionally.
    rule_id:
        Optional identifier for this rule (used in PermissionResult).
    priority:
        Lower numbers are evaluated first. Default 100.
    """

    action: str
    allow: bool
    reason: str
    constraints: list[ConstraintEvaluator] = field(default_factory=list)
    rule_id: str = "unnamed"
    priority: int = 100

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> PermissionRule:
        """Build a PermissionRule from a plain dictionary.

        Parameters
        ----------
        data:
            Dictionary with keys ``action``, ``allow``, ``reason``,
            ``constraints`` (optional), ``rule_id`` (optional),
            ``priority`` (optional).

        Returns
        -------
        PermissionRule

        Raises
        ------
        ValueError
            If ``action`` or ``allow`` are missing or invalid.
        """
        action = str(data.get("action", ""))
        if not action:
            raise ValueError("PermissionRule.action must not be empty.")

        allow_raw = data.get("allow")
        if not isinstance(allow_raw, bool):
            raise ValueError(
                f"PermissionRule.allow must be a boolean; got {allow_raw!r}."
            )

        reason = str(data.get("reason", "No reason provided."))
        rule_id = str(data.get("rule_id", data.get("id", "unnamed")))
        priority = int(data.get("priority", 100))

        raw_constraints: list[dict[str, object]] = list(
            data.get("constraints", [])  # type: ignore[arg-type]
        )
        constraints = [_build_constraint_from_dict(c) for c in raw_constraints]

        return cls(
            action=action,
            allow=allow_raw,
            reason=reason,
            constraints=constraints,
            rule_id=rule_id,
            priority=priority,
        )

    def matches(self, resource_path: str, context: dict[str, object] | None = None) -> bool:
        """Return True if all constraints pass for the given resource_path.

        An empty constraint list means the rule unconditionally matches.

        Parameters
        ----------
        resource_path:
            The resource path to evaluate constraints against.
        context:
            Optional additional context (e.g. file size, current time).

        Returns
        -------
        bool
        """
        effective_context = context or {}
        if not self.constraints:
            return True
        return all(
            c.evaluate(resource_path, effective_context) for c in self.constraints
        )


# ---------------------------------------------------------------------------
# PermissionMatrix
# ---------------------------------------------------------------------------


class PermissionMatrix:
    """Maps (action, resource_path) tuples to PermissionResult outcomes.

    Rules are evaluated in priority order (lower priority number first),
    then in declaration order within the same priority level. The first
    matching rule determines the outcome. If no rule matches, the matrix
    applies a default-deny policy.

    Parameters
    ----------
    rules:
        Ordered list of PermissionRule instances.
    default_allow:
        When ``True``, unmatched requests are permitted. When ``False``
        (default), unmatched requests are denied.

    Examples
    --------
    ::

        matrix = PermissionMatrix(
            rules=[
                PermissionRule(
                    action="file_read",
                    allow=True,
                    reason="Allow reading workspace files",
                    constraints=[RegionConstraint(allowed_paths=["/workspace"])],
                ),
            ]
        )
        result = matrix.check("file_read", "/workspace/readme.md")
        assert result.allowed is True
    """

    def __init__(
        self,
        rules: list[PermissionRule] | None = None,
        default_allow: bool = False,
    ) -> None:
        self._rules: list[PermissionRule] = sorted(
            rules or [], key=lambda r: (r.priority, r.rule_id)
        )
        self._default_allow = default_allow

    @classmethod
    def from_rules(
        cls,
        raw_rules: list[dict[str, object]],
        default_allow: bool = False,
    ) -> PermissionMatrix:
        """Build a PermissionMatrix from a list of rule dictionaries.

        Parameters
        ----------
        raw_rules:
            Each dict is passed to ``PermissionRule.from_dict``.
        default_allow:
            Default allow policy when no rule matches.

        Returns
        -------
        PermissionMatrix
        """
        rules = [PermissionRule.from_dict(r) for r in raw_rules]
        return cls(rules=rules, default_allow=default_allow)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        action: str,
        resource_path: str,
        context: dict[str, object] | None = None,
    ) -> PermissionResult:
        """Evaluate permission for an (action, resource_path) pair.

        Parameters
        ----------
        action:
            The action type to check (e.g. ``"file_read"``).
        resource_path:
            The resource path the action targets.
        context:
            Optional additional context for constraint evaluation (e.g.
            ``{"size_bytes": 1024, "timestamp": datetime.now()}``).

        Returns
        -------
        PermissionResult
            Result with ``allowed`` set to ``True`` or ``False``.
        """
        effective_context = context or {}

        for rule in self._rules:
            if rule.action != action:
                continue
            if rule.matches(resource_path, effective_context):
                verdict = "ALLOW" if rule.allow else "DENY"
                logger.debug(
                    "Permission %s: action=%s path=%s rule=%s",
                    verdict,
                    action,
                    resource_path,
                    rule.rule_id,
                )
                return PermissionResult(
                    allowed=rule.allow,
                    reason=rule.reason,
                    action=action,
                    resource_path=resource_path,
                    matched_rule=rule.rule_id,
                )

        # No rule matched — apply default policy.
        default_reason = (
            f"No matching rule for action '{action}' on '{resource_path}'. "
            f"Default policy: {'allow' if self._default_allow else 'deny'}."
        )
        logger.debug(
            "Permission DEFAULT-%s: action=%s path=%s",
            "ALLOW" if self._default_allow else "DENY",
            action,
            resource_path,
        )
        return PermissionResult(
            allowed=self._default_allow,
            reason=default_reason,
            action=action,
            resource_path=resource_path,
            matched_rule=None,
        )

    def check_all(
        self,
        requests: list[tuple[str, str]],
        context: dict[str, object] | None = None,
    ) -> list[PermissionResult]:
        """Evaluate permission for a batch of (action, resource_path) pairs.

        Parameters
        ----------
        requests:
            List of (action, resource_path) tuples.
        context:
            Shared context for all evaluations.

        Returns
        -------
        list[PermissionResult]
            One result per request, in the same order.
        """
        return [self.check(action, path, context) for action, path in requests]

    def is_action_known(self, action: str) -> bool:
        """Return True if the action is a known action type."""
        return action in _KNOWN_ACTIONS

    def list_rules_for_action(self, action: str) -> list[PermissionRule]:
        """Return all rules that apply to a given action type.

        Parameters
        ----------
        action:
            The action type to filter by.

        Returns
        -------
        list[PermissionRule]
            Rules in evaluation order.
        """
        return [r for r in self._rules if r.action == action]

    def add_rule(self, rule: PermissionRule) -> None:
        """Add a rule to the matrix and re-sort by priority.

        Parameters
        ----------
        rule:
            The PermissionRule to add.
        """
        self._rules.append(rule)
        self._rules.sort(key=lambda r: (r.priority, r.rule_id))

    @property
    def rule_count(self) -> int:
        """Return the total number of rules in the matrix."""
        return len(self._rules)

    @property
    def default_allow(self) -> bool:
        """Return the default allow/deny policy."""
        return self._default_allow

    def summary(self) -> dict[str, object]:
        """Return a plain dict summarising the matrix configuration."""
        action_counts: dict[str, int] = {}
        for rule in self._rules:
            action_counts[rule.action] = action_counts.get(rule.action, 0) + 1
        return {
            "rule_count": self.rule_count,
            "default_allow": self._default_allow,
            "actions_covered": sorted(action_counts.keys()),
            "rules_per_action": action_counts,
        }
