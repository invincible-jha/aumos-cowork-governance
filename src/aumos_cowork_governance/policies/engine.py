"""Core policy engine for evaluating governance policies against action contexts.

The engine loads policies from YAML configuration and evaluates them against
action contexts produced by the Cowork agent lifecycle hooks.

Example
-------
>>> engine = PolicyEngine()
>>> engine.load("governance.yaml")
>>> result = engine.evaluate({"action": "file_read", "path": "/etc/passwd"})
>>> result.allowed
False
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class PolicyAction(str, Enum):
    """Actions that a policy can mandate when its conditions are met."""

    ALLOW = "allow"
    BLOCK = "block"
    WARN = "warn"
    LOG = "log"
    APPROVE = "approve"


@dataclass
class PolicyResult:
    """Result of evaluating a single policy rule against an action context."""

    policy_name: str
    matched: bool
    action: PolicyAction
    message: str
    notify: list[str] = field(default_factory=list)


@dataclass
class EvaluationResult:
    """Aggregate result of running all policies against an action context."""

    allowed: bool
    results: list[PolicyResult]
    requires_approval: bool
    blocking_policy: str | None


class PolicyEngine:
    """Evaluates action contexts against a set of loaded governance policies.

    Policies are loaded from a YAML file (or in-memory dict) and evaluated
    in declaration order.  The first BLOCK policy terminates evaluation and
    sets ``allowed=False``.  APPROVE policies set ``requires_approval=True``
    without blocking.

    Parameters
    ----------
    pii_detector:
        Optional callable that accepts a string and returns ``True`` when PII
        is detected.  If omitted, ``contains_pii`` operator always returns
        ``False``.
    """

    def __init__(
        self,
        pii_detector: "PiiDetectorCallable | None" = None,
    ) -> None:
        self._policies: list[dict[str, object]] = []
        self._pii_detector = pii_detector

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self, config_path: str | Path) -> None:
        """Load and parse policies from a YAML governance configuration file.

        Parameters
        ----------
        config_path:
            Path to the governance YAML file.  The file must contain a
            top-level ``policies`` list.
        """
        config_path = Path(config_path)
        with config_path.open("r", encoding="utf-8") as fh:
            raw: dict[str, object] = yaml.safe_load(fh) or {}

        self._policies = list(raw.get("policies", []))  # type: ignore[arg-type]
        logger.info("Loaded %d policies from %s", len(self._policies), config_path)

    def load_from_dict(self, config: dict[str, object]) -> None:
        """Load policies from an already-parsed configuration dictionary."""
        self._policies = list(config.get("policies", []))  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(self, action_context: dict[str, object]) -> EvaluationResult:
        """Evaluate all policies against an action context.

        Parameters
        ----------
        action_context:
            Flat or nested dictionary describing the agent action.  Keys
            depend on the hook type (e.g., ``action``, ``path``, ``url``,
            ``content``, ``tokens``, ``cost_usd``).

        Returns
        -------
        EvaluationResult
            Aggregate outcome.  ``allowed`` is ``False`` only when at least
            one BLOCK policy matched.
        """
        results: list[PolicyResult] = []
        requires_approval: bool = False
        blocking_policy: str | None = None
        allowed: bool = True

        for raw_policy in self._policies:
            policy_name: str = str(raw_policy.get("name", "unnamed"))
            action_value: PolicyAction = PolicyAction(
                str(raw_policy.get("action", PolicyAction.LOG.value)).lower()
            )
            message: str = str(raw_policy.get("message", ""))
            notify: list[str] = list(raw_policy.get("notify", []))  # type: ignore[arg-type]
            conditions: list[dict[str, object]] = list(
                raw_policy.get("conditions", [])  # type: ignore[arg-type]
            )
            condition_logic: str = str(raw_policy.get("condition_logic", "AND")).upper()

            matched = self._evaluate_conditions(
                conditions, condition_logic, action_context
            )

            result = PolicyResult(
                policy_name=policy_name,
                matched=matched,
                action=action_value,
                message=message,
                notify=notify,
            )
            results.append(result)

            if matched:
                if action_value == PolicyAction.BLOCK:
                    allowed = False
                    blocking_policy = policy_name
                    # BLOCK short-circuits further evaluation.
                    break
                elif action_value == PolicyAction.APPROVE:
                    requires_approval = True

        return EvaluationResult(
            allowed=allowed,
            results=results,
            requires_approval=requires_approval,
            blocking_policy=blocking_policy,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate_conditions(
        self,
        conditions: list[dict[str, object]],
        logic: str,
        context: dict[str, object],
    ) -> bool:
        """Evaluate a list of conditions using AND or OR logic."""
        if not conditions:
            return True

        outcomes = [self._evaluate_condition(cond, context) for cond in conditions]

        if logic == "OR":
            return any(outcomes)
        # Default AND
        return all(outcomes)

    def _evaluate_condition(
        self,
        condition: dict[str, object],
        context: dict[str, object],
    ) -> bool:
        """Evaluate a single condition dict against the action context."""
        field_path: str = str(condition.get("field", ""))
        operator: str = str(condition.get("operator", "equals"))
        expected: object = condition.get("value")

        actual = self._resolve_field(field_path, context)

        return self._apply_operator(operator, actual, expected, context)

    def _resolve_field(self, field_path: str, context: dict[str, object]) -> object:
        """Resolve a dot-separated field path from the context dict."""
        parts = field_path.split(".")
        current: object = context
        for part in parts:
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current

    def _apply_operator(
        self,
        operator: str,
        actual: object,
        expected: object,
        context: dict[str, object],
    ) -> bool:
        """Apply an operator to the actual value resolved from context."""
        match operator:
            case "equals":
                return actual == expected
            case "not_equals":
                return actual != expected
            case "starts_with":
                return isinstance(actual, str) and isinstance(expected, str) and actual.startswith(expected)
            case "contains":
                if isinstance(actual, str) and isinstance(expected, str):
                    return expected in actual
                if isinstance(actual, (list, tuple, set)) and expected is not None:
                    return expected in actual
                return False
            case "greater_than":
                try:
                    return float(actual) > float(expected)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    return False
            case "less_than":
                try:
                    return float(actual) < float(expected)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    return False
            case "matches":
                if not isinstance(actual, str) or not isinstance(expected, str):
                    return False
                return bool(re.search(expected, actual))
            case "in_list":
                if not isinstance(expected, list):
                    return False
                return actual in expected
            case "not_in_list":
                if not isinstance(expected, list):
                    return True
                return actual not in expected
            case "contains_pii":
                if not isinstance(actual, str):
                    return False
                if self._pii_detector is not None:
                    return self._pii_detector(actual)
                return False
            case _:
                logger.warning("Unknown policy operator: %s", operator)
                return False


# Type alias used only for annotations — kept here to avoid circular imports.
from typing import Callable  # noqa: E402

PiiDetectorCallable = Callable[[str], bool]
