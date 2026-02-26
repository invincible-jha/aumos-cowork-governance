"""Rule evaluator with AND/OR condition logic.

The RuleEvaluator is a standalone component that can evaluate a list of
conditions against a context dictionary.  It is used internally by the
PolicyEngine but can also be used independently for testing policy logic.

Example
-------
>>> evaluator = RuleEvaluator()
>>> conditions = [{"field": "action", "operator": "equals", "value": "file_read"}]
>>> evaluator.evaluate(conditions, "AND", {"action": "file_read"})
True
"""
from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)


class RuleEvaluator:
    """Evaluates structured condition lists against action context dictionaries.

    Each condition is a dict with the following keys:

    - ``field`` (str): dot-separated path into the context dict
    - ``operator`` (str): comparison operator name
    - ``value`` (object): the expected value to compare against

    Parameters
    ----------
    pii_detector:
        Optional callable ``(text: str) -> bool`` used for the
        ``contains_pii`` operator.  When omitted the operator always
        returns ``False``.
    """

    def __init__(
        self,
        pii_detector: "PiiDetectorCallable | None" = None,
    ) -> None:
        self._pii_detector = pii_detector

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        conditions: list[dict[str, object]],
        logic: str,
        context: dict[str, object],
    ) -> bool:
        """Evaluate a list of conditions using AND or OR logic.

        Parameters
        ----------
        conditions:
            List of condition dicts.
        logic:
            ``"AND"`` (all conditions must match) or ``"OR"`` (any match).
        context:
            The action context dictionary to evaluate against.

        Returns
        -------
        bool
            ``True`` when the conditions are satisfied.
        """
        if not conditions:
            return True

        outcomes = [self._eval_one(cond, context) for cond in conditions]

        if logic.upper() == "OR":
            return any(outcomes)
        return all(outcomes)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _eval_one(
        self,
        condition: dict[str, object],
        context: dict[str, object],
    ) -> bool:
        """Evaluate a single condition dict."""
        field_path = str(condition.get("field", ""))
        operator = str(condition.get("operator", "equals"))
        expected = condition.get("value")

        # Support negation prefix: "not:starts_with"
        negate = False
        if operator.startswith("not:"):
            negate = True
            operator = operator[4:]

        actual = self._resolve(field_path, context)
        result = self._apply(operator, actual, expected)
        return (not result) if negate else result

    def _resolve(self, field_path: str, context: dict[str, object]) -> object:
        """Resolve a dot-separated field path from a context dict."""
        current: object = context
        for part in field_path.split("."):
            if not isinstance(current, dict):
                return None
            current = current.get(part)
        return current

    def _apply(self, operator: str, actual: object, expected: object) -> bool:
        """Apply an operator to actual and expected values."""
        match operator:
            case "equals":
                return actual == expected
            case "not_equals":
                return actual != expected
            case "starts_with":
                return (
                    isinstance(actual, str)
                    and isinstance(expected, str)
                    and actual.startswith(expected)
                )
            case "ends_with":
                return (
                    isinstance(actual, str)
                    and isinstance(expected, str)
                    and actual.endswith(expected)
                )
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
            case "greater_than_or_equal":
                try:
                    return float(actual) >= float(expected)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    return False
            case "less_than_or_equal":
                try:
                    return float(actual) <= float(expected)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    return False
            case "matches":
                if not isinstance(actual, str) or not isinstance(expected, str):
                    return False
                try:
                    return bool(re.search(expected, actual))
                except re.error:
                    logger.warning("Invalid regex in policy condition: %s", expected)
                    return False
            case "in_list":
                return isinstance(expected, list) and actual in expected
            case "not_in_list":
                return not isinstance(expected, list) or actual not in expected
            case "contains_pii":
                if not isinstance(actual, str):
                    return False
                if self._pii_detector is not None:
                    return self._pii_detector(actual)
                return False
            case "is_null":
                return actual is None
            case "is_not_null":
                return actual is not None
            case _:
                logger.warning("Unknown rule operator: %s", operator)
                return False


from typing import Callable  # noqa: E402

PiiDetectorCallable = Callable[[str], bool]
