"""Unit tests for policies/evaluator.py — RuleEvaluator."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from aumos_cowork_governance.policies.evaluator import RuleEvaluator


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def evaluator() -> RuleEvaluator:
    return RuleEvaluator()


@pytest.fixture()
def evaluator_with_pii_detector() -> RuleEvaluator:
    detector = MagicMock(return_value=True)
    return RuleEvaluator(pii_detector=detector)


# ---------------------------------------------------------------------------
# Empty conditions
# ---------------------------------------------------------------------------


class TestRuleEvaluatorEmptyConditions:
    def test_empty_conditions_and_logic_returns_true(
        self, evaluator: RuleEvaluator
    ) -> None:
        assert evaluator.evaluate([], "AND", {}) is True

    def test_empty_conditions_or_logic_returns_true(
        self, evaluator: RuleEvaluator
    ) -> None:
        assert evaluator.evaluate([], "OR", {}) is True


# ---------------------------------------------------------------------------
# AND logic
# ---------------------------------------------------------------------------


class TestRuleEvaluatorAndLogic:
    def test_and_all_match(self, evaluator: RuleEvaluator) -> None:
        conditions = [
            {"field": "action", "operator": "equals", "value": "file_read"},
            {"field": "path", "operator": "starts_with", "value": "/data"},
        ]
        ctx = {"action": "file_read", "path": "/data/report.csv"}
        assert evaluator.evaluate(conditions, "AND", ctx) is True

    def test_and_one_fails(self, evaluator: RuleEvaluator) -> None:
        conditions = [
            {"field": "action", "operator": "equals", "value": "file_read"},
            {"field": "path", "operator": "starts_with", "value": "/etc"},
        ]
        ctx = {"action": "file_read", "path": "/data/report.csv"}
        assert evaluator.evaluate(conditions, "AND", ctx) is False


# ---------------------------------------------------------------------------
# OR logic
# ---------------------------------------------------------------------------


class TestRuleEvaluatorOrLogic:
    def test_or_one_matches(self, evaluator: RuleEvaluator) -> None:
        conditions = [
            {"field": "action", "operator": "equals", "value": "file_delete"},
            {"field": "path", "operator": "starts_with", "value": "/data"},
        ]
        ctx = {"action": "file_read", "path": "/data/report.csv"}
        assert evaluator.evaluate(conditions, "OR", ctx) is True

    def test_or_none_matches(self, evaluator: RuleEvaluator) -> None:
        conditions = [
            {"field": "action", "operator": "equals", "value": "file_delete"},
            {"field": "path", "operator": "starts_with", "value": "/etc"},
        ]
        ctx = {"action": "file_read", "path": "/data/report.csv"}
        assert evaluator.evaluate(conditions, "OR", ctx) is False


# ---------------------------------------------------------------------------
# Negation prefix
# ---------------------------------------------------------------------------


class TestRuleEvaluatorNegation:
    def test_not_starts_with_negation(self, evaluator: RuleEvaluator) -> None:
        conditions = [
            {"field": "path", "operator": "not:starts_with", "value": "/etc"}
        ]
        assert evaluator.evaluate(conditions, "AND", {"path": "/home/user"}) is True
        assert evaluator.evaluate(conditions, "AND", {"path": "/etc/passwd"}) is False


# ---------------------------------------------------------------------------
# All individual operators
# ---------------------------------------------------------------------------


class TestRuleEvaluatorOperators:
    def test_equals(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "x", "operator": "equals", "value": "hello"}]
        assert evaluator.evaluate(cond, "AND", {"x": "hello"}) is True
        assert evaluator.evaluate(cond, "AND", {"x": "world"}) is False

    def test_not_equals(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "x", "operator": "not_equals", "value": "hello"}]
        assert evaluator.evaluate(cond, "AND", {"x": "world"}) is True

    def test_starts_with(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "path", "operator": "starts_with", "value": "/etc"}]
        assert evaluator.evaluate(cond, "AND", {"path": "/etc/hosts"}) is True

    def test_ends_with(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "filename", "operator": "ends_with", "value": ".pem"}]
        assert evaluator.evaluate(cond, "AND", {"filename": "cert.pem"}) is True
        assert evaluator.evaluate(cond, "AND", {"filename": "cert.txt"}) is False

    def test_contains_string(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "msg", "operator": "contains", "value": "secret"}]
        assert evaluator.evaluate(cond, "AND", {"msg": "my secret key"}) is True

    def test_contains_list(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "tags", "operator": "contains", "value": "pii"}]
        assert evaluator.evaluate(cond, "AND", {"tags": ["pii", "restricted"]}) is True

    def test_greater_than(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "cost", "operator": "greater_than", "value": 10.0}]
        assert evaluator.evaluate(cond, "AND", {"cost": 15.0}) is True
        assert evaluator.evaluate(cond, "AND", {"cost": 5.0}) is False

    def test_less_than(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "cost", "operator": "less_than", "value": 10.0}]
        assert evaluator.evaluate(cond, "AND", {"cost": 5.0}) is True

    def test_greater_than_or_equal(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "n", "operator": "greater_than_or_equal", "value": 10}]
        assert evaluator.evaluate(cond, "AND", {"n": 10}) is True
        assert evaluator.evaluate(cond, "AND", {"n": 11}) is True
        assert evaluator.evaluate(cond, "AND", {"n": 9}) is False

    def test_less_than_or_equal(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "n", "operator": "less_than_or_equal", "value": 10}]
        assert evaluator.evaluate(cond, "AND", {"n": 10}) is True
        assert evaluator.evaluate(cond, "AND", {"n": 11}) is False

    def test_matches_regex(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "email", "operator": "matches", "value": r"\b\w+@\w+\.\w+\b"}]
        assert evaluator.evaluate(cond, "AND", {"email": "user@example.com"}) is True

    def test_matches_invalid_regex_returns_false(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "x", "operator": "matches", "value": r"[invalid regex("}]
        assert evaluator.evaluate(cond, "AND", {"x": "anything"}) is False

    def test_in_list(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "role", "operator": "in_list", "value": ["admin", "superuser"]}]
        assert evaluator.evaluate(cond, "AND", {"role": "admin"}) is True
        assert evaluator.evaluate(cond, "AND", {"role": "guest"}) is False

    def test_not_in_list(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "role", "operator": "not_in_list", "value": ["banned"]}]
        assert evaluator.evaluate(cond, "AND", {"role": "admin"}) is True
        assert evaluator.evaluate(cond, "AND", {"role": "banned"}) is False

    def test_is_null(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "optional_field", "operator": "is_null", "value": None}]
        assert evaluator.evaluate(cond, "AND", {"optional_field": None}) is True
        assert evaluator.evaluate(cond, "AND", {"optional_field": "something"}) is False

    def test_is_not_null(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "required_field", "operator": "is_not_null", "value": None}]
        assert evaluator.evaluate(cond, "AND", {"required_field": "value"}) is True
        assert evaluator.evaluate(cond, "AND", {"required_field": None}) is False

    def test_unknown_operator_returns_false(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "x", "operator": "nonexistent_op", "value": "y"}]
        assert evaluator.evaluate(cond, "AND", {"x": "y"}) is False

    def test_contains_pii_with_detector_true(
        self, evaluator_with_pii_detector: RuleEvaluator
    ) -> None:
        cond = [{"field": "content", "operator": "contains_pii", "value": None}]
        assert (
            evaluator_with_pii_detector.evaluate(
                cond, "AND", {"content": "test@example.com"}
            )
            is True
        )

    def test_contains_pii_without_detector_returns_false(
        self, evaluator: RuleEvaluator
    ) -> None:
        cond = [{"field": "content", "operator": "contains_pii", "value": None}]
        assert evaluator.evaluate(cond, "AND", {"content": "test@example.com"}) is False


# ---------------------------------------------------------------------------
# Nested field resolution
# ---------------------------------------------------------------------------


class TestRuleEvaluatorFieldResolution:
    def test_resolves_nested_dict(self, evaluator: RuleEvaluator) -> None:
        cond = [{"field": "a.b.c", "operator": "equals", "value": "deep"}]
        ctx: dict[str, object] = {"a": {"b": {"c": "deep"}}}
        assert evaluator.evaluate(cond, "AND", ctx) is True

    def test_missing_intermediate_key_returns_none(
        self, evaluator: RuleEvaluator
    ) -> None:
        cond = [{"field": "a.b.missing", "operator": "equals", "value": "x"}]
        ctx: dict[str, object] = {"a": {"b": {}}}
        assert evaluator.evaluate(cond, "AND", ctx) is False
