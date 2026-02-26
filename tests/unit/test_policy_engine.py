"""Unit tests for policies/engine.py — PolicyEngine and supporting dataclasses."""
from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from aumos_cowork_governance.policies.engine import (
    EvaluationResult,
    PolicyAction,
    PolicyEngine,
    PolicyResult,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine() -> PolicyEngine:
    return PolicyEngine()


@pytest.fixture()
def engine_with_pii_detector() -> PolicyEngine:
    detector = MagicMock(return_value=False)
    return PolicyEngine(pii_detector=detector)


@pytest.fixture()
def block_policy_config() -> dict[str, object]:
    return {
        "policies": [
            {
                "name": "block-etc",
                "action": "block",
                "message": "Access to /etc denied.",
                "conditions": [
                    {"field": "path", "operator": "starts_with", "value": "/etc"}
                ],
            }
        ]
    }


@pytest.fixture()
def warn_policy_config() -> dict[str, object]:
    return {
        "policies": [
            {
                "name": "warn-tmp",
                "action": "warn",
                "message": "Access to /tmp detected.",
                "conditions": [
                    {"field": "path", "operator": "starts_with", "value": "/tmp"}
                ],
            }
        ]
    }


@pytest.fixture()
def approve_policy_config() -> dict[str, object]:
    return {
        "policies": [
            {
                "name": "approve-delete",
                "action": "approve",
                "message": "Deletion requires approval.",
                "conditions": [
                    {"field": "action", "operator": "equals", "value": "file_delete"}
                ],
            }
        ]
    }


# ---------------------------------------------------------------------------
# PolicyAction enum
# ---------------------------------------------------------------------------


class TestPolicyAction:
    def test_allow_value(self) -> None:
        assert PolicyAction.ALLOW == "allow"

    def test_block_value(self) -> None:
        assert PolicyAction.BLOCK == "block"

    def test_warn_value(self) -> None:
        assert PolicyAction.WARN == "warn"

    def test_log_value(self) -> None:
        assert PolicyAction.LOG == "log"

    def test_approve_value(self) -> None:
        assert PolicyAction.APPROVE == "approve"


# ---------------------------------------------------------------------------
# PolicyResult dataclass
# ---------------------------------------------------------------------------


class TestPolicyResult:
    def test_default_notify_is_empty_list(self) -> None:
        result = PolicyResult(
            policy_name="p",
            matched=True,
            action=PolicyAction.BLOCK,
            message="blocked",
        )
        assert result.notify == []

    def test_fields_stored_correctly(self) -> None:
        result = PolicyResult(
            policy_name="my-policy",
            matched=False,
            action=PolicyAction.WARN,
            message="warning message",
            notify=["admin@example.com"],
        )
        assert result.policy_name == "my-policy"
        assert result.matched is False
        assert result.action == PolicyAction.WARN
        assert result.message == "warning message"
        assert result.notify == ["admin@example.com"]


# ---------------------------------------------------------------------------
# EvaluationResult dataclass
# ---------------------------------------------------------------------------


class TestEvaluationResult:
    def test_allowed_true_when_no_block(self) -> None:
        result = EvaluationResult(
            allowed=True,
            results=[],
            requires_approval=False,
            blocking_policy=None,
        )
        assert result.allowed is True
        assert result.blocking_policy is None


# ---------------------------------------------------------------------------
# PolicyEngine — loading
# ---------------------------------------------------------------------------


class TestPolicyEngineLoading:
    def test_load_from_dict_empty(self, engine: PolicyEngine) -> None:
        engine.load_from_dict({})
        assert engine._policies == []

    def test_load_from_dict_with_policies(
        self, engine: PolicyEngine, block_policy_config: dict[str, object]
    ) -> None:
        engine.load_from_dict(block_policy_config)
        assert len(engine._policies) == 1
        assert engine._policies[0]["name"] == "block-etc"

    def test_load_from_yaml_file(
        self, engine: PolicyEngine, tmp_path: Path
    ) -> None:
        config = {
            "policies": [
                {
                    "name": "test-policy",
                    "action": "log",
                    "conditions": [],
                    "message": "test",
                }
            ]
        }
        config_file = tmp_path / "gov.yaml"
        config_file.write_text(yaml.dump(config), encoding="utf-8")
        engine.load(config_file)
        assert len(engine._policies) == 1

    def test_load_from_yaml_file_missing_raises(
        self, engine: PolicyEngine, tmp_path: Path
    ) -> None:
        with pytest.raises(FileNotFoundError):
            engine.load(tmp_path / "nonexistent.yaml")

    def test_load_from_dict_replaces_previous_policies(
        self, engine: PolicyEngine
    ) -> None:
        engine.load_from_dict({"policies": [{"name": "first", "action": "log"}]})
        engine.load_from_dict({"policies": [{"name": "second", "action": "warn"}]})
        assert len(engine._policies) == 1
        assert engine._policies[0]["name"] == "second"


# ---------------------------------------------------------------------------
# PolicyEngine — evaluation — no policies
# ---------------------------------------------------------------------------


class TestPolicyEngineNoPolicies:
    def test_empty_policies_allows_all(self, engine: PolicyEngine) -> None:
        result = engine.evaluate({"action": "file_read", "path": "/data"})
        assert result.allowed is True
        assert result.requires_approval is False
        assert result.blocking_policy is None
        assert result.results == []


# ---------------------------------------------------------------------------
# PolicyEngine — BLOCK action
# ---------------------------------------------------------------------------


class TestPolicyEngineBlock:
    def test_block_policy_sets_allowed_false(
        self,
        engine: PolicyEngine,
        block_policy_config: dict[str, object],
    ) -> None:
        engine.load_from_dict(block_policy_config)
        result = engine.evaluate({"path": "/etc/passwd"})
        assert result.allowed is False
        assert result.blocking_policy == "block-etc"

    def test_non_matching_block_allows_action(
        self,
        engine: PolicyEngine,
        block_policy_config: dict[str, object],
    ) -> None:
        engine.load_from_dict(block_policy_config)
        result = engine.evaluate({"path": "/home/user/data.csv"})
        assert result.allowed is True

    def test_block_short_circuits_remaining_policies(
        self, engine: PolicyEngine
    ) -> None:
        engine.load_from_dict(
            {
                "policies": [
                    {
                        "name": "block-first",
                        "action": "block",
                        "message": "blocked",
                        "conditions": [
                            {"field": "action", "operator": "equals", "value": "bad"}
                        ],
                    },
                    {
                        "name": "log-second",
                        "action": "log",
                        "message": "logged",
                        "conditions": [
                            {"field": "action", "operator": "equals", "value": "bad"}
                        ],
                    },
                ]
            }
        )
        result = engine.evaluate({"action": "bad"})
        assert result.allowed is False
        # Second policy should not be evaluated after block.
        assert len(result.results) == 1


# ---------------------------------------------------------------------------
# PolicyEngine — APPROVE action
# ---------------------------------------------------------------------------


class TestPolicyEngineApprove:
    def test_approve_policy_sets_requires_approval(
        self,
        engine: PolicyEngine,
        approve_policy_config: dict[str, object],
    ) -> None:
        engine.load_from_dict(approve_policy_config)
        result = engine.evaluate({"action": "file_delete"})
        assert result.requires_approval is True
        assert result.allowed is True

    def test_approve_does_not_block(
        self,
        engine: PolicyEngine,
        approve_policy_config: dict[str, object],
    ) -> None:
        engine.load_from_dict(approve_policy_config)
        result = engine.evaluate({"action": "file_delete"})
        assert result.allowed is True


# ---------------------------------------------------------------------------
# PolicyEngine — WARN action
# ---------------------------------------------------------------------------


class TestPolicyEngineWarn:
    def test_warn_policy_does_not_block(
        self,
        engine: PolicyEngine,
        warn_policy_config: dict[str, object],
    ) -> None:
        engine.load_from_dict(warn_policy_config)
        result = engine.evaluate({"path": "/tmp/scratch.txt"})
        assert result.allowed is True
        assert result.results[0].matched is True
        assert result.results[0].action == PolicyAction.WARN


# ---------------------------------------------------------------------------
# PolicyEngine — operator tests
# ---------------------------------------------------------------------------


class TestPolicyEngineOperators:
    def _make_engine_with_operator(
        self,
        operator: str,
        value: object,
        field: str = "data",
    ) -> PolicyEngine:
        eng = PolicyEngine()
        eng.load_from_dict(
            {
                "policies": [
                    {
                        "name": f"test-{operator}",
                        "action": "block",
                        "conditions": [
                            {"field": field, "operator": operator, "value": value}
                        ],
                    }
                ]
            }
        )
        return eng

    def test_operator_equals_match(self) -> None:
        eng = self._make_engine_with_operator("equals", "file_read")
        assert eng.evaluate({"data": "file_read"}).allowed is False

    def test_operator_equals_no_match(self) -> None:
        eng = self._make_engine_with_operator("equals", "file_read")
        assert eng.evaluate({"data": "file_write"}).allowed is True

    def test_operator_not_equals_match(self) -> None:
        eng = self._make_engine_with_operator("not_equals", "file_read")
        assert eng.evaluate({"data": "file_write"}).allowed is False

    def test_operator_starts_with_match(self) -> None:
        eng = self._make_engine_with_operator("starts_with", "/etc")
        assert eng.evaluate({"data": "/etc/passwd"}).allowed is False

    def test_operator_starts_with_no_match(self) -> None:
        eng = self._make_engine_with_operator("starts_with", "/etc")
        assert eng.evaluate({"data": "/home/user"}).allowed is True

    def test_operator_contains_string(self) -> None:
        eng = self._make_engine_with_operator("contains", "secret")
        assert eng.evaluate({"data": "this is a secret key"}).allowed is False

    def test_operator_contains_no_match(self) -> None:
        eng = self._make_engine_with_operator("contains", "secret")
        assert eng.evaluate({"data": "nothing here"}).allowed is True

    def test_operator_greater_than_match(self) -> None:
        eng = self._make_engine_with_operator("greater_than", 10.0)
        assert eng.evaluate({"data": 15.0}).allowed is False

    def test_operator_greater_than_no_match(self) -> None:
        eng = self._make_engine_with_operator("greater_than", 10.0)
        assert eng.evaluate({"data": 5.0}).allowed is True

    def test_operator_less_than_match(self) -> None:
        eng = self._make_engine_with_operator("less_than", 10.0)
        assert eng.evaluate({"data": 5.0}).allowed is False

    def test_operator_less_than_no_match(self) -> None:
        eng = self._make_engine_with_operator("less_than", 10.0)
        assert eng.evaluate({"data": 15.0}).allowed is True

    def test_operator_matches_regex(self) -> None:
        eng = self._make_engine_with_operator("matches", r"^\d{3}-\d{2}-\d{4}$")
        assert eng.evaluate({"data": "123-45-6789"}).allowed is False

    def test_operator_matches_regex_no_match(self) -> None:
        eng = self._make_engine_with_operator("matches", r"^\d{3}-\d{2}-\d{4}$")
        assert eng.evaluate({"data": "not an ssn"}).allowed is True

    def test_operator_in_list_match(self) -> None:
        eng = self._make_engine_with_operator("in_list", ["a", "b", "c"])
        assert eng.evaluate({"data": "b"}).allowed is False

    def test_operator_in_list_no_match(self) -> None:
        eng = self._make_engine_with_operator("in_list", ["a", "b", "c"])
        assert eng.evaluate({"data": "z"}).allowed is True

    def test_operator_not_in_list_match(self) -> None:
        eng = self._make_engine_with_operator("not_in_list", ["a", "b"])
        assert eng.evaluate({"data": "c"}).allowed is False

    def test_operator_unknown_returns_false(self) -> None:
        eng = self._make_engine_with_operator("totally_unknown_op", "x")
        # Unknown operator → condition evaluates to False → policy does not match → allowed.
        assert eng.evaluate({"data": "x"}).allowed is True

    def test_operator_contains_pii_with_detector_true(self) -> None:
        detector = MagicMock(return_value=True)
        eng = PolicyEngine(pii_detector=detector)
        eng.load_from_dict(
            {
                "policies": [
                    {
                        "name": "pii-block",
                        "action": "block",
                        "conditions": [
                            {"field": "content", "operator": "contains_pii", "value": None}
                        ],
                    }
                ]
            }
        )
        result = eng.evaluate({"content": "test@example.com"})
        assert result.allowed is False

    def test_operator_contains_pii_without_detector_returns_false(self) -> None:
        eng = PolicyEngine(pii_detector=None)
        eng.load_from_dict(
            {
                "policies": [
                    {
                        "name": "pii-block",
                        "action": "block",
                        "conditions": [
                            {"field": "content", "operator": "contains_pii", "value": None}
                        ],
                    }
                ]
            }
        )
        result = eng.evaluate({"content": "test@example.com"})
        # No detector means PII check always false → policy doesn't match → allowed.
        assert result.allowed is True


# ---------------------------------------------------------------------------
# PolicyEngine — AND/OR condition logic
# ---------------------------------------------------------------------------


class TestPolicyEngineConditionLogic:
    def test_and_logic_requires_all_conditions(self, engine: PolicyEngine) -> None:
        engine.load_from_dict(
            {
                "policies": [
                    {
                        "name": "and-policy",
                        "action": "block",
                        "condition_logic": "AND",
                        "conditions": [
                            {"field": "action", "operator": "equals", "value": "file_read"},
                            {"field": "path", "operator": "starts_with", "value": "/etc"},
                        ],
                    }
                ]
            }
        )
        # Only one condition matches — should NOT block.
        assert engine.evaluate({"action": "file_read", "path": "/home"}).allowed is True
        # Both match — should block.
        assert engine.evaluate({"action": "file_read", "path": "/etc/x"}).allowed is False

    def test_or_logic_requires_any_condition(self, engine: PolicyEngine) -> None:
        engine.load_from_dict(
            {
                "policies": [
                    {
                        "name": "or-policy",
                        "action": "block",
                        "condition_logic": "OR",
                        "conditions": [
                            {"field": "action", "operator": "equals", "value": "file_delete"},
                            {"field": "path", "operator": "starts_with", "value": "/etc"},
                        ],
                    }
                ]
            }
        )
        # Either condition matching should block.
        assert engine.evaluate({"action": "file_delete", "path": "/home"}).allowed is False
        assert engine.evaluate({"action": "file_read", "path": "/etc/x"}).allowed is False

    def test_empty_conditions_always_matches(self, engine: PolicyEngine) -> None:
        engine.load_from_dict(
            {
                "policies": [
                    {
                        "name": "catch-all",
                        "action": "log",
                        "conditions": [],
                    }
                ]
            }
        )
        result = engine.evaluate({})
        assert result.results[0].matched is True


# ---------------------------------------------------------------------------
# PolicyEngine — nested field resolution
# ---------------------------------------------------------------------------


class TestPolicyEngineFieldResolution:
    def test_nested_field_dot_path(self, engine: PolicyEngine) -> None:
        engine.load_from_dict(
            {
                "policies": [
                    {
                        "name": "nested",
                        "action": "block",
                        "conditions": [
                            {
                                "field": "request.headers.auth",
                                "operator": "equals",
                                "value": "invalid",
                            }
                        ],
                    }
                ]
            }
        )
        ctx: dict[str, object] = {
            "request": {"headers": {"auth": "invalid"}}
        }
        assert engine.evaluate(ctx).allowed is False

    def test_missing_field_returns_none_and_does_not_match(
        self, engine: PolicyEngine
    ) -> None:
        engine.load_from_dict(
            {
                "policies": [
                    {
                        "name": "missing-field",
                        "action": "block",
                        "conditions": [
                            {"field": "does.not.exist", "operator": "equals", "value": "x"}
                        ],
                    }
                ]
            }
        )
        assert engine.evaluate({}).allowed is True
