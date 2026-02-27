"""Tests for PermissionMatrix and PermissionRule (E8.1)."""
from __future__ import annotations

import pytest

from aumos_cowork_governance.permissions.action_permission import (
    PermissionMatrix,
    PermissionResult,
    PermissionRule,
)
from aumos_cowork_governance.permissions.constraint_evaluator import (
    GlobPatternConstraint,
    RegexPatternConstraint,
    RegionConstraint,
    SizeLimitConstraint,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _read_rule(
    path_prefix: str = "/workspace",
    allow: bool = True,
    rule_id: str = "test-read",
    priority: int = 100,
) -> PermissionRule:
    return PermissionRule(
        action="file_read",
        allow=allow,
        reason="Test file read rule",
        constraints=[RegionConstraint(allowed_paths=[path_prefix])],
        rule_id=rule_id,
        priority=priority,
    )


def _write_rule(
    path_prefix: str = "/workspace",
    allow: bool = True,
    rule_id: str = "test-write",
) -> PermissionRule:
    return PermissionRule(
        action="file_write",
        allow=allow,
        reason="Test file write rule",
        constraints=[RegionConstraint(allowed_paths=[path_prefix])],
        rule_id=rule_id,
    )


@pytest.fixture()
def basic_matrix() -> PermissionMatrix:
    return PermissionMatrix(
        rules=[
            _read_rule(path_prefix="/workspace", allow=True, rule_id="r1"),
            _read_rule(path_prefix="/etc", allow=False, rule_id="r2"),
            _write_rule(path_prefix="/workspace", allow=True, rule_id="w1"),
        ],
        default_allow=False,
    )


# ---------------------------------------------------------------------------
# PermissionResult
# ---------------------------------------------------------------------------

class TestPermissionResult:
    def test_allowed_result_is_truthy(self) -> None:
        result = PermissionResult(
            allowed=True, reason="OK", action="file_read", resource_path="/x"
        )
        assert bool(result) is True

    def test_denied_result_is_falsy(self) -> None:
        result = PermissionResult(
            allowed=False, reason="Denied", action="file_read", resource_path="/x"
        )
        assert bool(result) is False

    def test_frozen_dataclass(self) -> None:
        result = PermissionResult(
            allowed=True, reason="OK", action="file_read", resource_path="/x"
        )
        with pytest.raises((AttributeError, TypeError)):
            result.allowed = False  # type: ignore[misc]

    def test_matched_rule_defaults_none(self) -> None:
        result = PermissionResult(
            allowed=True, reason="OK", action="file_read", resource_path="/x"
        )
        assert result.matched_rule is None

    def test_matched_rule_set(self) -> None:
        result = PermissionResult(
            allowed=True,
            reason="OK",
            action="file_read",
            resource_path="/x",
            matched_rule="rule-001",
        )
        assert result.matched_rule == "rule-001"


# ---------------------------------------------------------------------------
# PermissionRule
# ---------------------------------------------------------------------------

class TestPermissionRuleConstruction:
    def test_basic_construction(self) -> None:
        rule = PermissionRule(
            action="file_read",
            allow=True,
            reason="Allow reads",
        )
        assert rule.action == "file_read"
        assert rule.allow is True

    def test_from_dict_minimal(self) -> None:
        rule = PermissionRule.from_dict(
            {"action": "file_write", "allow": False, "reason": "Deny writes"}
        )
        assert rule.action == "file_write"
        assert rule.allow is False

    def test_from_dict_with_constraint(self) -> None:
        rule = PermissionRule.from_dict(
            {
                "action": "file_read",
                "allow": True,
                "reason": "Allow workspace reads",
                "constraints": [
                    {"type": "region", "allowed_paths": ["/workspace"]}
                ],
            }
        )
        assert len(rule.constraints) == 1

    def test_from_dict_missing_action_raises(self) -> None:
        with pytest.raises(ValueError, match="action"):
            PermissionRule.from_dict({"allow": True, "reason": "test"})

    def test_from_dict_non_bool_allow_raises(self) -> None:
        with pytest.raises(ValueError, match="allow"):
            PermissionRule.from_dict(
                {"action": "file_read", "allow": "yes", "reason": "test"}
            )

    def test_from_dict_rule_id_alias(self) -> None:
        rule = PermissionRule.from_dict(
            {"action": "file_read", "allow": True, "reason": "r", "id": "my-id"}
        )
        assert rule.rule_id == "my-id"

    def test_from_dict_priority(self) -> None:
        rule = PermissionRule.from_dict(
            {
                "action": "file_read",
                "allow": True,
                "reason": "r",
                "priority": 50,
            }
        )
        assert rule.priority == 50


class TestPermissionRuleMatches:
    def test_no_constraints_always_matches(self) -> None:
        rule = PermissionRule(action="file_read", allow=True, reason="r")
        assert rule.matches("/any/path") is True

    def test_region_constraint_matches_prefix(self) -> None:
        rule = PermissionRule(
            action="file_read",
            allow=True,
            reason="r",
            constraints=[RegionConstraint(allowed_paths=["/workspace"])],
        )
        assert rule.matches("/workspace/data.csv") is True

    def test_region_constraint_rejects_outside_prefix(self) -> None:
        rule = PermissionRule(
            action="file_read",
            allow=True,
            reason="r",
            constraints=[RegionConstraint(allowed_paths=["/workspace"])],
        )
        assert rule.matches("/etc/passwd") is False

    def test_multiple_constraints_all_must_pass(self) -> None:
        rule = PermissionRule(
            action="file_read",
            allow=True,
            reason="r",
            constraints=[
                RegionConstraint(allowed_paths=["/workspace"]),
                GlobPatternConstraint(patterns=["*.csv"]),
            ],
        )
        assert rule.matches("/workspace/data.csv") is True
        assert rule.matches("/workspace/data.exe") is False


# ---------------------------------------------------------------------------
# PermissionMatrix
# ---------------------------------------------------------------------------

class TestPermissionMatrixCheck:
    def test_allowed_in_workspace(self, basic_matrix: PermissionMatrix) -> None:
        result = basic_matrix.check("file_read", "/workspace/data.csv")
        assert result.allowed is True

    def test_denied_in_etc(self, basic_matrix: PermissionMatrix) -> None:
        result = basic_matrix.check("file_read", "/etc/passwd")
        assert result.allowed is False

    def test_default_deny_for_unknown_path(
        self, basic_matrix: PermissionMatrix
    ) -> None:
        result = basic_matrix.check("file_read", "/home/user/secret.txt")
        assert result.allowed is False
        assert result.matched_rule is None

    def test_default_allow_matrix(self) -> None:
        matrix = PermissionMatrix(rules=[], default_allow=True)
        result = matrix.check("network_access", "https://example.com")
        assert result.allowed is True
        assert result.matched_rule is None

    def test_correct_action_matched(self, basic_matrix: PermissionMatrix) -> None:
        result = basic_matrix.check("file_read", "/workspace/notes.txt")
        assert result.action == "file_read"

    def test_resource_path_preserved(self, basic_matrix: PermissionMatrix) -> None:
        result = basic_matrix.check("file_read", "/workspace/notes.txt")
        assert result.resource_path == "/workspace/notes.txt"

    def test_matched_rule_id_returned(self, basic_matrix: PermissionMatrix) -> None:
        result = basic_matrix.check("file_read", "/workspace/data.csv")
        assert result.matched_rule == "r1"

    def test_write_allowed_in_workspace(self, basic_matrix: PermissionMatrix) -> None:
        result = basic_matrix.check("file_write", "/workspace/output.csv")
        assert result.allowed is True

    def test_write_denied_outside_workspace(
        self, basic_matrix: PermissionMatrix
    ) -> None:
        result = basic_matrix.check("file_write", "/etc/config")
        assert result.allowed is False

    def test_unknown_action_default_deny(
        self, basic_matrix: PermissionMatrix
    ) -> None:
        result = basic_matrix.check("command_execute", "/bin/rm")
        assert result.allowed is False

    def test_bool_result_allowed(self, basic_matrix: PermissionMatrix) -> None:
        result = basic_matrix.check("file_read", "/workspace/data.csv")
        assert bool(result) is True  # __bool__

    def test_bool_result_denied(self, basic_matrix: PermissionMatrix) -> None:
        result = basic_matrix.check("file_read", "/etc/passwd")
        assert not result  # __bool__


class TestPermissionMatrixPriority:
    def test_higher_priority_rule_wins(self) -> None:
        # Rule with priority=10 (deny) should override rule with priority=100 (allow)
        matrix = PermissionMatrix(
            rules=[
                PermissionRule(
                    action="file_read",
                    allow=True,
                    reason="Allow all reads",
                    constraints=[],
                    rule_id="allow-all",
                    priority=100,
                ),
                PermissionRule(
                    action="file_read",
                    allow=False,
                    reason="Deny sensitive reads",
                    constraints=[RegionConstraint(allowed_paths=["/workspace/sensitive"])],
                    rule_id="deny-sensitive",
                    priority=10,
                ),
            ]
        )
        result = matrix.check("file_read", "/workspace/sensitive/secret.txt")
        assert result.allowed is False
        assert result.matched_rule == "deny-sensitive"

    def test_lower_priority_number_evaluated_first(self) -> None:
        matrix = PermissionMatrix(
            rules=[
                PermissionRule(
                    action="file_read",
                    allow=False,
                    reason="Deny",
                    constraints=[],
                    rule_id="deny",
                    priority=5,
                ),
                PermissionRule(
                    action="file_read",
                    allow=True,
                    reason="Allow",
                    constraints=[],
                    rule_id="allow",
                    priority=50,
                ),
            ]
        )
        result = matrix.check("file_read", "/workspace/data.csv")
        assert result.allowed is False
        assert result.matched_rule == "deny"


class TestPermissionMatrixBatch:
    def test_check_all_returns_correct_count(
        self, basic_matrix: PermissionMatrix
    ) -> None:
        results = basic_matrix.check_all(
            [
                ("file_read", "/workspace/a.csv"),
                ("file_read", "/etc/passwd"),
                ("file_write", "/workspace/b.csv"),
            ]
        )
        assert len(results) == 3

    def test_check_all_preserves_order(
        self, basic_matrix: PermissionMatrix
    ) -> None:
        results = basic_matrix.check_all(
            [
                ("file_read", "/workspace/a.csv"),
                ("file_read", "/etc/passwd"),
            ]
        )
        assert results[0].allowed is True
        assert results[1].allowed is False


class TestPermissionMatrixManagement:
    def test_add_rule_increases_count(self) -> None:
        matrix = PermissionMatrix(rules=[])
        assert matrix.rule_count == 0
        matrix.add_rule(_read_rule())
        assert matrix.rule_count == 1

    def test_list_rules_for_action(self, basic_matrix: PermissionMatrix) -> None:
        rules = basic_matrix.list_rules_for_action("file_read")
        assert all(r.action == "file_read" for r in rules)

    def test_is_action_known_valid(self) -> None:
        matrix = PermissionMatrix()
        assert matrix.is_action_known("file_read") is True
        assert matrix.is_action_known("network_access") is True

    def test_is_action_known_invalid(self) -> None:
        matrix = PermissionMatrix()
        assert matrix.is_action_known("unknown_action_xyz") is False

    def test_summary_contains_rule_count(self, basic_matrix: PermissionMatrix) -> None:
        summary = basic_matrix.summary()
        assert summary["rule_count"] == 3

    def test_summary_contains_default_allow(
        self, basic_matrix: PermissionMatrix
    ) -> None:
        summary = basic_matrix.summary()
        assert summary["default_allow"] is False

    def test_from_rules_factory(self) -> None:
        matrix = PermissionMatrix.from_rules(
            [
                {
                    "action": "file_read",
                    "allow": True,
                    "reason": "Allow workspace",
                    "constraints": [
                        {"type": "region", "allowed_paths": ["/workspace"]}
                    ],
                }
            ]
        )
        result = matrix.check("file_read", "/workspace/data.csv")
        assert result.allowed is True

    def test_empty_matrix_default_deny(self) -> None:
        matrix = PermissionMatrix()
        result = matrix.check("file_read", "/workspace/data.csv")
        assert result.allowed is False
