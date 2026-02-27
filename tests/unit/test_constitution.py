"""Unit tests for the constitution package — Phase 6F.

Covers:
- Constitution YAML parsing and validation
- Role definition with all permission types
- Constraint evaluation (budget, rate, scope, safety)
- Wildcard tool pattern matching
- Escalation rule triggering
- Enforcer permission checks
- Enforcer tool access checks
- Enforcer budget checks
- Conflict detection
- All 4 conflict resolution strategies
- Constitution internal consistency validation
- CLI commands
- Edge cases: empty constitution, unknown role, conflicting constraints
"""
from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from aumos_cowork_governance.constitution.conflict_resolver import (
    Conflict,
    ConflictResolution,
    ConflictResolver,
)
from aumos_cowork_governance.constitution.enforcer import (
    ActionType,
    AgentAction,
    ConstitutionEnforcer,
    EnforcementResult,
)
from aumos_cowork_governance.constitution.schema import (
    ConflictStrategy,
    Constitution,
    Constraint,
    EscalationRule,
    Permission,
    RoleDefinition,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _make_action(
    agent_id: str = "agent-1",
    role: str = "worker",
    action_type: ActionType = ActionType.TOOL_CALL,
    details: dict[str, Any] | None = None,
) -> AgentAction:
    return AgentAction(
        agent_id=agent_id,
        role=role,
        action_type=action_type,
        details=details or {},
        timestamp=_now(),
    )


def _make_constitution(
    team_name: str = "test-team",
    roles: list[RoleDefinition] | None = None,
    constraints: list[Constraint] | None = None,
    escalation_rules: list[EscalationRule] | None = None,
    conflict_strategy: ConflictStrategy = ConflictStrategy.PRIORITY_BASED,
) -> Constitution:
    return Constitution(
        version="1.0.0",
        team_name=team_name,
        roles=roles or [],
        constraints=constraints or [],
        escalation_rules=escalation_rules or [],
        conflict_strategy=conflict_strategy,
        created_at=_now(),
        updated_at=_now(),
    )


def _full_constitution() -> Constitution:
    """Return a realistic multi-role constitution for most tests."""
    return _make_constitution(
        roles=[
            RoleDefinition(
                name="orchestrator",
                permissions=list(Permission),
                max_budget_usd=1000.0,
                allowed_tools=["*"],
                denied_tools=[],
                can_delegate_to=["worker", "reviewer"],
                requires_approval_from=[],
            ),
            RoleDefinition(
                name="worker",
                permissions=[
                    Permission.READ,
                    Permission.WRITE,
                    Permission.EXECUTE,
                    Permission.ESCALATE,
                ],
                max_budget_usd=100.0,
                allowed_tools=["read_*", "write_*", "search_*"],
                denied_tools=["admin_*", "delete_*"],
                can_delegate_to=[],
                requires_approval_from=["orchestrator"],
            ),
            RoleDefinition(
                name="reviewer",
                permissions=[Permission.READ, Permission.APPROVE],
                max_budget_usd=None,
                allowed_tools=["read_*", "search_*"],
                denied_tools=[],
                can_delegate_to=[],
                requires_approval_from=[],
            ),
        ],
        constraints=[
            Constraint(
                name="budget_cap",
                description="Global budget cap",
                constraint_type="budget_limit",
                parameters={"limit_usd": 500.0},
                applies_to=["*"],
                severity="critical",
            ),
            Constraint(
                name="worker_rate",
                description="Worker rate limit",
                constraint_type="rate_limit",
                parameters={"calls_per_minute": 60},
                applies_to=["worker"],
                severity="warning",
            ),
        ],
        escalation_rules=[
            EscalationRule(
                trigger="Budget exceeded",
                from_role="worker",
                to_role="orchestrator",
                auto_escalate=True,
                timeout_seconds=300.0,
            ),
        ],
        conflict_strategy=ConflictStrategy.PRIORITY_BASED,
    )


# ---------------------------------------------------------------------------
# Permission enum
# ---------------------------------------------------------------------------


class TestPermissionEnum:
    def test_all_values_present(self) -> None:
        values = {p.value for p in Permission}
        assert values == {"read", "write", "execute", "delegate", "approve", "escalate"}

    def test_string_coercion(self) -> None:
        assert Permission("read") is Permission.READ
        assert Permission("delegate") is Permission.DELEGATE

    def test_invalid_permission_raises(self) -> None:
        with pytest.raises(ValueError):
            Permission("superpower")


class TestConflictStrategyEnum:
    def test_all_values(self) -> None:
        values = {s.value for s in ConflictStrategy}
        assert values == {"priority_based", "consensus", "leader_decides", "most_restrictive"}


# ---------------------------------------------------------------------------
# RoleDefinition
# ---------------------------------------------------------------------------


class TestRoleDefinition:
    def test_defaults(self) -> None:
        role = RoleDefinition(name="basic")
        assert role.permissions == []
        assert role.max_budget_usd is None
        assert role.allowed_tools == []
        assert role.denied_tools == []
        assert role.can_delegate_to == []
        assert role.requires_approval_from == []

    def test_all_permissions(self) -> None:
        role = RoleDefinition(name="admin", permissions=list(Permission))
        assert len(role.permissions) == 6

    def test_budget_zero_allowed(self) -> None:
        role = RoleDefinition(name="no_spend", max_budget_usd=0.0)
        assert role.max_budget_usd == 0.0

    def test_negative_budget_raises(self) -> None:
        with pytest.raises(Exception):
            RoleDefinition(name="bad", max_budget_usd=-1.0)

    def test_tool_patterns_stored(self) -> None:
        role = RoleDefinition(
            name="limited",
            allowed_tools=["read_*", "search_*"],
            denied_tools=["admin_*"],
        )
        assert "read_*" in role.allowed_tools
        assert "admin_*" in role.denied_tools

    def test_delegation_list(self) -> None:
        role = RoleDefinition(name="lead", can_delegate_to=["worker", "reviewer"])
        assert "worker" in role.can_delegate_to
        assert "reviewer" in role.can_delegate_to

    def test_requires_approval_list(self) -> None:
        role = RoleDefinition(name="agent", requires_approval_from=["orchestrator"])
        assert "orchestrator" in role.requires_approval_from

    def test_permission_deduplication_preserved(self) -> None:
        role = RoleDefinition(
            name="dup", permissions=[Permission.READ, Permission.READ]
        )
        # Pydantic does not deduplicate lists by default; we accept duplicates.
        assert Permission.READ in role.permissions


# ---------------------------------------------------------------------------
# Constraint
# ---------------------------------------------------------------------------


class TestConstraint:
    def test_valid_constraint_types(self) -> None:
        for ct in ["budget_limit", "rate_limit", "scope_limit", "safety_rule"]:
            c = Constraint(name="c", description="d", constraint_type=ct)
            assert c.constraint_type == ct

    def test_invalid_constraint_type_raises(self) -> None:
        with pytest.raises(Exception):
            Constraint(name="c", description="d", constraint_type="custom_type")

    def test_valid_severities(self) -> None:
        for sv in ["warning", "error", "critical"]:
            c = Constraint(
                name="c", description="d", constraint_type="budget_limit", severity=sv
            )
            assert c.severity == sv

    def test_invalid_severity_raises(self) -> None:
        with pytest.raises(Exception):
            Constraint(
                name="c",
                description="d",
                constraint_type="budget_limit",
                severity="fatal",
            )

    def test_default_applies_to_all(self) -> None:
        c = Constraint(name="c", description="d", constraint_type="budget_limit")
        assert c.applies_to == ["*"]

    def test_applies_to_specific_roles(self) -> None:
        c = Constraint(
            name="c",
            description="d",
            constraint_type="rate_limit",
            applies_to=["worker", "reviewer"],
        )
        assert "worker" in c.applies_to
        assert "reviewer" in c.applies_to

    def test_parameters_stored(self) -> None:
        c = Constraint(
            name="budget",
            description="d",
            constraint_type="budget_limit",
            parameters={"limit_usd": 100.0},
        )
        assert c.parameters["limit_usd"] == 100.0


# ---------------------------------------------------------------------------
# EscalationRule
# ---------------------------------------------------------------------------


class TestEscalationRule:
    def test_basic_fields(self) -> None:
        rule = EscalationRule(
            trigger="on error",
            from_role="worker",
            to_role="orchestrator",
            auto_escalate=True,
            timeout_seconds=120.0,
        )
        assert rule.trigger == "on error"
        assert rule.from_role == "worker"
        assert rule.to_role == "orchestrator"
        assert rule.auto_escalate is True
        assert rule.timeout_seconds == 120.0

    def test_auto_escalate_default_false(self) -> None:
        rule = EscalationRule(trigger="t", from_role="a", to_role="b")
        assert rule.auto_escalate is False

    def test_timeout_none_allowed(self) -> None:
        rule = EscalationRule(trigger="t", from_role="a", to_role="b", timeout_seconds=None)
        assert rule.timeout_seconds is None

    def test_negative_timeout_raises(self) -> None:
        with pytest.raises(Exception):
            EscalationRule(trigger="t", from_role="a", to_role="b", timeout_seconds=-1.0)

    def test_zero_timeout_raises(self) -> None:
        with pytest.raises(Exception):
            EscalationRule(trigger="t", from_role="a", to_role="b", timeout_seconds=0.0)


# ---------------------------------------------------------------------------
# Constitution — construction and basic accessors
# ---------------------------------------------------------------------------


class TestConstitutionBasics:
    def test_defaults(self) -> None:
        c = Constitution(team_name="alpha")
        assert c.version == "1.0.0"
        assert c.description == ""
        assert c.roles == []
        assert c.constraints == []
        assert c.escalation_rules == []
        assert c.conflict_strategy == ConflictStrategy.PRIORITY_BASED
        assert c.created_at.tzinfo is not None
        assert c.updated_at.tzinfo is not None

    def test_get_role_found(self) -> None:
        c = _full_constitution()
        role = c.get_role("worker")
        assert role is not None
        assert role.name == "worker"

    def test_get_role_not_found(self) -> None:
        c = _full_constitution()
        assert c.get_role("nonexistent") is None

    def test_get_role_empty_constitution(self) -> None:
        c = _make_constitution()
        assert c.get_role("anything") is None

    def test_timestamps_utc(self) -> None:
        c = Constitution(team_name="tz-test")
        assert c.created_at.tzinfo == timezone.utc
        assert c.updated_at.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# Constitution — YAML serialisation round-trip
# ---------------------------------------------------------------------------


class TestConstitutionYaml:
    def test_to_yaml_produces_valid_yaml(self) -> None:
        c = _full_constitution()
        yaml_str = c.to_yaml()
        parsed = yaml.safe_load(yaml_str)
        assert parsed["team_name"] == "test-team"

    def test_from_yaml_round_trip(self) -> None:
        original = _full_constitution()
        yaml_str = original.to_yaml()
        restored = Constitution.from_yaml(yaml_str)
        assert restored.team_name == original.team_name
        assert restored.version == original.version
        assert len(restored.roles) == len(original.roles)
        assert len(restored.constraints) == len(original.constraints)
        assert len(restored.escalation_rules) == len(original.escalation_rules)

    def test_from_yaml_role_permissions(self) -> None:
        yaml_str = textwrap.dedent("""\
            version: "1.0.0"
            team_name: yaml-test
            roles:
              - name: admin
                permissions: [read, write, execute, delegate, approve, escalate]
                max_budget_usd: 500.0
                allowed_tools: ["*"]
                denied_tools: []
                can_delegate_to: []
                requires_approval_from: []
            constraints: []
            escalation_rules: []
            conflict_strategy: priority_based
            created_at: "2026-01-01T00:00:00+00:00"
            updated_at: "2026-01-01T00:00:00+00:00"
        """)
        c = Constitution.from_yaml(yaml_str)
        role = c.get_role("admin")
        assert role is not None
        assert Permission.DELEGATE in role.permissions
        assert role.max_budget_usd == 500.0

    def test_from_yaml_empty_string_raises(self) -> None:
        # Empty YAML -> empty dict -> validation error (missing team_name)
        with pytest.raises(Exception):
            Constitution.from_yaml("")

    def test_from_yaml_missing_team_name_raises(self) -> None:
        with pytest.raises(Exception):
            Constitution.from_yaml("version: '1.0.0'\nroles: []\n")

    def test_to_yaml_conflict_strategy_preserved(self) -> None:
        c = _make_constitution(conflict_strategy=ConflictStrategy.CONSENSUS)
        restored = Constitution.from_yaml(c.to_yaml())
        assert restored.conflict_strategy == ConflictStrategy.CONSENSUS


# ---------------------------------------------------------------------------
# Constitution — dict serialisation
# ---------------------------------------------------------------------------


class TestConstitutionDict:
    def test_to_dict_returns_dict(self) -> None:
        c = _full_constitution()
        d = c.to_dict()
        assert isinstance(d, dict)
        assert d["team_name"] == "test-team"

    def test_from_dict_round_trip(self) -> None:
        original = _full_constitution()
        restored = Constitution.from_dict(original.to_dict())
        assert restored.team_name == original.team_name
        assert len(restored.roles) == len(original.roles)

    def test_from_dict_empty_raises(self) -> None:
        with pytest.raises(Exception):
            Constitution.from_dict({})


# ---------------------------------------------------------------------------
# Constitution — validate_constitution()
# ---------------------------------------------------------------------------


class TestConstitutionValidation:
    def test_valid_constitution_no_errors(self) -> None:
        c = _full_constitution()
        errors = c.validate_constitution()
        assert errors == []

    def test_unknown_delegate_target(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="boss",
                    permissions=[Permission.DELEGATE],
                    can_delegate_to=["ghost_role"],
                )
            ]
        )
        errors = c.validate_constitution()
        assert any("ghost_role" in e for e in errors)

    def test_unknown_approval_role(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="worker",
                    permissions=[Permission.EXECUTE],
                    requires_approval_from=["nonexistent"],
                )
            ]
        )
        errors = c.validate_constitution()
        assert any("nonexistent" in e for e in errors)

    def test_escalation_rule_unknown_from_role(self) -> None:
        c = _make_constitution(
            roles=[RoleDefinition(name="orchestrator")],
            escalation_rules=[
                EscalationRule(
                    trigger="t", from_role="ghost", to_role="orchestrator"
                )
            ],
        )
        errors = c.validate_constitution()
        assert any("ghost" in e for e in errors)

    def test_escalation_rule_unknown_to_role(self) -> None:
        c = _make_constitution(
            roles=[RoleDefinition(name="worker")],
            escalation_rules=[
                EscalationRule(trigger="t", from_role="worker", to_role="ghost")
            ],
        )
        errors = c.validate_constitution()
        assert any("ghost" in e for e in errors)

    def test_constraint_unknown_role(self) -> None:
        c = _make_constitution(
            roles=[RoleDefinition(name="worker")],
            constraints=[
                Constraint(
                    name="c",
                    description="d",
                    constraint_type="budget_limit",
                    applies_to=["phantom"],
                )
            ],
        )
        errors = c.validate_constitution()
        assert any("phantom" in e for e in errors)

    def test_constraint_wildcard_no_error(self) -> None:
        c = _make_constitution(
            roles=[RoleDefinition(name="worker")],
            constraints=[
                Constraint(
                    name="c",
                    description="d",
                    constraint_type="budget_limit",
                    applies_to=["*"],
                )
            ],
        )
        errors = c.validate_constitution()
        assert errors == []

    def test_circular_delegation_detected(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="a", permissions=[Permission.DELEGATE], can_delegate_to=["b"]
                ),
                RoleDefinition(
                    name="b", permissions=[Permission.DELEGATE], can_delegate_to=["a"]
                ),
            ]
        )
        errors = c.validate_constitution()
        assert any("Circular" in e for e in errors)

    def test_self_delegation_cycle(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="self_loop",
                    permissions=[Permission.DELEGATE],
                    can_delegate_to=["self_loop"],
                )
            ]
        )
        errors = c.validate_constitution()
        assert any("Circular" in e for e in errors)

    def test_three_node_cycle(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(name="a", can_delegate_to=["b"]),
                RoleDefinition(name="b", can_delegate_to=["c"]),
                RoleDefinition(name="c", can_delegate_to=["a"]),
            ]
        )
        errors = c.validate_constitution()
        assert any("Circular" in e for e in errors)

    def test_empty_constitution_valid(self) -> None:
        c = _make_constitution()
        errors = c.validate_constitution()
        assert errors == []

    def test_multiple_errors_returned(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="a",
                    can_delegate_to=["missing1"],
                    requires_approval_from=["missing2"],
                )
            ]
        )
        errors = c.validate_constitution()
        assert len(errors) >= 2


# ---------------------------------------------------------------------------
# Constitution.starter()
# ---------------------------------------------------------------------------


class TestConstitutionStarter:
    def test_starter_creates_three_roles(self) -> None:
        c = Constitution.starter("alpha-team")
        assert len(c.roles) == 3

    def test_starter_team_name(self) -> None:
        c = Constitution.starter("my-team")
        assert c.team_name == "my-team"

    def test_starter_orchestrator_has_full_permissions(self) -> None:
        c = Constitution.starter("t")
        orch = c.get_role("orchestrator")
        assert orch is not None
        assert set(orch.permissions) == set(Permission)

    def test_starter_is_internally_valid(self) -> None:
        c = Constitution.starter("test")
        errors = c.validate_constitution()
        assert errors == []


# ---------------------------------------------------------------------------
# ConstitutionEnforcer — permissions
# ---------------------------------------------------------------------------


class TestEnforcerPermissions:
    @pytest.fixture()
    def enforcer(self) -> ConstitutionEnforcer:
        return ConstitutionEnforcer(_full_constitution())

    def test_worker_has_execute(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_permission("worker", Permission.EXECUTE) is True

    def test_worker_lacks_approve(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_permission("worker", Permission.APPROVE) is False

    def test_orchestrator_has_all_permissions(
        self, enforcer: ConstitutionEnforcer
    ) -> None:
        for perm in Permission:
            assert enforcer.check_permission("orchestrator", perm) is True

    def test_reviewer_has_read_and_approve(
        self, enforcer: ConstitutionEnforcer
    ) -> None:
        assert enforcer.check_permission("reviewer", Permission.READ) is True
        assert enforcer.check_permission("reviewer", Permission.APPROVE) is True

    def test_reviewer_lacks_write(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_permission("reviewer", Permission.WRITE) is False

    def test_unknown_role_returns_false(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_permission("ghost", Permission.READ) is False


# ---------------------------------------------------------------------------
# ConstitutionEnforcer — tool access
# ---------------------------------------------------------------------------


class TestEnforcerToolAccess:
    @pytest.fixture()
    def enforcer(self) -> ConstitutionEnforcer:
        return ConstitutionEnforcer(_full_constitution())

    def test_worker_allowed_read_file(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_tool_access("worker", "read_file") is True

    def test_worker_allowed_search_index(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_tool_access("worker", "search_index") is True

    def test_worker_denied_admin_tool(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_tool_access("worker", "admin_reset") is False

    def test_worker_denied_delete_tool(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_tool_access("worker", "delete_record") is False

    def test_worker_denied_unknown_tool(self, enforcer: ConstitutionEnforcer) -> None:
        # "other_tool" doesn't match read_*, write_*, or search_*
        assert enforcer.check_tool_access("worker", "other_tool") is False

    def test_orchestrator_wildcard_allows_any(
        self, enforcer: ConstitutionEnforcer
    ) -> None:
        assert enforcer.check_tool_access("orchestrator", "any_tool_whatsoever") is True

    def test_orchestrator_wildcard_allows_admin(
        self, enforcer: ConstitutionEnforcer
    ) -> None:
        assert enforcer.check_tool_access("orchestrator", "admin_reset") is True

    def test_reviewer_allowed_read_doc(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_tool_access("reviewer", "read_document") is True

    def test_reviewer_denied_write_tool(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_tool_access("reviewer", "write_document") is False

    def test_unknown_role_denied(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_tool_access("ghost", "read_file") is False

    def test_empty_allowed_tools_permits_all(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="open",
                    permissions=[Permission.EXECUTE],
                    allowed_tools=[],
                    denied_tools=[],
                )
            ]
        )
        enforcer = ConstitutionEnforcer(c)
        assert enforcer.check_tool_access("open", "anything") is True

    def test_denied_overrides_allowed_wildcard(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="limited",
                    permissions=[Permission.EXECUTE],
                    allowed_tools=["*"],
                    denied_tools=["danger_*"],
                )
            ]
        )
        enforcer = ConstitutionEnforcer(c)
        assert enforcer.check_tool_access("limited", "danger_nuke") is False
        assert enforcer.check_tool_access("limited", "safe_tool") is True

    def test_exact_tool_name_matching(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="exact",
                    permissions=[Permission.EXECUTE],
                    allowed_tools=["specific_tool"],
                    denied_tools=[],
                )
            ]
        )
        enforcer = ConstitutionEnforcer(c)
        assert enforcer.check_tool_access("exact", "specific_tool") is True
        assert enforcer.check_tool_access("exact", "specific_tool_v2") is False


# ---------------------------------------------------------------------------
# ConstitutionEnforcer — budget checks
# ---------------------------------------------------------------------------


class TestEnforcerBudget:
    @pytest.fixture()
    def enforcer(self) -> ConstitutionEnforcer:
        return ConstitutionEnforcer(_full_constitution())

    def test_worker_within_budget(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_budget("worker", 50.0) is True

    def test_worker_at_budget_limit(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_budget("worker", 100.0) is True

    def test_worker_exceeds_budget(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_budget("worker", 100.01) is False

    def test_orchestrator_within_budget(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_budget("orchestrator", 999.99) is True

    def test_orchestrator_exceeds_budget(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_budget("orchestrator", 1000.01) is False

    def test_reviewer_no_budget_cap(self, enforcer: ConstitutionEnforcer) -> None:
        # reviewer has max_budget_usd=None — no cap
        assert enforcer.check_budget("reviewer", 9_999_999.0) is True

    def test_unknown_role_budget_denied(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_budget("ghost", 1.0) is False

    def test_zero_amount_always_allowed(self, enforcer: ConstitutionEnforcer) -> None:
        assert enforcer.check_budget("worker", 0.0) is True

    def test_zero_budget_cap_blocks_all(self) -> None:
        c = _make_constitution(
            roles=[RoleDefinition(name="no_spend", max_budget_usd=0.0)]
        )
        enforcer = ConstitutionEnforcer(c)
        assert enforcer.check_budget("no_spend", 0.01) is False
        assert enforcer.check_budget("no_spend", 0.0) is True


# ---------------------------------------------------------------------------
# ConstitutionEnforcer — evaluate() full pipeline
# ---------------------------------------------------------------------------


class TestEnforcerEvaluate:
    @pytest.fixture()
    def enforcer(self) -> ConstitutionEnforcer:
        return ConstitutionEnforcer(_full_constitution())

    def test_allowed_tool_call(self, enforcer: ConstitutionEnforcer) -> None:
        action = _make_action(role="worker", details={"tool_name": "read_file"})
        result = enforcer.evaluate(action)
        assert result.allowed is True
        assert result.violations == []

    def test_denied_tool_call(self, enforcer: ConstitutionEnforcer) -> None:
        action = _make_action(role="worker", details={"tool_name": "admin_reset"})
        result = enforcer.evaluate(action)
        assert result.allowed is False
        assert any("admin_reset" in v for v in result.violations)

    def test_unknown_role_denied(self, enforcer: ConstitutionEnforcer) -> None:
        action = _make_action(role="ghost")
        result = enforcer.evaluate(action)
        assert result.allowed is False
        assert any("ghost" in v for v in result.violations)

    def test_budget_spend_within_limit(self, enforcer: ConstitutionEnforcer) -> None:
        action = _make_action(
            role="orchestrator",
            action_type=ActionType.BUDGET_SPEND,
            details={"amount_usd": 50.0},
        )
        result = enforcer.evaluate(action)
        assert result.allowed is True

    def test_budget_spend_exceeds_limit(self, enforcer: ConstitutionEnforcer) -> None:
        action = _make_action(
            role="worker",
            action_type=ActionType.BUDGET_SPEND,
            details={"amount_usd": 200.0},
        )
        result = enforcer.evaluate(action)
        assert result.allowed is False
        assert any("budget" in v.lower() for v in result.violations)

    def test_delegation_to_allowed_role(self, enforcer: ConstitutionEnforcer) -> None:
        action = _make_action(
            role="orchestrator",
            action_type=ActionType.DELEGATION,
            details={"target_role": "worker"},
        )
        result = enforcer.evaluate(action)
        assert result.allowed is True

    def test_delegation_to_disallowed_role(
        self, enforcer: ConstitutionEnforcer
    ) -> None:
        action = _make_action(
            role="worker",
            action_type=ActionType.DELEGATION,
            details={"target_role": "orchestrator"},
        )
        result = enforcer.evaluate(action)
        assert result.allowed is False

    def test_escalation_by_worker_allowed(self, enforcer: ConstitutionEnforcer) -> None:
        action = _make_action(role="worker", action_type=ActionType.ESCALATION)
        result = enforcer.evaluate(action)
        assert result.allowed is True

    def test_escalation_by_reviewer_denied(
        self, enforcer: ConstitutionEnforcer
    ) -> None:
        action = _make_action(role="reviewer", action_type=ActionType.ESCALATION)
        result = enforcer.evaluate(action)
        assert result.allowed is False

    def test_data_access_by_worker(self, enforcer: ConstitutionEnforcer) -> None:
        action = _make_action(role="worker", action_type=ActionType.DATA_ACCESS)
        result = enforcer.evaluate(action)
        assert result.allowed is True

    def test_audit_log_grows_with_each_evaluate(
        self, enforcer: ConstitutionEnforcer
    ) -> None:
        assert len(enforcer.audit_log) == 0
        enforcer.evaluate(_make_action(role="worker", details={"tool_name": "read_x"}))
        enforcer.evaluate(_make_action(role="worker", details={"tool_name": "read_y"}))
        assert len(enforcer.audit_log) == 2

    def test_audit_log_is_copy(self, enforcer: ConstitutionEnforcer) -> None:
        enforcer.evaluate(_make_action(role="worker", details={"tool_name": "read_x"}))
        log_copy = enforcer.audit_log
        log_copy.clear()
        assert len(enforcer.audit_log) == 1

    def test_applied_constraints_listed(self, enforcer: ConstitutionEnforcer) -> None:
        action = _make_action(
            role="worker",
            action_type=ActionType.BUDGET_SPEND,
            details={"amount_usd": 10.0},
        )
        result = enforcer.evaluate(action)
        # budget_cap applies_to=["*"] -> worker is included
        assert "budget_cap" in result.applied_constraints

    def test_worker_rate_constraint_applied(
        self, enforcer: ConstitutionEnforcer
    ) -> None:
        action = _make_action(role="worker", details={"tool_name": "read_file"})
        result = enforcer.evaluate(action)
        assert "worker_rate" in result.applied_constraints

    def test_constraint_not_applied_to_wrong_role(
        self, enforcer: ConstitutionEnforcer
    ) -> None:
        action = _make_action(role="reviewer", details={"tool_name": "read_doc"})
        result = enforcer.evaluate(action)
        # worker_rate applies only to worker
        assert "worker_rate" not in result.applied_constraints

    def test_result_is_frozen_dataclass(self, enforcer: ConstitutionEnforcer) -> None:
        action = _make_action(role="worker", details={"tool_name": "read_x"})
        result = enforcer.evaluate(action)
        with pytest.raises((AttributeError, TypeError)):
            result.allowed = False  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ConstitutionEnforcer — get_required_approvals
# ---------------------------------------------------------------------------


class TestEnforcerRequiredApprovals:
    @pytest.fixture()
    def enforcer(self) -> ConstitutionEnforcer:
        return ConstitutionEnforcer(_full_constitution())

    def test_worker_budget_spend_requires_orchestrator(
        self, enforcer: ConstitutionEnforcer
    ) -> None:
        approvals = enforcer.get_required_approvals("worker", ActionType.BUDGET_SPEND)
        assert "orchestrator" in approvals

    def test_orchestrator_has_no_required_approvals(
        self, enforcer: ConstitutionEnforcer
    ) -> None:
        approvals = enforcer.get_required_approvals("orchestrator", ActionType.BUDGET_SPEND)
        assert approvals == []

    def test_tool_call_no_approval_required(
        self, enforcer: ConstitutionEnforcer
    ) -> None:
        approvals = enforcer.get_required_approvals("worker", ActionType.TOOL_CALL)
        assert approvals == []

    def test_unknown_role_returns_empty(self, enforcer: ConstitutionEnforcer) -> None:
        approvals = enforcer.get_required_approvals("ghost", ActionType.BUDGET_SPEND)
        assert approvals == []


# ---------------------------------------------------------------------------
# Constraint evaluation — budget_limit
# ---------------------------------------------------------------------------


class TestConstraintBudgetLimit:
    def test_budget_constraint_blocks_over_limit(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="agent",
                    permissions=[Permission.APPROVE],
                    max_budget_usd=10000.0,  # role allows more
                )
            ],
            constraints=[
                Constraint(
                    name="hard_cap",
                    description="Hard cap",
                    constraint_type="budget_limit",
                    parameters={"limit_usd": 100.0},
                    applies_to=["*"],
                    severity="critical",
                )
            ],
        )
        enforcer = ConstitutionEnforcer(c)
        action = _make_action(
            role="agent",
            action_type=ActionType.BUDGET_SPEND,
            details={"amount_usd": 101.0},
        )
        result = enforcer.evaluate(action)
        assert result.allowed is False
        assert any("hard_cap" in v for v in result.violations)

    def test_budget_constraint_passes_within_limit(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="agent",
                    permissions=[Permission.APPROVE],
                    max_budget_usd=10000.0,
                )
            ],
            constraints=[
                Constraint(
                    name="soft_cap",
                    description="Soft cap",
                    constraint_type="budget_limit",
                    parameters={"limit_usd": 200.0},
                    applies_to=["*"],
                    severity="error",
                )
            ],
        )
        enforcer = ConstitutionEnforcer(c)
        action = _make_action(
            role="agent",
            action_type=ActionType.BUDGET_SPEND,
            details={"amount_usd": 100.0},
        )
        result = enforcer.evaluate(action)
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Constraint evaluation — rate_limit
# ---------------------------------------------------------------------------


class TestConstraintRateLimit:
    def test_zero_rate_limit_blocks(self) -> None:
        c = _make_constitution(
            roles=[RoleDefinition(name="agent", permissions=[Permission.EXECUTE])],
            constraints=[
                Constraint(
                    name="disabled_rate",
                    description="d",
                    constraint_type="rate_limit",
                    parameters={"calls_per_minute": 0},
                    applies_to=["agent"],
                    severity="error",
                )
            ],
        )
        enforcer = ConstitutionEnforcer(c)
        action = _make_action(role="agent", details={"tool_name": "x"})
        result = enforcer.evaluate(action)
        assert result.allowed is False

    def test_positive_rate_limit_passes(self) -> None:
        c = _make_constitution(
            roles=[RoleDefinition(name="agent", permissions=[Permission.EXECUTE])],
            constraints=[
                Constraint(
                    name="normal_rate",
                    description="d",
                    constraint_type="rate_limit",
                    parameters={"calls_per_minute": 60},
                    applies_to=["agent"],
                    severity="warning",
                )
            ],
        )
        enforcer = ConstitutionEnforcer(c)
        action = _make_action(role="agent", details={"tool_name": "x"})
        result = enforcer.evaluate(action)
        assert result.allowed is True  # warning doesn't block


# ---------------------------------------------------------------------------
# Constraint evaluation — scope_limit
# ---------------------------------------------------------------------------


class TestConstraintScopeLimit:
    def test_scope_limit_blocks_out_of_scope_action(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="restricted",
                    permissions=[Permission.READ, Permission.EXECUTE],
                    allowed_tools=["*"],
                )
            ],
            constraints=[
                Constraint(
                    name="scope_guard",
                    description="Only data access",
                    constraint_type="scope_limit",
                    parameters={"allowed_action_types": ["data_access"]},
                    applies_to=["restricted"],
                    severity="error",
                )
            ],
        )
        enforcer = ConstitutionEnforcer(c)
        action = _make_action(
            role="restricted",
            action_type=ActionType.TOOL_CALL,
            details={"tool_name": "some_tool"},
        )
        result = enforcer.evaluate(action)
        assert result.allowed is False
        assert any("scope" in v.lower() for v in result.violations)

    def test_scope_limit_allows_in_scope_action(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="restricted",
                    permissions=[Permission.READ],
                )
            ],
            constraints=[
                Constraint(
                    name="scope_guard",
                    description="Only data access",
                    constraint_type="scope_limit",
                    parameters={"allowed_action_types": ["data_access"]},
                    applies_to=["restricted"],
                    severity="error",
                )
            ],
        )
        enforcer = ConstitutionEnforcer(c)
        action = _make_action(
            role="restricted",
            action_type=ActionType.DATA_ACCESS,
        )
        result = enforcer.evaluate(action)
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Constraint evaluation — safety_rule
# ---------------------------------------------------------------------------


class TestConstraintSafetyRule:
    def test_safety_rule_blocks_blocked_tool(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="agent",
                    permissions=[Permission.EXECUTE],
                    allowed_tools=["*"],
                )
            ],
            constraints=[
                Constraint(
                    name="no_rm",
                    description="Never delete",
                    constraint_type="safety_rule",
                    parameters={"blocked_tools": ["rm_*", "delete_*"]},
                    applies_to=["*"],
                    severity="critical",
                )
            ],
        )
        enforcer = ConstitutionEnforcer(c)
        action = _make_action(
            role="agent",
            action_type=ActionType.TOOL_CALL,
            details={"tool_name": "rm_everything"},
        )
        result = enforcer.evaluate(action)
        assert result.allowed is False
        assert any("rm_everything" in v for v in result.violations)

    def test_safety_rule_allows_safe_tool(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="agent",
                    permissions=[Permission.EXECUTE],
                    allowed_tools=["*"],
                )
            ],
            constraints=[
                Constraint(
                    name="no_rm",
                    description="Never delete",
                    constraint_type="safety_rule",
                    parameters={"blocked_tools": ["rm_*"]},
                    applies_to=["*"],
                    severity="critical",
                )
            ],
        )
        enforcer = ConstitutionEnforcer(c)
        action = _make_action(
            role="agent",
            action_type=ActionType.TOOL_CALL,
            details={"tool_name": "read_file"},
        )
        result = enforcer.evaluate(action)
        assert result.allowed is True

    def test_safety_rule_warning_severity_does_not_block(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="agent",
                    permissions=[Permission.EXECUTE],
                    allowed_tools=["*"],
                )
            ],
            constraints=[
                Constraint(
                    name="warn_only",
                    description="Warn but allow",
                    constraint_type="safety_rule",
                    parameters={"blocked_tools": ["risky_*"]},
                    applies_to=["*"],
                    severity="warning",
                )
            ],
        )
        enforcer = ConstitutionEnforcer(c)
        action = _make_action(
            role="agent",
            action_type=ActionType.TOOL_CALL,
            details={"tool_name": "risky_tool"},
        )
        result = enforcer.evaluate(action)
        # warning severity adds to warnings, not violations
        assert result.allowed is True
        assert len(result.warnings) > 0


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------


class TestConflictDetection:
    @pytest.fixture()
    def resolver(self) -> ConflictResolver:
        return ConflictResolver(_full_constitution())

    def test_no_conflict_different_resources(
        self, resolver: ConflictResolver
    ) -> None:
        actions = [
            _make_action(
                agent_id="a1",
                role="worker",
                action_type=ActionType.TOOL_CALL,
                details={"resource": "file_a.txt"},
            ),
            _make_action(
                agent_id="a2",
                role="reviewer",
                action_type=ActionType.TOOL_CALL,
                details={"resource": "file_b.txt"},
            ),
        ]
        conflicts = resolver.detect_conflict(actions)
        assert conflicts == []

    def test_resource_write_conflict(self, resolver: ConflictResolver) -> None:
        actions = [
            _make_action(
                agent_id="a1",
                role="worker",
                action_type=ActionType.TOOL_CALL,
                details={"resource": "shared.csv"},
            ),
            _make_action(
                agent_id="a2",
                role="orchestrator",
                action_type=ActionType.TOOL_CALL,
                details={"resource": "shared.csv"},
            ),
        ]
        conflicts = resolver.detect_conflict(actions)
        assert len(conflicts) == 1
        assert conflicts[0].agent_a == "a1"
        assert conflicts[0].agent_b == "a2"

    def test_budget_conflict(self, resolver: ConflictResolver) -> None:
        actions = [
            _make_action(
                agent_id="a1",
                role="worker",
                action_type=ActionType.BUDGET_SPEND,
                details={"budget_key": "project_budget"},
            ),
            _make_action(
                agent_id="a2",
                role="worker",
                action_type=ActionType.BUDGET_SPEND,
                details={"budget_key": "project_budget"},
            ),
        ]
        conflicts = resolver.detect_conflict(actions)
        assert len(conflicts) == 1
        assert "project_budget" in conflicts[0].description

    def test_delegation_overlap_conflict(self, resolver: ConflictResolver) -> None:
        actions = [
            _make_action(
                agent_id="a1",
                role="orchestrator",
                action_type=ActionType.DELEGATION,
                details={"target_role": "worker"},
            ),
            _make_action(
                agent_id="a2",
                role="orchestrator",
                action_type=ActionType.DELEGATION,
                details={"target_role": "worker"},
            ),
        ]
        conflicts = resolver.detect_conflict(actions)
        assert len(conflicts) == 1

    def test_escalation_conflict(self, resolver: ConflictResolver) -> None:
        actions = [
            _make_action(
                agent_id="a1", role="worker", action_type=ActionType.ESCALATION
            ),
            _make_action(
                agent_id="a2", role="worker", action_type=ActionType.ESCALATION
            ),
        ]
        conflicts = resolver.detect_conflict(actions)
        assert len(conflicts) == 1

    def test_same_agent_no_conflict(self, resolver: ConflictResolver) -> None:
        action = _make_action(
            agent_id="a1",
            role="worker",
            action_type=ActionType.TOOL_CALL,
            details={"resource": "file.csv"},
        )
        conflicts = resolver.detect_conflict([action, action])
        assert conflicts == []

    def test_no_resource_key_no_conflict(self, resolver: ConflictResolver) -> None:
        actions = [
            _make_action(agent_id="a1", role="worker", action_type=ActionType.TOOL_CALL),
            _make_action(agent_id="a2", role="worker", action_type=ActionType.TOOL_CALL),
        ]
        conflicts = resolver.detect_conflict(actions)
        assert conflicts == []

    def test_empty_actions_no_conflict(self, resolver: ConflictResolver) -> None:
        assert resolver.detect_conflict([]) == []

    def test_single_action_no_conflict(self, resolver: ConflictResolver) -> None:
        action = _make_action(
            agent_id="a1",
            role="worker",
            action_type=ActionType.TOOL_CALL,
            details={"resource": "x"},
        )
        assert resolver.detect_conflict([action]) == []


# ---------------------------------------------------------------------------
# Conflict resolution — PRIORITY_BASED
# ---------------------------------------------------------------------------


class TestResolvePriorityBased:
    def test_higher_priority_role_wins(self) -> None:
        c = _full_constitution()  # orchestrator idx=0, worker idx=1
        resolver = ConflictResolver(c)

        actions = [
            _make_action(agent_id="worker_agent", role="worker"),
            _make_action(agent_id="orch_agent", role="orchestrator"),
        ]
        conflict = Conflict(
            agent_a="worker_agent",
            agent_b="orch_agent",
            description="test",
            conflicting_actions=actions,
        )
        resolution = resolver.resolve_by_priority(conflict)
        assert resolution.winner == "orch_agent"
        assert resolution.strategy_used == ConflictStrategy.PRIORITY_BASED

    def test_unknown_role_lowest_priority(self) -> None:
        c = _full_constitution()
        resolver = ConflictResolver(c)

        actions = [
            _make_action(agent_id="known", role="orchestrator"),
            _make_action(agent_id="unknown", role="phantom"),
        ]
        conflict = Conflict(
            agent_a="known",
            agent_b="unknown",
            description="test",
            conflicting_actions=actions,
        )
        resolution = resolver.resolve_by_priority(conflict)
        assert resolution.winner == "known"

    def test_equal_priority_timestamp_tiebreak(self) -> None:
        c = _full_constitution()
        resolver = ConflictResolver(c)

        early = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        late = datetime(2026, 1, 1, 12, 0, 1, tzinfo=timezone.utc)

        actions = [
            AgentAction(
                agent_id="late_agent",
                role="worker",
                action_type=ActionType.TOOL_CALL,
                details={},
                timestamp=late,
            ),
            AgentAction(
                agent_id="early_agent",
                role="worker",
                action_type=ActionType.TOOL_CALL,
                details={},
                timestamp=early,
            ),
        ]
        conflict = Conflict(
            agent_a="late_agent",
            agent_b="early_agent",
            description="tie",
            conflicting_actions=actions,
        )
        resolution = resolver.resolve_by_priority(conflict)
        assert resolution.winner == "early_agent"


# ---------------------------------------------------------------------------
# Conflict resolution — MOST_RESTRICTIVE
# ---------------------------------------------------------------------------


class TestResolveMostRestrictive:
    def test_fewer_permissions_wins(self) -> None:
        c = _full_constitution()  # reviewer (2 perms) vs orchestrator (6 perms)
        resolver = ConflictResolver(c)

        actions = [
            _make_action(agent_id="orch_agent", role="orchestrator"),
            _make_action(agent_id="rev_agent", role="reviewer"),
        ]
        conflict = Conflict(
            agent_a="orch_agent",
            agent_b="rev_agent",
            description="test",
            conflicting_actions=actions,
        )
        resolution = resolver.resolve_most_restrictive(conflict)
        assert resolution.winner == "rev_agent"
        assert resolution.strategy_used == ConflictStrategy.MOST_RESTRICTIVE

    def test_lower_budget_cap_wins(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="rich",
                    permissions=[Permission.READ],
                    max_budget_usd=1000.0,
                ),
                RoleDefinition(
                    name="poor",
                    permissions=[Permission.READ],
                    max_budget_usd=10.0,
                ),
            ]
        )
        resolver = ConflictResolver(c)

        actions = [
            _make_action(agent_id="rich_agent", role="rich"),
            _make_action(agent_id="poor_agent", role="poor"),
        ]
        conflict = Conflict(
            agent_a="rich_agent",
            agent_b="poor_agent",
            description="test",
            conflicting_actions=actions,
        )
        resolution = resolver.resolve_most_restrictive(conflict)
        assert resolution.winner == "poor_agent"

    def test_constitution_level_strategy_dispatches(self) -> None:
        c = _make_constitution(
            conflict_strategy=ConflictStrategy.MOST_RESTRICTIVE,
            roles=[
                RoleDefinition(
                    name="full", permissions=list(Permission), max_budget_usd=500.0
                ),
                RoleDefinition(
                    name="minimal",
                    permissions=[Permission.READ],
                    max_budget_usd=10.0,
                ),
            ],
        )
        resolver = ConflictResolver(c)
        actions = [
            _make_action(agent_id="full_agent", role="full"),
            _make_action(agent_id="minimal_agent", role="minimal"),
        ]
        conflict = Conflict(
            agent_a="full_agent",
            agent_b="minimal_agent",
            description="test",
            conflicting_actions=actions,
        )
        resolution = resolver.resolve(conflict)
        assert resolution.strategy_used == ConflictStrategy.MOST_RESTRICTIVE
        assert resolution.winner == "minimal_agent"


# ---------------------------------------------------------------------------
# Conflict resolution — LEADER_DECIDES
# ---------------------------------------------------------------------------


class TestResolveLeaderDecides:
    def test_leader_wins_when_present(self) -> None:
        c = _make_constitution(
            conflict_strategy=ConflictStrategy.LEADER_DECIDES,
            roles=[
                RoleDefinition(name="orchestrator"),  # index 0 = leader
                RoleDefinition(name="worker"),
            ],
        )
        resolver = ConflictResolver(c)
        actions = [
            _make_action(agent_id="w_agent", role="worker"),
            _make_action(agent_id="o_agent", role="orchestrator"),
        ]
        conflict = Conflict(
            agent_a="w_agent",
            agent_b="o_agent",
            description="test",
            conflicting_actions=actions,
        )
        resolution = resolver.resolve(conflict)
        assert resolution.winner == "o_agent"
        assert resolution.strategy_used == ConflictStrategy.LEADER_DECIDES

    def test_fallback_to_priority_when_no_leader(self) -> None:
        c = _make_constitution(
            conflict_strategy=ConflictStrategy.LEADER_DECIDES,
            roles=[
                RoleDefinition(name="orchestrator"),
                RoleDefinition(name="worker"),
            ],
        )
        resolver = ConflictResolver(c)
        # Neither agent is orchestrator
        actions = [
            _make_action(agent_id="w1", role="worker"),
            _make_action(agent_id="w2", role="worker"),
        ]
        conflict = Conflict(
            agent_a="w1", agent_b="w2", description="test", conflicting_actions=actions
        )
        resolution = resolver.resolve(conflict)
        assert resolution.strategy_used == ConflictStrategy.LEADER_DECIDES
        assert resolution.winner is not None

    def test_empty_roles_falls_back_gracefully(self) -> None:
        c = _make_constitution(
            conflict_strategy=ConflictStrategy.LEADER_DECIDES, roles=[]
        )
        resolver = ConflictResolver(c)
        actions = [
            _make_action(agent_id="a", role="worker"),
            _make_action(agent_id="b", role="worker"),
        ]
        conflict = Conflict(
            agent_a="a", agent_b="b", description="test", conflicting_actions=actions
        )
        resolution = resolver.resolve(conflict)
        # Should not raise
        assert resolution.winner is not None or resolution.winner is None


# ---------------------------------------------------------------------------
# Conflict resolution — CONSENSUS
# ---------------------------------------------------------------------------


class TestResolveConsensus:
    def test_consensus_when_same_action_type(self) -> None:
        c = _make_constitution(
            conflict_strategy=ConflictStrategy.CONSENSUS,
            roles=[
                RoleDefinition(name="a"),
                RoleDefinition(name="b"),
            ],
        )
        resolver = ConflictResolver(c)

        early = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        late = datetime(2026, 1, 1, 11, 0, 0, tzinfo=timezone.utc)

        actions = [
            AgentAction(
                agent_id="agent_late",
                role="a",
                action_type=ActionType.DATA_ACCESS,
                details={},
                timestamp=late,
            ),
            AgentAction(
                agent_id="agent_early",
                role="b",
                action_type=ActionType.DATA_ACCESS,
                details={},
                timestamp=early,
            ),
        ]
        conflict = Conflict(
            agent_a="agent_late",
            agent_b="agent_early",
            description="test",
            conflicting_actions=actions,
        )
        resolution = resolver.resolve(conflict)
        assert resolution.strategy_used == ConflictStrategy.CONSENSUS
        assert resolution.winner == "agent_early"
        assert "consensus" in resolution.resolution.lower()

    def test_no_consensus_falls_back_to_priority(self) -> None:
        c = _make_constitution(
            conflict_strategy=ConflictStrategy.CONSENSUS,
            roles=[
                RoleDefinition(name="a"),
                RoleDefinition(name="b"),
            ],
        )
        resolver = ConflictResolver(c)

        actions = [
            _make_action(agent_id="x", role="a", action_type=ActionType.TOOL_CALL),
            _make_action(agent_id="y", role="b", action_type=ActionType.ESCALATION),
        ]
        conflict = Conflict(
            agent_a="x",
            agent_b="y",
            description="test",
            conflicting_actions=actions,
        )
        resolution = resolver.resolve(conflict)
        assert resolution.strategy_used == ConflictStrategy.CONSENSUS
        assert "fallback" in resolution.details


# ---------------------------------------------------------------------------
# ConstitutionEnforcer — constructor validation
# ---------------------------------------------------------------------------


class TestEnforcerConstructor:
    def test_invalid_type_raises(self) -> None:
        with pytest.raises(TypeError):
            ConstitutionEnforcer("not a constitution")  # type: ignore[arg-type]

    def test_empty_constitution_accepted(self) -> None:
        c = _make_constitution()
        enforcer = ConstitutionEnforcer(c)
        assert enforcer is not None


# ---------------------------------------------------------------------------
# AgentAction dataclass
# ---------------------------------------------------------------------------


class TestAgentAction:
    def test_frozen(self) -> None:
        action = _make_action()
        with pytest.raises((AttributeError, TypeError)):
            action.role = "other"  # type: ignore[misc]

    def test_default_timestamp_utc(self) -> None:
        action = _make_action()
        assert action.timestamp.tzinfo is not None

    def test_all_action_types(self) -> None:
        for at in ActionType:
            action = _make_action(action_type=at)
            assert action.action_type == at


# ---------------------------------------------------------------------------
# CLI — constitution validate
# ---------------------------------------------------------------------------


class TestCLIConstitutionValidate:
    @pytest.fixture()
    def runner(self) -> CliRunner:
        return CliRunner()

    @pytest.fixture()
    def valid_yaml(self, tmp_path: "pytest.TempPathFactory") -> str:
        c = _full_constitution()
        path = tmp_path / "constitution.yaml"
        path.write_text(c.to_yaml(), encoding="utf-8")
        return str(path)

    def test_valid_constitution_exits_zero(
        self, runner: CliRunner, valid_yaml: str
    ) -> None:
        from aumos_cowork_governance.cli.main import cli

        result = runner.invoke(cli, ["constitution", "validate", "--file", valid_yaml])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_invalid_constitution_exits_nonzero(
        self, runner: CliRunner, tmp_path: "pytest.TempPathFactory"
    ) -> None:
        from aumos_cowork_governance.cli.main import cli

        c = _make_constitution(
            roles=[RoleDefinition(name="a", can_delegate_to=["ghost"])]
        )
        path = tmp_path / "bad.yaml"
        path.write_text(c.to_yaml(), encoding="utf-8")

        result = runner.invoke(cli, ["constitution", "validate", "--file", str(path)])
        assert result.exit_code != 0

    def test_bad_yaml_exits_nonzero(
        self, runner: CliRunner, tmp_path: "pytest.TempPathFactory"
    ) -> None:
        from aumos_cowork_governance.cli.main import cli

        path = tmp_path / "bad.yaml"
        path.write_text("team_name: missing_colon\nversion: [", encoding="utf-8")

        result = runner.invoke(cli, ["constitution", "validate", "--file", str(path)])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# CLI — constitution check
# ---------------------------------------------------------------------------


class TestCLIConstitutionCheck:
    @pytest.fixture()
    def runner(self) -> CliRunner:
        return CliRunner()

    @pytest.fixture()
    def constitution_file(self, tmp_path: "pytest.TempPathFactory") -> str:
        c = _full_constitution()
        path = tmp_path / "constitution.yaml"
        path.write_text(c.to_yaml(), encoding="utf-8")
        return str(path)

    def test_allowed_action_exits_zero(
        self, runner: CliRunner, constitution_file: str
    ) -> None:
        from aumos_cowork_governance.cli.main import cli

        result = runner.invoke(
            cli,
            [
                "constitution",
                "check",
                "--file",
                constitution_file,
                "--role",
                "worker",
                "--action",
                "tool_call",
                "--detail",
                "tool_name=read_file",
            ],
        )
        assert result.exit_code == 0

    def test_denied_action_exits_nonzero(
        self, runner: CliRunner, constitution_file: str
    ) -> None:
        from aumos_cowork_governance.cli.main import cli

        result = runner.invoke(
            cli,
            [
                "constitution",
                "check",
                "--file",
                constitution_file,
                "--role",
                "worker",
                "--action",
                "tool_call",
                "--detail",
                "tool_name=admin_reset",
            ],
        )
        assert result.exit_code != 0

    def test_unknown_role_exits_nonzero(
        self, runner: CliRunner, constitution_file: str
    ) -> None:
        from aumos_cowork_governance.cli.main import cli

        result = runner.invoke(
            cli,
            [
                "constitution",
                "check",
                "--file",
                constitution_file,
                "--role",
                "nonexistent",
                "--action",
                "tool_call",
            ],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# CLI — constitution init
# ---------------------------------------------------------------------------


class TestCLIConstitutionInit:
    @pytest.fixture()
    def runner(self) -> CliRunner:
        return CliRunner()

    def test_init_creates_file(
        self, runner: CliRunner, tmp_path: "pytest.TempPathFactory"
    ) -> None:
        from aumos_cowork_governance.cli.main import cli

        output_file = str(tmp_path / "starter.yaml")
        result = runner.invoke(
            cli,
            [
                "constitution",
                "init",
                "--team-name",
                "awesome-team",
                "--output",
                output_file,
            ],
        )
        assert result.exit_code == 0, result.output
        import os

        assert os.path.exists(output_file)

    def test_init_file_is_valid_yaml(
        self, runner: CliRunner, tmp_path: "pytest.TempPathFactory"
    ) -> None:
        from aumos_cowork_governance.cli.main import cli

        output_file = str(tmp_path / "starter.yaml")
        runner.invoke(
            cli,
            [
                "constitution",
                "init",
                "--team-name",
                "my-team",
                "--output",
                output_file,
            ],
        )
        with open(output_file, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        assert data["team_name"] == "my-team"

    def test_init_output_parseable_as_constitution(
        self, runner: CliRunner, tmp_path: "pytest.TempPathFactory"
    ) -> None:
        from aumos_cowork_governance.cli.main import cli

        output_file = str(tmp_path / "starter.yaml")
        runner.invoke(
            cli,
            [
                "constitution",
                "init",
                "--team-name",
                "parse-test",
                "--output",
                output_file,
            ],
        )
        with open(output_file, encoding="utf-8") as fh:
            raw = fh.read()
        constitution = Constitution.from_yaml(raw)
        assert constitution.team_name == "parse-test"
        assert len(constitution.roles) > 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_constitution_enforcer_unknown_role(self) -> None:
        c = _make_constitution()
        enforcer = ConstitutionEnforcer(c)
        result = enforcer.evaluate(_make_action(role="ghost"))
        assert result.allowed is False

    def test_conflicting_constraints_both_apply(self) -> None:
        """Two constraints both matching — most severe wins via violations list."""
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="agent",
                    permissions=[Permission.APPROVE],
                    max_budget_usd=10000.0,
                )
            ],
            constraints=[
                Constraint(
                    name="low_cap",
                    description="Low cap",
                    constraint_type="budget_limit",
                    parameters={"limit_usd": 50.0},
                    applies_to=["*"],
                    severity="error",
                ),
                Constraint(
                    name="high_cap",
                    description="High cap",
                    constraint_type="budget_limit",
                    parameters={"limit_usd": 500.0},
                    applies_to=["*"],
                    severity="warning",
                ),
            ],
        )
        enforcer = ConstitutionEnforcer(c)
        action = _make_action(
            role="agent",
            action_type=ActionType.BUDGET_SPEND,
            details={"amount_usd": 75.0},
        )
        result = enforcer.evaluate(action)
        assert result.allowed is False  # low_cap error-severity blocks
        assert any("low_cap" in v for v in result.violations)

    def test_data_access_no_resource_no_conflict(self) -> None:
        c = _full_constitution()
        resolver = ConflictResolver(c)
        actions = [
            _make_action(agent_id="a1", role="worker", action_type=ActionType.DATA_ACCESS),
            _make_action(agent_id="a2", role="worker", action_type=ActionType.DATA_ACCESS),
        ]
        conflicts = resolver.detect_conflict(actions)
        assert conflicts == []

    def test_agent_action_details_empty_dict(self) -> None:
        action = AgentAction(
            agent_id="x",
            role="worker",
            action_type=ActionType.TOOL_CALL,
            details={},
            timestamp=_now(),
        )
        assert action.details == {}

    def test_constitution_with_single_role_valid(self) -> None:
        c = _make_constitution(
            roles=[RoleDefinition(name="solo", permissions=[Permission.READ])]
        )
        errors = c.validate_constitution()
        assert errors == []

    def test_enforcer_approve_permission_for_budget_spend(self) -> None:
        c = _make_constitution(
            roles=[
                RoleDefinition(
                    name="spending_role",
                    permissions=[Permission.READ],  # no APPROVE
                    max_budget_usd=1000.0,
                )
            ]
        )
        enforcer = ConstitutionEnforcer(c)
        action = _make_action(
            role="spending_role",
            action_type=ActionType.BUDGET_SPEND,
            details={"amount_usd": 5.0},
        )
        result = enforcer.evaluate(action)
        assert result.allowed is False
        assert any("approve" in v.lower() for v in result.violations)

    def test_constitution_starter_passes_yaml_round_trip(self) -> None:
        c = Constitution.starter("round-trip-team")
        restored = Constitution.from_yaml(c.to_yaml())
        errors = restored.validate_constitution()
        assert errors == []
