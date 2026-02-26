"""Tests for ApprovalGate (gates.py)."""
from __future__ import annotations

import pytest

from aumos_cowork_governance.approval.gates import ApprovalGate, GateConfig


@pytest.fixture()
def gate() -> ApprovalGate:
    # llm_call uses require_approval=True so that auto_approve_below_cost is
    # evaluated: costs strictly below 0.10 are auto-approved; at or above 0.10
    # approval is required.
    return ApprovalGate(gates=[
        GateConfig(action_patterns=["file_delete*"], require_approval=True),
        GateConfig(action_patterns=["llm_call"], require_approval=True, auto_approve_below_cost=0.10),
        GateConfig(action_patterns=["admin_*"], require_approval=False, required_role="admin"),
    ])


# ---------------------------------------------------------------------------
# GateConfig
# ---------------------------------------------------------------------------


class TestGateConfig:
    def test_defaults(self) -> None:
        config = GateConfig(action_patterns=["act*"], require_approval=True)
        assert config.auto_approve_below_cost == 0.0
        assert config.required_role is None

    def test_custom_fields(self) -> None:
        config = GateConfig(
            action_patterns=["act*"],
            require_approval=True,
            auto_approve_below_cost=0.5,
            required_role="ops",
        )
        assert config.auto_approve_below_cost == 0.5
        assert config.required_role == "ops"


# ---------------------------------------------------------------------------
# ApprovalGate — construction and add_gate
# ---------------------------------------------------------------------------


class TestApprovalGateConstruction:
    def test_empty_gates(self) -> None:
        gate = ApprovalGate()
        assert gate.gates == []

    def test_initial_gates(self, gate: ApprovalGate) -> None:
        assert len(gate.gates) == 3

    def test_add_gate_appends(self) -> None:
        gate = ApprovalGate()
        config = GateConfig(action_patterns=["new_action"], require_approval=True)
        gate.add_gate(config)
        assert len(gate.gates) == 1

    def test_gates_property_is_copy(self, gate: ApprovalGate) -> None:
        gates_copy = gate.gates
        gates_copy.append(GateConfig(action_patterns=["extra"], require_approval=False))
        assert len(gate.gates) == 3  # Original unchanged


# ---------------------------------------------------------------------------
# ApprovalGate — needs_approval
# ---------------------------------------------------------------------------


class TestNeedsApproval:
    def test_no_match_returns_false(self, gate: ApprovalGate) -> None:
        assert gate.needs_approval("unknown_action") is False

    def test_file_delete_requires_approval(self, gate: ApprovalGate) -> None:
        assert gate.needs_approval("file_delete") is True

    def test_file_delete_glob_matches_variants(self, gate: ApprovalGate) -> None:
        assert gate.needs_approval("file_delete_recursive") is True
        assert gate.needs_approval("file_delete_all") is True

    def test_llm_call_no_approval_within_cost(self, gate: ApprovalGate) -> None:
        assert gate.needs_approval("llm_call", estimated_cost=0.05) is False

    def test_llm_call_requires_approval_above_cost(self, gate: ApprovalGate) -> None:
        assert gate.needs_approval("llm_call", estimated_cost=0.20) is True

    def test_llm_call_exactly_at_threshold_still_requires_approval(self, gate: ApprovalGate) -> None:
        # estimated_cost < auto_approve_below_cost (strict less-than)
        assert gate.needs_approval("llm_call", estimated_cost=0.10) is True

    def test_admin_action_with_correct_role_no_approval(self, gate: ApprovalGate) -> None:
        assert gate.needs_approval("admin_purge", actor_role="admin") is False

    def test_admin_action_without_role_requires_approval(self, gate: ApprovalGate) -> None:
        assert gate.needs_approval("admin_purge", actor_role=None) is True

    def test_admin_action_wrong_role_requires_approval(self, gate: ApprovalGate) -> None:
        assert gate.needs_approval("admin_purge", actor_role="user") is True

    def test_require_approval_with_role_bypass(self) -> None:
        gate = ApprovalGate(gates=[
            GateConfig(
                action_patterns=["sensitive_*"],
                require_approval=True,
                required_role="security-admin",
            )
        ])
        assert gate.needs_approval("sensitive_data_export", actor_role="security-admin") is False
        assert gate.needs_approval("sensitive_data_export", actor_role="analyst") is True

    def test_first_matching_gate_wins(self) -> None:
        gate = ApprovalGate(gates=[
            GateConfig(action_patterns=["data_*"], require_approval=True),
            GateConfig(action_patterns=["data_read"], require_approval=False),
        ])
        # First gate matches "data_read" — approval required
        assert gate.needs_approval("data_read") is True

    def test_cost_zero_no_auto_approve_threshold(self, gate: ApprovalGate) -> None:
        # file_delete has no auto_approve threshold, so even cost 0 requires approval
        assert gate.needs_approval("file_delete", estimated_cost=0.0) is True

    def test_empty_gate_no_approval_for_anything(self) -> None:
        gate = ApprovalGate()
        assert gate.needs_approval("any_action") is False
        assert gate.needs_approval("delete_everything") is False
