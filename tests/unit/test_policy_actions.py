"""Unit tests for policies/actions.py — PolicyActionHandler."""
from __future__ import annotations

from unittest.mock import MagicMock, call

import pytest

from aumos_cowork_governance.policies.actions import PolicyActionHandler, PolicyBlockedError
from aumos_cowork_governance.policies.engine import PolicyAction, PolicyResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def handler() -> PolicyActionHandler:
    return PolicyActionHandler()


@pytest.fixture()
def audit_mock() -> MagicMock:
    return MagicMock()


@pytest.fixture()
def queue_mock() -> MagicMock:
    return MagicMock()


def _make_result(
    action: PolicyAction,
    matched: bool = True,
    policy_name: str = "test-policy",
    message: str = "test message",
    notify: list[str] | None = None,
) -> PolicyResult:
    return PolicyResult(
        policy_name=policy_name,
        matched=matched,
        action=action,
        message=message,
        notify=notify or [],
    )


# ---------------------------------------------------------------------------
# PolicyBlockedError
# ---------------------------------------------------------------------------


class TestPolicyBlockedError:
    def test_attributes_stored(self) -> None:
        err = PolicyBlockedError("my-policy", "Access denied.")
        assert err.policy_name == "my-policy"
        assert err.message == "Access denied."

    def test_exception_message_contains_policy_name(self) -> None:
        err = PolicyBlockedError("my-policy", "Access denied.")
        assert "my-policy" in str(err)

    def test_is_exception_subclass(self) -> None:
        assert issubclass(PolicyBlockedError, Exception)


# ---------------------------------------------------------------------------
# PolicyActionHandler — unmatched result is no-op
# ---------------------------------------------------------------------------


class TestPolicyActionHandlerUnmatched:
    def test_unmatched_result_is_no_op(self, handler: PolicyActionHandler) -> None:
        result = _make_result(PolicyAction.BLOCK, matched=False)
        # Should not raise PolicyBlockedError.
        handler.execute(result, {})

    def test_unmatched_result_with_audit_does_not_log(
        self, audit_mock: MagicMock
    ) -> None:
        handler = PolicyActionHandler(audit_logger=audit_mock)
        result = _make_result(PolicyAction.LOG, matched=False)
        handler.execute(result, {})
        audit_mock.log.assert_not_called()


# ---------------------------------------------------------------------------
# BLOCK action
# ---------------------------------------------------------------------------


class TestPolicyActionHandlerBlock:
    def test_block_raises_policy_blocked_error(self, handler: PolicyActionHandler) -> None:
        result = _make_result(PolicyAction.BLOCK)
        with pytest.raises(PolicyBlockedError) as exc_info:
            handler.execute(result, {"action": "file_delete"})
        assert exc_info.value.policy_name == "test-policy"

    def test_block_with_audit_logs_event(self, audit_mock: MagicMock) -> None:
        handler = PolicyActionHandler(audit_logger=audit_mock)
        result = _make_result(PolicyAction.BLOCK)
        with pytest.raises(PolicyBlockedError):
            handler.execute(result, {"action": "file_delete"})
        audit_mock.log.assert_called_once()
        logged = audit_mock.log.call_args[0][0]
        assert logged["event"] == "policy_block"
        assert logged["policy"] == "test-policy"


# ---------------------------------------------------------------------------
# WARN action
# ---------------------------------------------------------------------------


class TestPolicyActionHandlerWarn:
    def test_warn_does_not_raise(self, handler: PolicyActionHandler) -> None:
        result = _make_result(PolicyAction.WARN)
        handler.execute(result, {})  # Should not raise.

    def test_warn_with_audit_logs_warn_event(self, audit_mock: MagicMock) -> None:
        handler = PolicyActionHandler(audit_logger=audit_mock)
        result = _make_result(PolicyAction.WARN)
        handler.execute(result, {"path": "/tmp/x"})
        audit_mock.log.assert_called_once()
        logged = audit_mock.log.call_args[0][0]
        assert logged["event"] == "policy_warn"


# ---------------------------------------------------------------------------
# LOG action
# ---------------------------------------------------------------------------


class TestPolicyActionHandlerLog:
    def test_log_does_not_raise(self, handler: PolicyActionHandler) -> None:
        result = _make_result(PolicyAction.LOG)
        handler.execute(result, {})

    def test_log_with_audit_logs_log_event(self, audit_mock: MagicMock) -> None:
        handler = PolicyActionHandler(audit_logger=audit_mock)
        result = _make_result(PolicyAction.LOG)
        handler.execute(result, {})
        audit_mock.log.assert_called_once()
        logged = audit_mock.log.call_args[0][0]
        assert logged["event"] == "policy_log"


# ---------------------------------------------------------------------------
# APPROVE action
# ---------------------------------------------------------------------------


class TestPolicyActionHandlerApprove:
    def test_approve_calls_queue_enqueue(self, queue_mock: MagicMock) -> None:
        handler = PolicyActionHandler(approval_queue=queue_mock)
        result = _make_result(
            PolicyAction.APPROVE,
            notify=["approver@example.com"],
        )
        handler.execute(result, {"action": "file_delete"})
        queue_mock.enqueue.assert_called_once()

    def test_approve_with_audit_logs_approve_queued(
        self, audit_mock: MagicMock, queue_mock: MagicMock
    ) -> None:
        handler = PolicyActionHandler(
            audit_logger=audit_mock, approval_queue=queue_mock
        )
        result = _make_result(PolicyAction.APPROVE)
        handler.execute(result, {})
        audit_mock.log.assert_called_once()
        logged = audit_mock.log.call_args[0][0]
        assert logged["event"] == "policy_approve_queued"

    def test_approve_without_queue_does_not_raise(
        self, handler: PolicyActionHandler
    ) -> None:
        result = _make_result(PolicyAction.APPROVE)
        handler.execute(result, {})  # Should not raise.


# ---------------------------------------------------------------------------
# ALLOW action
# ---------------------------------------------------------------------------


class TestPolicyActionHandlerAllow:
    def test_allow_is_no_op(self, handler: PolicyActionHandler) -> None:
        result = _make_result(PolicyAction.ALLOW)
        handler.execute(result, {})  # Should not raise.


# ---------------------------------------------------------------------------
# execute_all
# ---------------------------------------------------------------------------


class TestPolicyActionHandlerExecuteAll:
    def test_execute_all_processes_matched_results(
        self, audit_mock: MagicMock
    ) -> None:
        handler = PolicyActionHandler(audit_logger=audit_mock)
        results = [
            _make_result(PolicyAction.LOG, matched=True),
            _make_result(PolicyAction.WARN, matched=False),
            _make_result(PolicyAction.LOG, matched=True, policy_name="second"),
        ]
        handler.execute_all(results, {})
        assert audit_mock.log.call_count == 2

    def test_execute_all_stops_at_block(
        self, audit_mock: MagicMock
    ) -> None:
        handler = PolicyActionHandler(audit_logger=audit_mock)
        results = [
            _make_result(PolicyAction.BLOCK, matched=True, policy_name="blocker"),
            _make_result(PolicyAction.LOG, matched=True, policy_name="logger"),
        ]
        with pytest.raises(PolicyBlockedError):
            handler.execute_all(results, {})
        # Only the block was logged (via _handle_block), not the second LOG.
        calls_events = [call[0][0]["event"] for call in audit_mock.log.call_args_list]
        assert "policy_log" not in calls_events
