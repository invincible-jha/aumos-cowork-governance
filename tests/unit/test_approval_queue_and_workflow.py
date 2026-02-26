"""Tests for ApprovalQueue and ApprovalWorkflow."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from aumos_cowork_governance.approval.queue import (
    ApprovalQueue,
    ApprovalRequest as QueueRequest,
    ApprovalStatus as QueueStatus,
)
from aumos_cowork_governance.approval.workflow import (
    ApprovalWorkflow,
    ApprovalRequest as WorkflowRequest,
    ApprovalStatus as WorkflowStatus,
)


# ---------------------------------------------------------------------------
# ApprovalQueue — enqueue
# ---------------------------------------------------------------------------


@pytest.fixture()
def queue() -> ApprovalQueue:
    return ApprovalQueue()


class TestApprovalQueueEnqueue:
    def test_enqueue_returns_request_id(self, queue: ApprovalQueue) -> None:
        rid = queue.enqueue(
            action_context={"action": "file_delete"},
            policy_name="require-approval-delete",
            message="Approval needed.",
        )
        assert isinstance(rid, str)
        assert rid

    def test_enqueue_custom_request_id(self, queue: ApprovalQueue) -> None:
        rid = queue.enqueue(
            action_context={"action": "x"},
            policy_name="p",
            message="m",
            request_id="custom-id-123",
        )
        assert rid == "custom-id-123"

    def test_enqueue_stores_request(self, queue: ApprovalQueue) -> None:
        rid = queue.enqueue(action_context={}, policy_name="p", message="m")
        request = queue.get(rid)
        assert request.request_id == rid
        assert request.status == QueueStatus.PENDING

    def test_enqueue_with_notify(self, queue: ApprovalQueue) -> None:
        rid = queue.enqueue(
            action_context={},
            policy_name="p",
            message="m",
            notify=["admin@example.com"],
        )
        request = queue.get(rid)
        assert "admin@example.com" in request.notify

    def test_enqueue_overflow_raises(self) -> None:
        small_queue = ApprovalQueue(max_pending=2)
        small_queue.enqueue(action_context={}, policy_name="p", message="m")
        small_queue.enqueue(action_context={}, policy_name="p", message="m")
        with pytest.raises(OverflowError):
            small_queue.enqueue(action_context={}, policy_name="p", message="m")

    def test_enqueue_after_approval_allows_more_pending(self, queue: ApprovalQueue) -> None:
        small_queue = ApprovalQueue(max_pending=1)
        rid = small_queue.enqueue(action_context={}, policy_name="p", message="m")
        small_queue.approve(rid)
        # Now queue has 0 pending, so we can enqueue again
        rid2 = small_queue.enqueue(action_context={}, policy_name="p", message="m")
        assert rid2


# ---------------------------------------------------------------------------
# ApprovalQueue — approve / deny / timeout / cancel
# ---------------------------------------------------------------------------


class TestApprovalQueueTransitions:
    def test_approve_transitions_to_approved(self, queue: ApprovalQueue) -> None:
        rid = queue.enqueue(action_context={}, policy_name="p", message="m")
        queue.approve(rid, reviewer="alice", note="Looks good")
        request = queue.get(rid)
        assert request.status == QueueStatus.APPROVED
        assert request.reviewer == "alice"
        assert request.review_note == "Looks good"

    def test_deny_transitions_to_denied(self, queue: ApprovalQueue) -> None:
        rid = queue.enqueue(action_context={}, policy_name="p", message="m")
        queue.deny(rid, reviewer="bob", note="Too risky")
        request = queue.get(rid)
        assert request.status == QueueStatus.DENIED

    def test_timeout_transitions_to_timed_out(self, queue: ApprovalQueue) -> None:
        rid = queue.enqueue(action_context={}, policy_name="p", message="m")
        queue.timeout(rid)
        request = queue.get(rid)
        assert request.status == QueueStatus.TIMED_OUT

    def test_cancel_transitions_to_cancelled(self, queue: ApprovalQueue) -> None:
        rid = queue.enqueue(action_context={}, policy_name="p", message="m")
        queue.cancel(rid)
        request = queue.get(rid)
        assert request.status == QueueStatus.CANCELLED

    def test_double_approve_raises_value_error(self, queue: ApprovalQueue) -> None:
        rid = queue.enqueue(action_context={}, policy_name="p", message="m")
        queue.approve(rid)
        with pytest.raises(ValueError, match="not PENDING"):
            queue.approve(rid)

    def test_approve_nonexistent_raises_key_error(self, queue: ApprovalQueue) -> None:
        with pytest.raises(KeyError):
            queue.approve("nonexistent-id")

    def test_updated_at_changes_on_transition(self, queue: ApprovalQueue) -> None:
        rid = queue.enqueue(action_context={}, policy_name="p", message="m")
        before = queue.get(rid).created_at
        queue.approve(rid)
        after = queue.get(rid).updated_at
        assert after >= before


# ---------------------------------------------------------------------------
# ApprovalQueue — read API
# ---------------------------------------------------------------------------


class TestApprovalQueueRead:
    def test_pending_returns_only_pending(self, queue: ApprovalQueue) -> None:
        rid1 = queue.enqueue(action_context={}, policy_name="p", message="m1")
        rid2 = queue.enqueue(action_context={}, policy_name="p", message="m2")
        queue.approve(rid1)
        pending = queue.pending()
        assert len(pending) == 1
        assert pending[0].request_id == rid2

    def test_all_requests_returns_all(self, queue: ApprovalQueue) -> None:
        queue.enqueue(action_context={}, policy_name="p", message="m1")
        queue.enqueue(action_context={}, policy_name="p", message="m2")
        all_reqs = queue.all_requests()
        assert len(all_reqs) == 2

    def test_count_pending(self, queue: ApprovalQueue) -> None:
        queue.enqueue(action_context={}, policy_name="p", message="m")
        queue.enqueue(action_context={}, policy_name="p", message="m")
        assert queue.count_pending() == 2

    def test_get_nonexistent_raises_key_error(self, queue: ApprovalQueue) -> None:
        with pytest.raises(KeyError):
            queue.get("no-such-id")


# ---------------------------------------------------------------------------
# ApprovalWorkflow — submit
# ---------------------------------------------------------------------------


@pytest.fixture()
def workflow() -> ApprovalWorkflow:
    return ApprovalWorkflow()


class TestApprovalWorkflowSubmit:
    def test_submit_returns_pending_request(self, workflow: ApprovalWorkflow) -> None:
        req = workflow.submit("agent-1", "file_delete", {"path": "/data/report.csv"})
        assert isinstance(req, WorkflowRequest)
        assert req.status == WorkflowStatus.PENDING
        assert req.agent_id == "agent-1"
        assert req.action_type == "file_delete"

    def test_submit_stores_request(self, workflow: ApprovalWorkflow) -> None:
        req = workflow.submit("agent-1", "file_delete", {})
        found = workflow.get(req.request_id)
        assert found is not None
        assert found.request_id == req.request_id

    def test_submit_with_timeout_sets_expires_at(self, workflow: ApprovalWorkflow) -> None:
        req = workflow.submit("agent-1", "action", {}, timeout_seconds=3600)
        assert req.expires_at is not None

    def test_submit_with_zero_timeout_no_expiry(self, workflow: ApprovalWorkflow) -> None:
        req = workflow.submit("agent-1", "action", {}, timeout_seconds=0)
        assert req.expires_at is None

    def test_submit_copies_action_data(self, workflow: ApprovalWorkflow) -> None:
        data = {"path": "/data", "size": 100}
        req = workflow.submit("agent-1", "action", data)
        data["path"] = "MUTATED"  # Mutate original
        assert req.action_data["path"] == "/data"  # Should not be affected


# ---------------------------------------------------------------------------
# ApprovalWorkflow — approve / reject
# ---------------------------------------------------------------------------


class TestApprovalWorkflowReview:
    def test_approve_transitions_to_approved(self, workflow: ApprovalWorkflow) -> None:
        req = workflow.submit("agent-1", "file_delete", {})
        approved = workflow.approve(req.request_id, reviewer="alice", reason="Confirmed safe")
        assert approved.status == WorkflowStatus.APPROVED
        assert approved.reviewed_by == "alice"
        assert approved.reviewed_at is not None

    def test_approve_with_reason(self, workflow: ApprovalWorkflow) -> None:
        req = workflow.submit("agent-1", "action", {})
        approved = workflow.approve(req.request_id, reviewer="alice", reason="Approved")
        assert approved.reason == "Approved"

    def test_approve_empty_reason_stored_as_none(self, workflow: ApprovalWorkflow) -> None:
        req = workflow.submit("agent-1", "action", {})
        approved = workflow.approve(req.request_id, reviewer="alice", reason="")
        assert approved.reason is None

    def test_reject_transitions_to_rejected(self, workflow: ApprovalWorkflow) -> None:
        req = workflow.submit("agent-1", "file_delete", {})
        rejected = workflow.reject(req.request_id, reviewer="bob", reason="Too risky")
        assert rejected.status == WorkflowStatus.REJECTED

    def test_approve_nonexistent_raises_key_error(self, workflow: ApprovalWorkflow) -> None:
        with pytest.raises(KeyError):
            workflow.approve("nonexistent", reviewer="alice")

    def test_reject_nonexistent_raises_key_error(self, workflow: ApprovalWorkflow) -> None:
        with pytest.raises(KeyError):
            workflow.reject("nonexistent", reviewer="alice")

    def test_approve_already_approved_raises_value_error(self, workflow: ApprovalWorkflow) -> None:
        req = workflow.submit("agent-1", "action", {})
        workflow.approve(req.request_id, reviewer="alice")
        with pytest.raises(ValueError):
            workflow.approve(req.request_id, reviewer="alice")

    def test_reject_already_rejected_raises_value_error(self, workflow: ApprovalWorkflow) -> None:
        req = workflow.submit("agent-1", "action", {})
        workflow.reject(req.request_id, reviewer="bob")
        with pytest.raises(ValueError):
            workflow.reject(req.request_id, reviewer="bob")


# ---------------------------------------------------------------------------
# ApprovalWorkflow — queries
# ---------------------------------------------------------------------------


class TestApprovalWorkflowQueries:
    def test_get_pending_returns_pending(self, workflow: ApprovalWorkflow) -> None:
        req1 = workflow.submit("a1", "act1", {})
        req2 = workflow.submit("a2", "act2", {})
        workflow.approve(req1.request_id, reviewer="admin")
        pending = workflow.get_pending()
        assert len(pending) == 1
        assert pending[0].request_id == req2.request_id

    def test_get_pending_sorted_by_requested_at(self, workflow: ApprovalWorkflow) -> None:
        workflow.submit("a1", "act1", {})
        workflow.submit("a2", "act2", {})
        workflow.submit("a3", "act3", {})
        pending = workflow.get_pending()
        times = [r.requested_at for r in pending]
        assert times == sorted(times)

    def test_get_returns_none_for_unknown(self, workflow: ApprovalWorkflow) -> None:
        assert workflow.get("unknown-id") is None

    def test_all_requests_returns_everything(self, workflow: ApprovalWorkflow) -> None:
        workflow.submit("a1", "act1", {})
        workflow.submit("a2", "act2", {})
        assert len(workflow.all_requests()) == 2


# ---------------------------------------------------------------------------
# ApprovalWorkflow — check_expired
# ---------------------------------------------------------------------------


class TestApprovalWorkflowExpiry:
    def test_check_expired_transitions_past_deadline(self, workflow: ApprovalWorkflow) -> None:
        req = workflow.submit("agent-1", "action", {}, timeout_seconds=1)
        # Manually set expires_at to the past
        req.expires_at = datetime.now(tz=timezone.utc) - timedelta(seconds=10)
        expired = workflow.check_expired()
        assert len(expired) == 1
        assert expired[0].status == WorkflowStatus.EXPIRED

    def test_check_expired_does_not_expire_future_deadline(self, workflow: ApprovalWorkflow) -> None:
        workflow.submit("agent-1", "action", {}, timeout_seconds=9999)
        expired = workflow.check_expired()
        assert len(expired) == 0

    def test_check_expired_ignores_non_pending(self, workflow: ApprovalWorkflow) -> None:
        req = workflow.submit("agent-1", "action", {}, timeout_seconds=1)
        workflow.approve(req.request_id, reviewer="admin")
        # Manually set expires_at to past even though already approved
        req.expires_at = datetime.now(tz=timezone.utc) - timedelta(seconds=10)
        expired = workflow.check_expired()
        assert len(expired) == 0

    def test_check_expired_ignores_no_expiry(self, workflow: ApprovalWorkflow) -> None:
        workflow.submit("agent-1", "action", {}, timeout_seconds=0)
        expired = workflow.check_expired()
        assert len(expired) == 0
