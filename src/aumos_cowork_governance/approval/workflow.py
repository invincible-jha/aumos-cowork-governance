"""Human-in-the-loop approval workflow for high-risk agent actions.

ApprovalWorkflow manages the lifecycle of approval requests: submission,
review (approve or reject), expiry checking, and status tracking.
All state is held in memory; callers that need persistence should wrap
this class with an AuditLogger.

Example
-------
>>> workflow = ApprovalWorkflow()
>>> req = workflow.submit("agent-1", "file_delete", {"path": "/data/report.csv"})
>>> req.status
<ApprovalStatus.PENDING: 'pending'>
>>> approved = workflow.approve(req.request_id, reviewer="alice", reason="Confirmed safe")
>>> approved.status
<ApprovalStatus.APPROVED: 'approved'>
"""
from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum

logger = logging.getLogger(__name__)


class ApprovalStatus(str, Enum):
    """Lifecycle states for an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    AUTO_APPROVED = "auto_approved"


@dataclass
class ApprovalRequest:
    """A single human-in-the-loop approval request.

    Attributes
    ----------
    request_id:
        Globally unique identifier generated at submission time.
    agent_id:
        Identifier of the agent that submitted the request.
    action_type:
        Short label for the action category (e.g. ``"file_delete"``).
    action_data:
        Arbitrary structured data describing the proposed action.
    requested_at:
        UTC datetime when the request was submitted.
    status:
        Current lifecycle status of the request.
    reviewed_by:
        Username or identifier of the human reviewer (set on review).
    reviewed_at:
        UTC datetime of the review decision (set on review).
    reason:
        Reviewer-supplied rationale for the approval or rejection.
    expires_at:
        UTC datetime after which the request transitions to EXPIRED.
        ``None`` means the request never expires automatically.
    """

    request_id: str
    agent_id: str
    action_type: str
    action_data: dict[str, object]
    requested_at: datetime
    status: ApprovalStatus
    reviewed_by: str | None = None
    reviewed_at: datetime | None = None
    reason: str | None = None
    expires_at: datetime | None = None


class ApprovalWorkflow:
    """Manages human-in-the-loop approval requests in memory.

    Thread safety: all public methods are guarded by an internal lock so the
    workflow is safe to call from multiple threads within a single process.
    """

    def __init__(self) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    def submit(
        self,
        agent_id: str,
        action_type: str,
        action_data: dict[str, object],
        timeout_seconds: float = 3600.0,
    ) -> ApprovalRequest:
        """Submit a new action for human approval.

        Parameters
        ----------
        agent_id:
            Identifier of the agent requesting approval.
        action_type:
            Short label for the action category.
        action_data:
            Arbitrary data describing the proposed action.
        timeout_seconds:
            Seconds before the request automatically transitions to
            EXPIRED status.  Pass ``0`` or a negative value to disable
            expiry.

        Returns
        -------
        ApprovalRequest
            The newly created request in PENDING status.
        """
        now = datetime.now(tz=timezone.utc)
        expires_at: datetime | None = None
        if timeout_seconds > 0:
            expires_at = now + timedelta(seconds=timeout_seconds)

        request = ApprovalRequest(
            request_id=str(uuid.uuid4()),
            agent_id=agent_id,
            action_type=action_type,
            action_data=dict(action_data),
            requested_at=now,
            status=ApprovalStatus.PENDING,
            expires_at=expires_at,
        )

        with self._lock:
            self._requests[request.request_id] = request

        logger.info(
            "Approval request submitted: id=%s agent=%s action=%s expires_at=%s",
            request.request_id,
            agent_id,
            action_type,
            expires_at,
        )
        return request

    # ------------------------------------------------------------------
    # Review actions
    # ------------------------------------------------------------------

    def approve(
        self,
        request_id: str,
        reviewer: str,
        reason: str = "",
    ) -> ApprovalRequest:
        """Approve a pending request.

        Parameters
        ----------
        request_id:
            The unique identifier of the request to approve.
        reviewer:
            Identifier of the human reviewer.
        reason:
            Optional rationale for the approval decision.

        Returns
        -------
        ApprovalRequest
            The updated request in APPROVED status.

        Raises
        ------
        KeyError
            If no request with ``request_id`` exists.
        ValueError
            If the request is not in PENDING status.
        """
        with self._lock:
            request = self._get_or_raise(request_id)
            self._assert_pending(request)

            now = datetime.now(tz=timezone.utc)
            request.status = ApprovalStatus.APPROVED
            request.reviewed_by = reviewer
            request.reviewed_at = now
            request.reason = reason or None

        logger.info(
            "Approval request approved: id=%s reviewer=%s",
            request_id,
            reviewer,
        )
        return request

    def reject(
        self,
        request_id: str,
        reviewer: str,
        reason: str = "",
    ) -> ApprovalRequest:
        """Reject a pending request.

        Parameters
        ----------
        request_id:
            The unique identifier of the request to reject.
        reviewer:
            Identifier of the human reviewer.
        reason:
            Optional rationale for the rejection decision.

        Returns
        -------
        ApprovalRequest
            The updated request in REJECTED status.

        Raises
        ------
        KeyError
            If no request with ``request_id`` exists.
        ValueError
            If the request is not in PENDING status.
        """
        with self._lock:
            request = self._get_or_raise(request_id)
            self._assert_pending(request)

            now = datetime.now(tz=timezone.utc)
            request.status = ApprovalStatus.REJECTED
            request.reviewed_by = reviewer
            request.reviewed_at = now
            request.reason = reason or None

        logger.info(
            "Approval request rejected: id=%s reviewer=%s",
            request_id,
            reviewer,
        )
        return request

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_pending(self) -> list[ApprovalRequest]:
        """Return all requests currently in PENDING status.

        Note: expired requests are not automatically transitioned here;
        call :meth:`check_expired` first if you want them excluded.

        Returns
        -------
        list[ApprovalRequest]
            All pending requests, ordered by ``requested_at`` ascending.
        """
        with self._lock:
            pending = [
                r for r in self._requests.values()
                if r.status == ApprovalStatus.PENDING
            ]
        return sorted(pending, key=lambda r: r.requested_at)

    def get(self, request_id: str) -> ApprovalRequest | None:
        """Return the request with the given identifier, or ``None``.

        Parameters
        ----------
        request_id:
            The unique identifier of the request.

        Returns
        -------
        ApprovalRequest | None
            The request, or ``None`` if it does not exist.
        """
        with self._lock:
            return self._requests.get(request_id)

    def all_requests(self) -> list[ApprovalRequest]:
        """Return all requests in insertion order.

        Returns
        -------
        list[ApprovalRequest]
            Every request regardless of status.
        """
        with self._lock:
            return list(self._requests.values())

    def check_expired(self) -> list[ApprovalRequest]:
        """Transition timed-out PENDING requests to EXPIRED status.

        Returns
        -------
        list[ApprovalRequest]
            The requests that were transitioned to EXPIRED in this call.
        """
        now = datetime.now(tz=timezone.utc)
        expired: list[ApprovalRequest] = []

        with self._lock:
            for request in self._requests.values():
                if (
                    request.status == ApprovalStatus.PENDING
                    and request.expires_at is not None
                    and now >= request.expires_at
                ):
                    request.status = ApprovalStatus.EXPIRED
                    expired.append(request)

        for request in expired:
            logger.info(
                "Approval request expired: id=%s agent=%s action=%s",
                request.request_id,
                request.agent_id,
                request.action_type,
            )

        return expired

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_or_raise(self, request_id: str) -> ApprovalRequest:
        """Return the request or raise KeyError."""
        try:
            return self._requests[request_id]
        except KeyError:
            raise KeyError(
                f"No approval request found with id={request_id!r}."
            ) from None

    @staticmethod
    def _assert_pending(request: ApprovalRequest) -> None:
        """Raise ValueError when the request is not in PENDING status."""
        if request.status != ApprovalStatus.PENDING:
            raise ValueError(
                f"Approval request {request.request_id!r} cannot be reviewed: "
                f"current status is {request.status.value!r} (expected 'pending')."
            )
