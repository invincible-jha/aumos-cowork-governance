"""In-memory approval request queue.

ApprovalQueue stores pending approval requests with status tracking.
Each request transitions through: PENDING -> APPROVED | DENIED | TIMED_OUT.

The queue is thread-safe for concurrent reads and writes.

Example
-------
>>> queue = ApprovalQueue()
>>> request_id = queue.enqueue(
...     action_context={"action": "file_delete", "path": "/data/archive"},
...     policy_name="require-approval-delete",
...     message="File deletion requires human approval.",
... )
>>> queue.approve(request_id)
>>> queue.get(request_id).status
<ApprovalStatus.APPROVED: 'approved'>
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class ApprovalStatus(str, Enum):
    """Lifecycle status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


@dataclass
class ApprovalRequest:
    """A single approval request record.

    Attributes
    ----------
    request_id:
        Unique identifier for this request.
    action_context:
        The action context that triggered the approval requirement.
    policy_name:
        Name of the policy that raised the approval requirement.
    message:
        Human-readable explanation of why approval is needed.
    notify:
        List of notification targets (email addresses, Slack channels).
    created_at:
        UTC datetime when the request was created.
    updated_at:
        UTC datetime of the most recent status change.
    status:
        Current lifecycle status.
    reviewer:
        Identifier of the human who approved or denied the request.
    review_note:
        Optional note from the reviewer.
    """

    request_id: str
    action_context: dict[str, object]
    policy_name: str
    message: str
    notify: list[str]
    created_at: datetime
    updated_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    reviewer: str | None = None
    review_note: str | None = None


class ApprovalQueue:
    """Thread-safe in-memory queue of pending approval requests.

    Parameters
    ----------
    max_pending:
        Maximum number of simultaneous pending requests.  Raises
        ``OverflowError`` when exceeded.
    """

    def __init__(self, max_pending: int = 100) -> None:
        self._requests: dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()
        self._max_pending = max_pending

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def enqueue(
        self,
        action_context: dict[str, object],
        policy_name: str,
        message: str,
        notify: list[str] | None = None,
        request_id: str | None = None,
    ) -> str:
        """Add a new approval request to the queue.

        Parameters
        ----------
        action_context:
            The action context that triggered the approval requirement.
        policy_name:
            Name of the triggering policy.
        message:
            Human-readable description of the request.
        notify:
            Optional list of notification targets.
        request_id:
            Override the auto-generated UUID.

        Returns
        -------
        str
            The unique ``request_id`` for the new request.

        Raises
        ------
        OverflowError
            When the queue already holds ``max_pending`` pending requests.
        """
        with self._lock:
            pending_count = sum(
                1 for r in self._requests.values() if r.status == ApprovalStatus.PENDING
            )
            if pending_count >= self._max_pending:
                raise OverflowError(
                    f"Approval queue is full ({self._max_pending} pending requests)."
                )

            rid = request_id or str(uuid.uuid4())
            now = datetime.now(tz=timezone.utc)
            request = ApprovalRequest(
                request_id=rid,
                action_context=action_context,
                policy_name=policy_name,
                message=message,
                notify=notify or [],
                created_at=now,
                updated_at=now,
            )
            self._requests[rid] = request
            return rid

    def approve(
        self,
        request_id: str,
        reviewer: str | None = None,
        note: str | None = None,
    ) -> None:
        """Mark a pending request as approved.

        Parameters
        ----------
        request_id:
            The request to approve.
        reviewer:
            Identifier of the approving human.
        note:
            Optional review note.

        Raises
        ------
        KeyError:
            When no request with that ID exists.
        ValueError:
            When the request is not in PENDING state.
        """
        self._transition(request_id, ApprovalStatus.APPROVED, reviewer, note)

    def deny(
        self,
        request_id: str,
        reviewer: str | None = None,
        note: str | None = None,
    ) -> None:
        """Mark a pending request as denied.

        Parameters
        ----------
        request_id:
            The request to deny.
        reviewer:
            Identifier of the denying human.
        note:
            Optional review note.
        """
        self._transition(request_id, ApprovalStatus.DENIED, reviewer, note)

    def timeout(self, request_id: str) -> None:
        """Mark a pending request as timed out (default-deny)."""
        self._transition(request_id, ApprovalStatus.TIMED_OUT, None, "Timed out awaiting review.")

    def cancel(self, request_id: str) -> None:
        """Cancel a pending request."""
        self._transition(request_id, ApprovalStatus.CANCELLED, None, None)

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def get(self, request_id: str) -> ApprovalRequest:
        """Retrieve a request by ID.

        Raises
        ------
        KeyError:
            When the request does not exist.
        """
        with self._lock:
            if request_id not in self._requests:
                raise KeyError(f"No approval request with ID: {request_id}")
            return self._requests[request_id]

    def pending(self) -> list[ApprovalRequest]:
        """Return all requests currently in PENDING state."""
        with self._lock:
            return [r for r in self._requests.values() if r.status == ApprovalStatus.PENDING]

    def all_requests(self) -> list[ApprovalRequest]:
        """Return all requests regardless of status."""
        with self._lock:
            return list(self._requests.values())

    def count_pending(self) -> int:
        """Return the number of currently pending requests."""
        return len(self.pending())

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _transition(
        self,
        request_id: str,
        new_status: ApprovalStatus,
        reviewer: str | None,
        note: str | None,
    ) -> None:
        """Transition a request to a new status."""
        with self._lock:
            if request_id not in self._requests:
                raise KeyError(f"No approval request with ID: {request_id}")
            request = self._requests[request_id]
            if request.status != ApprovalStatus.PENDING:
                raise ValueError(
                    f"Request {request_id} is in '{request.status}' state, "
                    f"not PENDING — cannot transition to '{new_status}'."
                )
            request.status = new_status
            request.updated_at = datetime.now(tz=timezone.utc)
            if reviewer is not None:
                request.reviewer = reviewer
            if note is not None:
                request.review_note = note
