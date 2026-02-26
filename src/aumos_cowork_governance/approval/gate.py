"""Approval gate middleware.

ApprovalGate pauses execution on high-risk actions and waits for a human
approval decision.  In synchronous mode it polls the ApprovalQueue with
a configurable timeout.  On timeout the gate applies default-deny semantics.

Example
-------
>>> from aumos_cowork_governance.approval.queue import ApprovalQueue
>>> queue = ApprovalQueue()
>>> gate = ApprovalGate(queue, timeout_seconds=60)
>>> # Synchronous wait — blocks until approved, denied, or timed out.
>>> outcome = gate.request_and_wait(
...     action_context={"action": "file_delete", "path": "/data"},
...     policy_name="require-approval-delete",
...     message="Deletion requires human approval.",
... )
>>> outcome.approved
False  # Default deny on timeout.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum

from aumos_cowork_governance.approval.queue import ApprovalQueue, ApprovalRequest, ApprovalStatus

logger = logging.getLogger(__name__)


class ApprovalOutcome(str, Enum):
    """The final outcome of an approval gate request."""

    APPROVED = "approved"
    DENIED = "denied"
    TIMED_OUT = "timed_out"


@dataclass
class GateResult:
    """Result returned by the approval gate.

    Attributes
    ----------
    outcome:
        The final decision.
    approved:
        Convenience boolean — ``True`` only when ``outcome == APPROVED``.
    request_id:
        The approval queue request identifier.
    reviewer:
        Identifier of the human reviewer (if applicable).
    note:
        Optional reviewer note.
    """

    outcome: ApprovalOutcome
    approved: bool
    request_id: str
    reviewer: str | None
    note: str | None


class ApprovalGate:
    """Middleware that pauses execution pending human approval.

    Parameters
    ----------
    queue:
        The :class:`ApprovalQueue` where requests are enqueued.
    timeout_seconds:
        Maximum time to wait for a decision.  After this duration, the
        request is timed out and execution is denied (default: 300 s).
    poll_interval_seconds:
        How often to check the queue for a decision (default: 2 s).
    """

    def __init__(
        self,
        queue: ApprovalQueue,
        timeout_seconds: float = 300.0,
        poll_interval_seconds: float = 2.0,
    ) -> None:
        self._queue = queue
        self._timeout = timeout_seconds
        self._poll_interval = poll_interval_seconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def request_and_wait(
        self,
        action_context: dict[str, object],
        policy_name: str,
        message: str,
        notify: list[str] | None = None,
    ) -> GateResult:
        """Enqueue an approval request and block until decided or timed out.

        Parameters
        ----------
        action_context:
            The action context that requires approval.
        policy_name:
            Name of the triggering policy.
        message:
            Human-readable explanation.
        notify:
            Notification targets for the request.

        Returns
        -------
        GateResult
            The final gate outcome.
        """
        request_id = self._queue.enqueue(
            action_context=action_context,
            policy_name=policy_name,
            message=message,
            notify=notify,
        )
        logger.info(
            "Approval gate: enqueued request %s for policy '%s'.",
            request_id,
            policy_name,
        )

        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            request = self._queue.get(request_id)
            if request.status != ApprovalStatus.PENDING:
                return self._build_result(request)
            time.sleep(self._poll_interval)

        # Timeout — apply default-deny.
        try:
            self._queue.timeout(request_id)
        except ValueError:
            pass  # Already transitioned by a concurrent caller.

        request = self._queue.get(request_id)
        logger.warning(
            "Approval gate: request %s timed out after %.0f s.",
            request_id,
            self._timeout,
        )
        return self._build_result(request)

    def submit(
        self,
        action_context: dict[str, object],
        policy_name: str,
        message: str,
        notify: list[str] | None = None,
    ) -> str:
        """Enqueue an approval request without waiting.

        Returns
        -------
        str
            The ``request_id`` for the enqueued request.
        """
        return self._queue.enqueue(
            action_context=action_context,
            policy_name=policy_name,
            message=message,
            notify=notify,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_result(request: ApprovalRequest) -> GateResult:
        """Convert an ApprovalRequest to a GateResult."""
        match request.status:
            case ApprovalStatus.APPROVED:
                outcome = ApprovalOutcome.APPROVED
                approved = True
            case ApprovalStatus.TIMED_OUT:
                outcome = ApprovalOutcome.TIMED_OUT
                approved = False
            case _:
                outcome = ApprovalOutcome.DENIED
                approved = False

        return GateResult(
            outcome=outcome,
            approved=approved,
            request_id=request.request_id,
            reviewer=request.reviewer,
            note=request.review_note,
        )
