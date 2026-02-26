"""Approval request timeout handler.

TimeoutHandler scans the ApprovalQueue for pending requests that have
exceeded their timeout duration and marks them as timed out (default-deny).

Typical usage is to run this on a background thread or schedule it
periodically alongside the ApprovalQueue.

Example
-------
>>> from aumos_cowork_governance.approval.queue import ApprovalQueue
>>> queue = ApprovalQueue()
>>> handler = TimeoutHandler(queue, default_timeout_seconds=300)
>>> # Called periodically to expire stale requests:
>>> expired = handler.expire_stale()
>>> len(expired)
0
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from aumos_cowork_governance.approval.queue import ApprovalQueue, ApprovalStatus

logger = logging.getLogger(__name__)


class TimeoutHandler:
    """Applies default-deny timeouts to stale approval requests.

    Parameters
    ----------
    queue:
        The :class:`ApprovalQueue` to monitor.
    default_timeout_seconds:
        How long a request may remain PENDING before timing out.
    """

    def __init__(
        self,
        queue: ApprovalQueue,
        default_timeout_seconds: float = 300.0,
    ) -> None:
        self._queue = queue
        self._timeout_delta = timedelta(seconds=default_timeout_seconds)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def expire_stale(self, now: datetime | None = None) -> list[str]:
        """Expire all pending requests that have exceeded the timeout.

        Parameters
        ----------
        now:
            Override the current UTC time (for testing).

        Returns
        -------
        list[str]
            List of request IDs that were timed out in this call.
        """
        effective_now = now or datetime.now(tz=timezone.utc)
        expired_ids: list[str] = []

        for request in self._queue.pending():
            age = effective_now - request.created_at
            if age >= self._timeout_delta:
                try:
                    self._queue.timeout(request.request_id)
                    expired_ids.append(request.request_id)
                    logger.warning(
                        "Approval request %s expired after %.0f seconds (policy: %s).",
                        request.request_id,
                        age.total_seconds(),
                        request.policy_name,
                    )
                except (KeyError, ValueError):
                    # Already transitioned by a concurrent caller.
                    pass

        return expired_ids

    def is_expired(self, request_id: str, now: datetime | None = None) -> bool:
        """Check whether a specific request has exceeded the timeout.

        Parameters
        ----------
        request_id:
            The request to check.
        now:
            Override the current UTC time.

        Returns
        -------
        bool
            ``True`` when the request is PENDING and past the timeout.
        """
        effective_now = now or datetime.now(tz=timezone.utc)
        try:
            request = self._queue.get(request_id)
        except KeyError:
            return False

        if request.status != ApprovalStatus.PENDING:
            return False

        age = effective_now - request.created_at
        return age >= self._timeout_delta

    @property
    def timeout_seconds(self) -> float:
        """The configured timeout duration in seconds."""
        return self._timeout_delta.total_seconds()
