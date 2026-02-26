"""Policy action handler.

Executes the side-effects associated with a matched policy:
- BLOCK  → raises PolicyBlockedError
- WARN   → logs a warning (and optionally writes to audit)
- LOG    → writes to audit trail
- APPROVE → queues the action for human review
- ALLOW  → no-op

Example
-------
>>> from aumos_cowork_governance.policies.engine import PolicyAction, PolicyResult
>>> handler = PolicyActionHandler()
>>> result = PolicyResult("my-policy", True, PolicyAction.WARN, "Suspicious path")
>>> handler.execute(result, {"action": "file_read", "path": "/tmp/x"})
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from aumos_cowork_governance.policies.engine import PolicyAction, PolicyResult

if TYPE_CHECKING:
    from aumos_cowork_governance.audit.logger import AuditLogger
    from aumos_cowork_governance.approval.queue import ApprovalQueue

logger = logging.getLogger(__name__)


class PolicyBlockedError(Exception):
    """Raised when a BLOCK policy matches an action context.

    Attributes
    ----------
    policy_name:
        Name of the policy that triggered the block.
    message:
        Human-readable explanation from the policy definition.
    """

    def __init__(self, policy_name: str, message: str) -> None:
        self.policy_name = policy_name
        self.message = message
        super().__init__(f"Policy '{policy_name}' blocked action: {message}")


class PolicyActionHandler:
    """Executes side-effects for matched policy results.

    Parameters
    ----------
    audit_logger:
        Optional audit logger.  When provided, LOG and WARN actions
        write structured entries to the audit trail.
    approval_queue:
        Optional approval queue.  When provided, APPROVE actions enqueue
        the action context for human review.
    """

    def __init__(
        self,
        audit_logger: "AuditLogger | None" = None,
        approval_queue: "ApprovalQueue | None" = None,
    ) -> None:
        self._audit_logger = audit_logger
        self._approval_queue = approval_queue

    def execute(
        self,
        result: PolicyResult,
        action_context: dict[str, object],
    ) -> None:
        """Execute the side-effect for a matched policy result.

        Parameters
        ----------
        result:
            A :class:`PolicyResult` with ``matched=True``.
        action_context:
            The action context the policy was evaluated against.

        Raises
        ------
        PolicyBlockedError
            When ``result.action == PolicyAction.BLOCK``.
        """
        if not result.matched:
            return

        match result.action:
            case PolicyAction.BLOCK:
                self._handle_block(result, action_context)
            case PolicyAction.WARN:
                self._handle_warn(result, action_context)
            case PolicyAction.LOG:
                self._handle_log(result, action_context)
            case PolicyAction.APPROVE:
                self._handle_approve(result, action_context)
            case PolicyAction.ALLOW:
                pass  # Explicit allow — no side-effect needed.

    def execute_all(
        self,
        results: list[PolicyResult],
        action_context: dict[str, object],
    ) -> None:
        """Execute side-effects for all matched results in order.

        Stops at the first BLOCK.

        Parameters
        ----------
        results:
            List of :class:`PolicyResult` objects (matched and unmatched).
        action_context:
            The action context used during evaluation.
        """
        for result in results:
            if result.matched:
                self.execute(result, action_context)

    # ------------------------------------------------------------------
    # Private handlers
    # ------------------------------------------------------------------

    def _handle_block(
        self,
        result: PolicyResult,
        action_context: dict[str, object],
    ) -> None:
        logger.warning(
            "POLICY BLOCK — policy='%s' message='%s' context=%s",
            result.policy_name,
            result.message,
            action_context,
        )
        if self._audit_logger is not None:
            self._audit_logger.log(
                {
                    "event": "policy_block",
                    "policy": result.policy_name,
                    "message": result.message,
                    "action_context": action_context,
                    "notify": result.notify,
                }
            )
        raise PolicyBlockedError(result.policy_name, result.message)

    def _handle_warn(
        self,
        result: PolicyResult,
        action_context: dict[str, object],
    ) -> None:
        logger.warning(
            "POLICY WARN — policy='%s' message='%s'",
            result.policy_name,
            result.message,
        )
        if self._audit_logger is not None:
            self._audit_logger.log(
                {
                    "event": "policy_warn",
                    "policy": result.policy_name,
                    "message": result.message,
                    "action_context": action_context,
                    "notify": result.notify,
                }
            )

    def _handle_log(
        self,
        result: PolicyResult,
        action_context: dict[str, object],
    ) -> None:
        logger.info(
            "POLICY LOG — policy='%s' message='%s'",
            result.policy_name,
            result.message,
        )
        if self._audit_logger is not None:
            self._audit_logger.log(
                {
                    "event": "policy_log",
                    "policy": result.policy_name,
                    "message": result.message,
                    "action_context": action_context,
                }
            )

    def _handle_approve(
        self,
        result: PolicyResult,
        action_context: dict[str, object],
    ) -> None:
        logger.info(
            "POLICY APPROVE — policy='%s' message='%s'",
            result.policy_name,
            result.message,
        )
        if self._approval_queue is not None:
            self._approval_queue.enqueue(
                action_context=action_context,
                policy_name=result.policy_name,
                message=result.message,
                notify=result.notify,
            )
        if self._audit_logger is not None:
            self._audit_logger.log(
                {
                    "event": "policy_approve_queued",
                    "policy": result.policy_name,
                    "message": result.message,
                    "action_context": action_context,
                    "notify": result.notify,
                }
            )
