"""Approval request notifier.

Sends approval request notifications via webhook (Slack/Teams compatible
format) with configurable message templates.

Example
-------
>>> from aumos_cowork_governance.approval.queue import ApprovalRequest
>>> notifier = ApprovalNotifier(webhook_url="https://hooks.slack.com/...")
>>> notifier.notify(request)
"""
from __future__ import annotations

import json
import logging
import urllib.request
from string import Template

from aumos_cowork_governance.approval.queue import ApprovalRequest

logger = logging.getLogger(__name__)

_DEFAULT_SLACK_TEMPLATE = Template(
    """{
  "text": "Approval Required",
  "blocks": [
    {
      "type": "header",
      "text": {"type": "plain_text", "text": "Approval Required"}
    },
    {
      "type": "section",
      "fields": [
        {"type": "mrkdwn", "text": "*Policy:*\\n$policy_name"},
        {"type": "mrkdwn", "text": "*Request ID:*\\n$request_id"}
      ]
    },
    {
      "type": "section",
      "text": {"type": "mrkdwn", "text": "*Message:*\\n$message"}
    },
    {
      "type": "context",
      "elements": [
        {"type": "mrkdwn", "text": "Created: $created_at"}
      ]
    }
  ]
}"""
)

_DEFAULT_TEAMS_TEMPLATE = Template(
    """{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "themeColor": "FF6600",
  "summary": "Approval Required",
  "sections": [{
    "activityTitle": "Approval Required",
    "activitySubtitle": "Policy: $policy_name",
    "facts": [
      {"name": "Request ID", "value": "$request_id"},
      {"name": "Message", "value": "$message"},
      {"name": "Created", "value": "$created_at"}
    ]
  }]
}"""
)

_DEFAULT_GENERIC_TEMPLATE = Template(
    '{"text": "Approval Required\\nPolicy: $policy_name\\nRequest ID: $request_id\\n$message"}'
)


class ApprovalNotifier:
    """Sends approval request notifications via webhook.

    Parameters
    ----------
    webhook_url:
        The URL to POST the notification to.  Supports Slack, Teams, and
        generic JSON webhook formats.
    webhook_format:
        ``"slack"``, ``"teams"``, or ``"generic"`` (default: ``"generic"``).
    timeout_seconds:
        HTTP request timeout in seconds (default: 5).
    """

    def __init__(
        self,
        webhook_url: str | None = None,
        webhook_format: str = "generic",
        timeout_seconds: float = 5.0,
    ) -> None:
        self._webhook_url = webhook_url
        self._format = webhook_format.lower()
        self._timeout = timeout_seconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def notify(self, request: ApprovalRequest) -> bool:
        """Send a notification for the given approval request.

        Parameters
        ----------
        request:
            The :class:`ApprovalRequest` to notify about.

        Returns
        -------
        bool
            ``True`` when the notification was delivered successfully.
        """
        payload = self._build_payload(request)
        if self._webhook_url:
            return self._post(payload)
        # Fall back to logging when no webhook is configured.
        logger.info("APPROVAL REQUIRED: %s", payload)
        return True

    def notify_by_id(
        self,
        request_id: str,
        policy_name: str,
        message: str,
        created_at: str,
    ) -> bool:
        """Send a notification without a full :class:`ApprovalRequest` object.

        Parameters
        ----------
        request_id:
            The approval request identifier.
        policy_name:
            Name of the triggering policy.
        message:
            Human-readable explanation.
        created_at:
            ISO-8601 timestamp string.

        Returns
        -------
        bool
            ``True`` when delivery succeeded.
        """
        payload = self._render_template(
            request_id=request_id,
            policy_name=policy_name,
            message=message,
            created_at=created_at,
        )
        if self._webhook_url:
            return self._post(payload)
        logger.info("APPROVAL REQUIRED: %s", payload)
        return True

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_payload(self, request: ApprovalRequest) -> str:
        return self._render_template(
            request_id=request.request_id,
            policy_name=request.policy_name,
            message=request.message,
            created_at=request.created_at.isoformat(),
        )

    def _render_template(
        self,
        request_id: str,
        policy_name: str,
        message: str,
        created_at: str,
    ) -> str:
        """Render the appropriate payload template."""
        safe_message = message.replace('"', '\\"').replace("\n", "\\n")
        substitutions = {
            "request_id": request_id,
            "policy_name": policy_name,
            "message": safe_message,
            "created_at": created_at,
        }
        match self._format:
            case "slack":
                return _DEFAULT_SLACK_TEMPLATE.safe_substitute(substitutions)
            case "teams":
                return _DEFAULT_TEAMS_TEMPLATE.safe_substitute(substitutions)
            case _:
                return _DEFAULT_GENERIC_TEMPLATE.safe_substitute(substitutions)

    def _post(self, payload: str) -> bool:
        """POST the payload to the configured webhook URL."""
        if not self._webhook_url:
            return False
        try:
            req = urllib.request.Request(
                self._webhook_url,
                data=payload.encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout):  # noqa: S310
                pass
            return True
        except Exception:
            logger.exception("Failed to deliver approval notification.")
            return False
