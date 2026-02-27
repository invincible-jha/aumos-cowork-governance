"""Budget alert manager.

Sends alerts when spend crosses configured percentage thresholds.
Supports three delivery channels: console, webhook (HTTP POST), and
a registered callback function.

Example
-------
>>> from aumos_cowork_governance.cost.tracker import CostTracker
>>> from aumos_cowork_governance.cost.budget import BudgetManager
>>> tracker = CostTracker()
>>> budget = BudgetManager(tracker, daily_usd=10.0)
>>> alerts = AlertManager(budget, thresholds=[50, 80, 100])
>>> alerts.check_and_notify()
"""
from __future__ import annotations

import json
import logging
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime, timezone
from enum import Enum
from typing import Callable

from aumos_cowork_governance.cost.budget import BudgetManager, BudgetPeriod, BudgetStatus, PeriodStatus

logger = logging.getLogger(__name__)


class AlertChannel(str, Enum):
    """Supported alert delivery channels."""

    CONSOLE = "console"
    WEBHOOK = "webhook"
    CALLBACK = "callback"


@dataclass
class AlertThreshold:
    """Configuration for a single alert threshold.

    Attributes
    ----------
    percent:
        Spend percentage at which to trigger the alert.
    periods:
        Which budget periods to monitor (default: all configured).
    """

    percent: float
    periods: list[BudgetPeriod] | None = None


class AlertManager:
    """Monitors budget status and sends threshold alerts.

    Parameters
    ----------
    budget_manager:
        The :class:`BudgetManager` instance to check against.
    thresholds:
        List of percentage thresholds to alert at.  Each threshold
        triggers at most once per day per period.
    webhook_url:
        Optional URL to POST alert payloads to.
    callback:
        Optional callable receiving ``(period, percent_used, message)``
        when an alert fires.
    """

    def __init__(
        self,
        budget_manager: BudgetManager,
        thresholds: list[float] | None = None,
        webhook_url: str | None = None,
        callback: Callable[[str, float, str], None] | None = None,
    ) -> None:
        self._budget = budget_manager
        self._thresholds = sorted(thresholds or [50.0, 80.0, 100.0])
        self._webhook_url = webhook_url
        self._callback = callback
        # Track which (date, period, threshold) alerts have already fired.
        self._fired: set[tuple[date, str, float]] = set()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_and_notify(self, reference_date: date | None = None) -> list[str]:
        """Check budget status and send any new threshold alerts.

        Parameters
        ----------
        reference_date:
            Override today's date.

        Returns
        -------
        list[str]
            List of alert messages sent in this call.
        """
        today = reference_date or datetime.now(tz=timezone.utc).date()
        status = self._budget.check(reference_date=today)
        fired_messages: list[str] = []

        period_statuses: list[tuple[str, PeriodStatus]] = []
        for period_name, period_status in [
            ("daily", status.daily),
            ("weekly", status.weekly),
            ("monthly", status.monthly),
        ]:
            if period_status is not None:
                period_statuses.append((period_name, period_status))

        for period_name, period_status in period_statuses:
            for threshold in self._thresholds:
                key = (today, period_name, threshold)
                if key in self._fired:
                    continue
                if period_status.percent_used >= threshold:
                    message = self._build_message(period_name, period_status, threshold)
                    self._send(period_name, period_status.percent_used, message)
                    self._fired.add(key)
                    fired_messages.append(message)

        return fired_messages

    def reset_fired(self) -> None:
        """Clear the set of already-fired alerts (useful for testing)."""
        self._fired.clear()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_message(
        self,
        period: str,
        status: PeriodStatus,
        threshold: float,
    ) -> str:
        """Compose a human-readable alert message."""
        status_word = "EXCEEDED" if status.exceeded else "approaching"
        return (
            f"[BUDGET ALERT] {period.upper()} budget {status_word} "
            f"{threshold:.0f}% threshold: "
            f"${status.spent_usd:.4f} of ${status.limit_usd:.2f} used "
            f"({status.percent_used:.1f}%)"
        )

    def _send(self, period: str, percent_used: float, message: str) -> None:
        """Dispatch the alert via all configured channels."""
        # Always log to the Python logger.
        logger.warning(message)

        # Webhook delivery.
        if self._webhook_url:
            self._post_webhook(period, percent_used, message)

        # Callback delivery.
        if self._callback is not None:
            try:
                self._callback(period, percent_used, message)
            except Exception:
                logger.exception("Budget alert callback raised an exception.")

    def _post_webhook(self, period: str, percent_used: float, message: str) -> None:
        """POST alert payload to the configured webhook URL."""
        if not self._webhook_url:
            return
        payload = json.dumps(
            {
                "text": message,
                "period": period,
                "percent_used": percent_used,
            }
        ).encode("utf-8")
        try:
            req = urllib.request.Request(
                self._webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5):  # noqa: S310
                pass
        except Exception:
            logger.exception("Failed to deliver budget alert to webhook.")
