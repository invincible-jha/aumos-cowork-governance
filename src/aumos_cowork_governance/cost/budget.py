"""Budget manager for API cost enforcement.

BudgetManager compares current spend (from CostTracker) against configured
daily, weekly, and monthly limits and returns a BudgetStatus describing
whether spending is within budget, approaching limits, or exceeded.

Example
-------
>>> from aumos_cowork_governance.cost.tracker import CostTracker
>>> tracker = CostTracker()
>>> manager = BudgetManager(tracker, daily_usd=10.0, monthly_usd=200.0)
>>> status = manager.check()
>>> status.within_budget
True
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from enum import Enum

from aumos_cowork_governance.cost.tracker import CostTracker


class BudgetPeriod(str, Enum):
    """Budget enforcement period."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


@dataclass
class PeriodStatus:
    """Budget status for a single period."""

    period: BudgetPeriod
    limit_usd: float
    spent_usd: float
    percent_used: float
    exceeded: bool
    approaching: bool  # True when >= 80% consumed.


@dataclass
class BudgetStatus:
    """Aggregate budget status across all configured periods.

    Attributes
    ----------
    within_budget:
        ``True`` when no period limit is exceeded.
    daily:
        Status for the daily budget (``None`` if not configured).
    weekly:
        Status for the weekly budget (``None`` if not configured).
    monthly:
        Status for the monthly budget (``None`` if not configured).
    exceeded_periods:
        List of period names where the limit is exceeded.
    """

    within_budget: bool
    daily: PeriodStatus | None
    weekly: PeriodStatus | None
    monthly: PeriodStatus | None
    exceeded_periods: list[str]


class BudgetManager:
    """Enforces daily, weekly, and monthly API cost budgets.

    Parameters
    ----------
    tracker:
        The :class:`CostTracker` providing actual spend data.
    daily_usd:
        Daily spend limit in USD.  ``None`` to disable.
    weekly_usd:
        Weekly spend limit in USD.  ``None`` to disable.
    monthly_usd:
        Monthly spend limit in USD.  ``None`` to disable.
    approaching_threshold_pct:
        Percentage of budget consumed that triggers the ``approaching``
        flag (default: 80).
    """

    def __init__(
        self,
        tracker: CostTracker,
        daily_usd: float | None = None,
        weekly_usd: float | None = None,
        monthly_usd: float | None = None,
        approaching_threshold_pct: float = 80.0,
    ) -> None:
        self._tracker = tracker
        self._daily_usd = daily_usd
        self._weekly_usd = weekly_usd
        self._monthly_usd = monthly_usd
        self._threshold = approaching_threshold_pct

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, reference_date: date | None = None) -> BudgetStatus:
        """Evaluate budget status for all configured periods.

        Parameters
        ----------
        reference_date:
            Override today's date (for testing).

        Returns
        -------
        BudgetStatus
            Current budget status across all periods.
        """
        today = reference_date or date.today()

        daily_status = self._check_period(BudgetPeriod.DAILY, today, self._daily_usd)
        weekly_status = self._check_period(BudgetPeriod.WEEKLY, today, self._weekly_usd)
        monthly_status = self._check_period(BudgetPeriod.MONTHLY, today, self._monthly_usd)

        exceeded: list[str] = []
        for status in [daily_status, weekly_status, monthly_status]:
            if status is not None and status.exceeded:
                exceeded.append(status.period.value)

        within_budget = len(exceeded) == 0

        return BudgetStatus(
            within_budget=within_budget,
            daily=daily_status,
            weekly=weekly_status,
            monthly=monthly_status,
            exceeded_periods=exceeded,
        )

    def is_within_budget(self, reference_date: date | None = None) -> bool:
        """Quick check returning ``True`` when all budgets are within limits."""
        return self.check(reference_date).within_budget

    def daily_remaining_usd(self, reference_date: date | None = None) -> float | None:
        """Return remaining daily budget in USD, or ``None`` if not configured."""
        today = reference_date or date.today()
        if self._daily_usd is None:
            return None
        spent = self._tracker.total_cost_usd(target_date=today)
        return max(0.0, self._daily_usd - spent)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_period(
        self,
        period: BudgetPeriod,
        today: date,
        limit_usd: float | None,
    ) -> PeriodStatus | None:
        """Compute budget status for a single period."""
        if limit_usd is None:
            return None

        spent = self._spent_in_period(period, today)
        percent = (spent / limit_usd * 100.0) if limit_usd > 0 else 0.0
        exceeded = spent >= limit_usd
        approaching = (not exceeded) and percent >= self._threshold

        return PeriodStatus(
            period=period,
            limit_usd=limit_usd,
            spent_usd=spent,
            percent_used=percent,
            exceeded=exceeded,
            approaching=approaching,
        )

    def _spent_in_period(self, period: BudgetPeriod, today: date) -> float:
        """Sum costs within the specified period ending today."""
        match period:
            case BudgetPeriod.DAILY:
                dates = [today]
            case BudgetPeriod.WEEKLY:
                start = today - timedelta(days=today.weekday())
                dates = [start + timedelta(days=i) for i in range(7) if start + timedelta(days=i) <= today]
            case BudgetPeriod.MONTHLY:
                dates = [
                    date(today.year, today.month, day)
                    for day in range(1, today.day + 1)
                ]

        return sum(self._tracker.total_cost_usd(target_date=d) for d in dates)
