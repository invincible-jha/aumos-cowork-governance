"""Cost limiter for enforcing per-action, per-session, and per-day spend caps.

The CostLimiter consults a CostTracker to determine current spend levels
and evaluates whether a proposed operation is within the configured budget
thresholds before allowing it to proceed.

Example
-------
>>> from aumos_cowork_governance.cost.tracker import CostTracker
>>> tracker = CostTracker()
>>> limiter = CostLimiter(per_action_limit=0.50, per_session_limit=5.0, per_day_limit=50.0)
>>> result = limiter.check("agent-1", estimated_cost=0.10, tracker=tracker)
>>> result.allowed
True
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import date, datetime, timezone

from aumos_cowork_governance.cost.tracker import CostTracker

logger = logging.getLogger(__name__)


@dataclass
class CostLimitResult:
    """Result of a cost limit check for a proposed agent operation.

    Attributes
    ----------
    allowed:
        ``True`` when the proposed operation is within all cost limits.
    reason:
        Human-readable explanation, especially when ``allowed`` is ``False``.
    current_cost:
        The current accumulated cost for the relevant scope (session or day).
    limit:
        The limit that was evaluated (the most restrictive one that failed,
        or the binding one when all pass).
    """

    allowed: bool
    reason: str
    current_cost: float
    limit: float


@dataclass
class CostRecord:
    """A single cost record for an agent operation.

    This dataclass mirrors the fields used by :class:`~aumos_cowork_governance.cost.tracker.UsageRecord`
    but provides a simpler, operation-oriented interface for use alongside
    the limiter.

    Attributes
    ----------
    agent_id:
        Identifier of the agent that performed the operation.
    operation:
        Short description of the operation (e.g. ``"llm_call"``, ``"tool_use"``).
    cost_usd:
        Estimated or actual cost in USD.
    tokens_used:
        Total tokens consumed (input + output), or 0 for non-LLM operations.
    model:
        Model identifier used, or an empty string for non-LLM operations.
    timestamp:
        UTC datetime when the operation occurred.
    """

    agent_id: str
    operation: str
    cost_usd: float
    tokens_used: int
    model: str
    timestamp: datetime


class CostLimiter:
    """Enforces three-tier cost limits on agent operations.

    The limiter checks three thresholds in order of increasing scope:

    1. **Per-action** — the estimated cost of a single proposed operation
       must not exceed ``per_action_limit``.
    2. **Per-session** — the total accumulated cost across all records in
       the tracker (acting as a session budget) must not exceed
       ``per_session_limit`` after adding the proposed cost.
    3. **Per-day** — the total cost recorded today (UTC) must not exceed
       ``per_day_limit`` after adding the proposed cost.

    The most restrictive failing limit is reported in the result.

    Parameters
    ----------
    per_action_limit:
        Maximum cost in USD for a single operation (default: 1.00).
    per_session_limit:
        Maximum total cost in USD for the entire session (default: 10.00).
    per_day_limit:
        Maximum total cost in USD for the current UTC calendar day
        (default: 100.00).
    """

    def __init__(
        self,
        per_action_limit: float = 1.0,
        per_session_limit: float = 10.0,
        per_day_limit: float = 100.0,
    ) -> None:
        self._per_action_limit = per_action_limit
        self._per_session_limit = per_session_limit
        self._per_day_limit = per_day_limit

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        agent_id: str,
        estimated_cost: float,
        tracker: CostTracker,
    ) -> CostLimitResult:
        """Evaluate whether a proposed operation is within all cost limits.

        Checks are performed in ascending order of severity.  The first
        limit that would be exceeded determines the result.

        Parameters
        ----------
        agent_id:
            Identifier of the agent requesting the operation.
        estimated_cost:
            Estimated cost in USD of the proposed operation.
        tracker:
            The :class:`CostTracker` holding accumulated cost records.

        Returns
        -------
        CostLimitResult
            ``allowed=True`` when all limits are satisfied, ``False``
            with an explanatory ``reason`` otherwise.
        """
        # 1. Per-action limit — simplest check, no tracker query needed.
        if estimated_cost > self._per_action_limit:
            logger.warning(
                "Cost limit exceeded for agent %r: action cost $%.4f > per-action limit $%.4f",
                agent_id,
                estimated_cost,
                self._per_action_limit,
            )
            return CostLimitResult(
                allowed=False,
                reason=(
                    f"Estimated action cost ${estimated_cost:.4f} exceeds the "
                    f"per-action limit of ${self._per_action_limit:.4f}."
                ),
                current_cost=estimated_cost,
                limit=self._per_action_limit,
            )

        # 2. Per-session limit — total cost in the tracker + this action.
        session_total = tracker.total_cost_usd()
        projected_session = session_total + estimated_cost
        if projected_session > self._per_session_limit:
            logger.warning(
                "Session cost limit exceeded for agent %r: projected $%.4f > session limit $%.4f",
                agent_id,
                projected_session,
                self._per_session_limit,
            )
            return CostLimitResult(
                allowed=False,
                reason=(
                    f"Projected session cost ${projected_session:.4f} would exceed the "
                    f"per-session limit of ${self._per_session_limit:.4f} "
                    f"(current session spend: ${session_total:.4f})."
                ),
                current_cost=session_total,
                limit=self._per_session_limit,
            )

        # 3. Per-day limit — today's accumulated cost + this action.
        today = datetime.now(tz=timezone.utc).date()
        daily_total = tracker.total_cost_usd(target_date=today)
        projected_daily = daily_total + estimated_cost
        if projected_daily > self._per_day_limit:
            logger.warning(
                "Daily cost limit exceeded for agent %r: projected $%.4f > daily limit $%.4f",
                agent_id,
                projected_daily,
                self._per_day_limit,
            )
            return CostLimitResult(
                allowed=False,
                reason=(
                    f"Projected daily cost ${projected_daily:.4f} would exceed the "
                    f"per-day limit of ${self._per_day_limit:.4f} "
                    f"(today's spend so far: ${daily_total:.4f})."
                ),
                current_cost=daily_total,
                limit=self._per_day_limit,
            )

        logger.debug(
            "Cost check passed for agent %r: estimated $%.4f "
            "(session: $%.4f / $%.4f, day: $%.4f / $%.4f)",
            agent_id,
            estimated_cost,
            session_total,
            self._per_session_limit,
            daily_total,
            self._per_day_limit,
        )
        return CostLimitResult(
            allowed=True,
            reason="All cost limits are within bounds.",
            current_cost=session_total,
            limit=self._per_session_limit,
        )

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def per_action_limit(self) -> float:
        """The configured per-action cost limit in USD."""
        return self._per_action_limit

    @property
    def per_session_limit(self) -> float:
        """The configured per-session cost limit in USD."""
        return self._per_session_limit

    @property
    def per_day_limit(self) -> float:
        """The configured per-day cost limit in USD."""
        return self._per_day_limit
