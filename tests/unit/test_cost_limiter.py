"""Tests for CostLimiter."""
from __future__ import annotations

import pytest

from aumos_cowork_governance.cost.limiter import CostLimiter, CostLimitResult, CostRecord
from aumos_cowork_governance.cost.tracker import CostTracker


@pytest.fixture()
def tracker() -> CostTracker:
    return CostTracker()


@pytest.fixture()
def limiter() -> CostLimiter:
    return CostLimiter(per_action_limit=1.0, per_session_limit=5.0, per_day_limit=20.0)


# ---------------------------------------------------------------------------
# CostLimitResult and CostRecord
# ---------------------------------------------------------------------------


class TestDataclasses:
    def test_cost_limit_result_allowed(self) -> None:
        result = CostLimitResult(allowed=True, reason="ok", current_cost=0.5, limit=1.0)
        assert result.allowed is True

    def test_cost_record_fields(self) -> None:
        from datetime import datetime, timezone
        record = CostRecord(
            agent_id="agent-1",
            operation="llm_call",
            cost_usd=0.05,
            tokens_used=500,
            model="claude-opus-4",
            timestamp=datetime.now(tz=timezone.utc),
        )
        assert record.agent_id == "agent-1"
        assert record.tokens_used == 500


# ---------------------------------------------------------------------------
# CostLimiter properties
# ---------------------------------------------------------------------------


class TestLimiterProperties:
    def test_per_action_limit_property(self, limiter: CostLimiter) -> None:
        assert limiter.per_action_limit == 1.0

    def test_per_session_limit_property(self, limiter: CostLimiter) -> None:
        assert limiter.per_session_limit == 5.0

    def test_per_day_limit_property(self, limiter: CostLimiter) -> None:
        assert limiter.per_day_limit == 20.0

    def test_default_limits(self) -> None:
        limiter = CostLimiter()
        assert limiter.per_action_limit == 1.0
        assert limiter.per_session_limit == 10.0
        assert limiter.per_day_limit == 100.0


# ---------------------------------------------------------------------------
# check — allowed cases
# ---------------------------------------------------------------------------


class TestCheckAllowed:
    def test_all_within_limits(self, limiter: CostLimiter, tracker: CostTracker) -> None:
        result = limiter.check("agent-1", estimated_cost=0.5, tracker=tracker)
        assert result.allowed is True
        assert "within" in result.reason.lower()

    def test_zero_cost_always_allowed(self, limiter: CostLimiter, tracker: CostTracker) -> None:
        result = limiter.check("agent-1", estimated_cost=0.0, tracker=tracker)
        assert result.allowed is True

    def test_check_with_accumulated_but_within_session(self, limiter: CostLimiter, tracker: CostTracker) -> None:
        tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=2.0)
        result = limiter.check("agent-1", estimated_cost=0.5, tracker=tracker)
        assert result.allowed is True  # 2.5 < 5.0 session limit


# ---------------------------------------------------------------------------
# check — per-action limit
# ---------------------------------------------------------------------------


class TestCheckPerActionLimit:
    def test_action_exceeds_limit(self, limiter: CostLimiter, tracker: CostTracker) -> None:
        result = limiter.check("agent-1", estimated_cost=1.5, tracker=tracker)
        assert result.allowed is False
        assert "per-action" in result.reason.lower()

    def test_action_exactly_at_limit_is_allowed(self, limiter: CostLimiter, tracker: CostTracker) -> None:
        # estimated_cost > per_action_limit, so exactly equal means allowed
        result = limiter.check("agent-1", estimated_cost=1.0, tracker=tracker)
        assert result.allowed is True

    def test_action_limit_error_fields(self, limiter: CostLimiter, tracker: CostTracker) -> None:
        result = limiter.check("agent-1", estimated_cost=2.0, tracker=tracker)
        assert result.current_cost == pytest.approx(2.0)
        assert result.limit == pytest.approx(1.0)


# ---------------------------------------------------------------------------
# check — per-session limit
# ---------------------------------------------------------------------------


class TestCheckPerSessionLimit:
    def test_session_limit_exceeded(self, limiter: CostLimiter, tracker: CostTracker) -> None:
        tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=4.5)
        result = limiter.check("agent-1", estimated_cost=0.8, tracker=tracker)
        assert result.allowed is False
        assert "session" in result.reason.lower()

    def test_session_limit_error_fields(self, limiter: CostLimiter, tracker: CostTracker) -> None:
        tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=4.5)
        result = limiter.check("agent-1", estimated_cost=0.8, tracker=tracker)
        assert result.current_cost == pytest.approx(4.5)
        assert result.limit == pytest.approx(5.0)


# ---------------------------------------------------------------------------
# check — per-day limit
# ---------------------------------------------------------------------------


class TestCheckPerDayLimit:
    def test_day_limit_exceeded(self, tracker: CostTracker) -> None:
        # Use a limiter with a very low day limit
        limiter = CostLimiter(per_action_limit=100.0, per_session_limit=1000.0, per_day_limit=5.0)
        tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=4.8)
        result = limiter.check("agent-1", estimated_cost=0.5, tracker=tracker)
        assert result.allowed is False
        assert "day" in result.reason.lower() or "daily" in result.reason.lower()
