"""Tests for CostTracker and BudgetManager."""
from __future__ import annotations

import pytest
from datetime import date, datetime, timezone

from aumos_cowork_governance.cost.tracker import CostTracker, UsageRecord
from aumos_cowork_governance.cost.budget import (
    BudgetManager,
    BudgetPeriod,
    BudgetStatus,
    PeriodStatus,
)


# ---------------------------------------------------------------------------
# UsageRecord
# ---------------------------------------------------------------------------


class TestUsageRecord:
    def test_total_tokens_property(self) -> None:
        record = UsageRecord(
            timestamp=datetime.now(tz=timezone.utc),
            task_id="t1",
            model="claude-opus-4",
            input_tokens=800,
            output_tokens=200,
            cost_usd=0.01,
        )
        assert record.total_tokens == 1000

    def test_metadata_defaults_to_empty_dict(self) -> None:
        record = UsageRecord(
            timestamp=datetime.now(tz=timezone.utc),
            task_id="t1",
            model="claude-opus-4",
            input_tokens=100,
            output_tokens=50,
            cost_usd=0.005,
        )
        assert record.metadata == {}


# ---------------------------------------------------------------------------
# CostTracker — record
# ---------------------------------------------------------------------------


@pytest.fixture()
def tracker() -> CostTracker:
    return CostTracker(session_id="test-session")


class TestCostTrackerRecord:
    def test_record_returns_usage_record(self, tracker: CostTracker) -> None:
        record = tracker.record(
            task_id="t1", model="claude-opus-4",
            input_tokens=500, output_tokens=100, cost_usd=0.01
        )
        assert isinstance(record, UsageRecord)

    def test_record_stores_entry(self, tracker: CostTracker) -> None:
        tracker.record(task_id="t1", model="m", input_tokens=100, output_tokens=50, cost_usd=0.001)
        assert len(tracker.all_records()) == 1

    def test_record_custom_timestamp(self, tracker: CostTracker) -> None:
        ts = datetime(2025, 1, 10, tzinfo=timezone.utc)
        record = tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=0.001, timestamp=ts)
        assert record.timestamp == ts

    def test_record_metadata_stored(self, tracker: CostTracker) -> None:
        record = tracker.record(
            task_id="t1", model="m", input_tokens=10, output_tokens=5,
            cost_usd=0.001, metadata={"tag": "batch-run"}
        )
        assert record.metadata["tag"] == "batch-run"

    def test_session_id_property(self, tracker: CostTracker) -> None:
        assert tracker.session_id == "test-session"

    def test_default_session_id(self) -> None:
        t = CostTracker()
        assert t.session_id == "default"


# ---------------------------------------------------------------------------
# CostTracker — read API
# ---------------------------------------------------------------------------


class TestCostTrackerRead:
    def test_all_records_returns_snapshot(self, tracker: CostTracker) -> None:
        tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=0.001)
        tracker.record(task_id="t2", model="m", input_tokens=10, output_tokens=5, cost_usd=0.002)
        records = tracker.all_records()
        assert len(records) == 2

    def test_records_for_task(self, tracker: CostTracker) -> None:
        tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=0.001)
        tracker.record(task_id="t2", model="m", input_tokens=10, output_tokens=5, cost_usd=0.002)
        tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=0.003)
        results = tracker.records_for_task("t1")
        assert len(results) == 2
        assert all(r.task_id == "t1" for r in results)

    def test_records_for_date(self, tracker: CostTracker) -> None:
        today = date.today()
        yesterday = date(today.year, today.month, max(1, today.day - 1))
        tracker.record(
            task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=0.01,
            timestamp=datetime(yesterday.year, yesterday.month, yesterday.day, tzinfo=timezone.utc)
        )
        tracker.record(task_id="t2", model="m", input_tokens=10, output_tokens=5, cost_usd=0.02)
        results = tracker.records_for_date(today)
        assert len(results) == 1
        assert results[0].task_id == "t2"

    def test_total_cost_usd(self, tracker: CostTracker) -> None:
        tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=0.01)
        tracker.record(task_id="t2", model="m", input_tokens=10, output_tokens=5, cost_usd=0.02)
        assert tracker.total_cost_usd() == pytest.approx(0.03)

    def test_total_cost_usd_filtered_by_date(self, tracker: CostTracker) -> None:
        today = date.today()
        tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=0.05)
        cost = tracker.total_cost_usd(target_date=today)
        assert cost == pytest.approx(0.05)

    def test_total_tokens(self, tracker: CostTracker) -> None:
        tracker.record(task_id="t1", model="m", input_tokens=100, output_tokens=50, cost_usd=0.01)
        tracker.record(task_id="t2", model="m", input_tokens=200, output_tokens=100, cost_usd=0.02)
        assert tracker.total_tokens() == 450

    def test_total_tokens_for_date(self, tracker: CostTracker) -> None:
        today = date.today()
        tracker.record(task_id="t1", model="m", input_tokens=300, output_tokens=100, cost_usd=0.01)
        assert tracker.total_tokens(target_date=today) == 400

    def test_cost_by_model(self, tracker: CostTracker) -> None:
        tracker.record(task_id="t1", model="claude-opus-4", input_tokens=100, output_tokens=50, cost_usd=0.01)
        tracker.record(task_id="t2", model="claude-opus-4", input_tokens=100, output_tokens=50, cost_usd=0.02)
        tracker.record(task_id="t3", model="gpt-4o", input_tokens=100, output_tokens=50, cost_usd=0.005)
        breakdown = tracker.cost_by_model()
        assert breakdown["claude-opus-4"] == pytest.approx(0.03)
        assert breakdown["gpt-4o"] == pytest.approx(0.005)

    def test_cost_by_task(self, tracker: CostTracker) -> None:
        tracker.record(task_id="task-a", model="m", input_tokens=10, output_tokens=5, cost_usd=0.01)
        tracker.record(task_id="task-a", model="m", input_tokens=10, output_tokens=5, cost_usd=0.02)
        tracker.record(task_id="task-b", model="m", input_tokens=10, output_tokens=5, cost_usd=0.05)
        breakdown = tracker.cost_by_task()
        assert breakdown["task-a"] == pytest.approx(0.03)
        assert breakdown["task-b"] == pytest.approx(0.05)

    def test_iter_records(self, tracker: CostTracker) -> None:
        tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=0.001)
        records = list(tracker.iter_records())
        assert len(records) == 1

    def test_reset_clears_all(self, tracker: CostTracker) -> None:
        tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=0.01)
        tracker.reset()
        assert tracker.all_records() == []
        assert tracker.total_cost_usd() == 0.0

    def test_empty_tracker_cost_is_zero(self, tracker: CostTracker) -> None:
        assert tracker.total_cost_usd() == 0.0
        assert tracker.total_tokens() == 0


# ---------------------------------------------------------------------------
# BudgetManager
# ---------------------------------------------------------------------------


@pytest.fixture()
def empty_tracker() -> CostTracker:
    return CostTracker()


class TestBudgetManager:
    def test_no_limits_always_within_budget(self, empty_tracker: CostTracker) -> None:
        manager = BudgetManager(empty_tracker)
        status = manager.check()
        assert status.within_budget is True
        assert status.daily is None
        assert status.weekly is None
        assert status.monthly is None

    def test_daily_limit_not_exceeded(self, empty_tracker: CostTracker) -> None:
        manager = BudgetManager(empty_tracker, daily_usd=10.0)
        empty_tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=5.0)
        status = manager.check()
        assert status.within_budget is True
        assert status.daily is not None
        assert status.daily.exceeded is False

    def test_daily_limit_exceeded(self, empty_tracker: CostTracker) -> None:
        manager = BudgetManager(empty_tracker, daily_usd=5.0)
        empty_tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=6.0)
        status = manager.check()
        assert status.within_budget is False
        assert "daily" in status.exceeded_periods

    def test_daily_remaining_usd_positive(self, empty_tracker: CostTracker) -> None:
        manager = BudgetManager(empty_tracker, daily_usd=10.0)
        empty_tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=3.0)
        remaining = manager.daily_remaining_usd()
        assert remaining == pytest.approx(7.0)

    def test_daily_remaining_usd_none_when_not_configured(self, empty_tracker: CostTracker) -> None:
        manager = BudgetManager(empty_tracker)
        assert manager.daily_remaining_usd() is None

    def test_daily_remaining_clamped_to_zero(self, empty_tracker: CostTracker) -> None:
        manager = BudgetManager(empty_tracker, daily_usd=1.0)
        empty_tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=5.0)
        remaining = manager.daily_remaining_usd()
        assert remaining == 0.0

    def test_approaching_flag_set_at_80_percent(self, empty_tracker: CostTracker) -> None:
        manager = BudgetManager(empty_tracker, daily_usd=10.0, approaching_threshold_pct=80.0)
        # Spend exactly 80%
        today = date.today()
        empty_tracker.record(
            task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=8.0,
            timestamp=datetime(today.year, today.month, today.day, tzinfo=timezone.utc)
        )
        status = manager.check(reference_date=today)
        assert status.daily is not None
        assert status.daily.approaching is True
        assert status.daily.exceeded is False

    def test_is_within_budget_shortcut(self, empty_tracker: CostTracker) -> None:
        manager = BudgetManager(empty_tracker, daily_usd=100.0)
        assert manager.is_within_budget() is True

    def test_monthly_limit_exceeded(self, empty_tracker: CostTracker) -> None:
        manager = BudgetManager(empty_tracker, monthly_usd=5.0)
        empty_tracker.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=10.0)
        status = manager.check()
        assert status.within_budget is False
        assert "monthly" in status.exceeded_periods

    def test_period_status_fields(self, empty_tracker: CostTracker) -> None:
        manager = BudgetManager(empty_tracker, daily_usd=10.0)
        status = manager.check()
        ps = status.daily
        assert ps is not None
        assert ps.period == BudgetPeriod.DAILY
        assert ps.limit_usd == 10.0
        # spent_usd may be int(0) when no records exist — check numeric type
        assert isinstance(ps.spent_usd, (int, float))
        assert isinstance(ps.percent_used, float)

    def test_reference_date_overrides_today(self, empty_tracker: CostTracker) -> None:
        ref_date = date(2025, 6, 15)
        empty_tracker.record(
            task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=3.0,
            timestamp=datetime(2025, 6, 15, tzinfo=timezone.utc)
        )
        manager = BudgetManager(empty_tracker, daily_usd=10.0)
        status = manager.check(reference_date=ref_date)
        assert status.daily is not None
        assert status.daily.spent_usd == pytest.approx(3.0)
