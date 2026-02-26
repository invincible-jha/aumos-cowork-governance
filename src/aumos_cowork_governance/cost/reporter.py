"""Cost usage reporter.

Generates CSV usage reports from CostTracker data with breakdowns
by model, task, and date.

Example
-------
>>> from pathlib import Path
>>> from aumos_cowork_governance.cost.tracker import CostTracker
>>> from aumos_cowork_governance.cost.reporter import CostReporter
>>> tracker = CostTracker()
>>> reporter = CostReporter(tracker)
>>> reporter.to_csv(Path("/tmp/cost_report.csv"), period="daily")
"""
from __future__ import annotations

import csv
from datetime import date, timedelta
from pathlib import Path

from aumos_cowork_governance.cost.tracker import CostTracker, UsageRecord


class CostReporter:
    """Generates cost reports from a :class:`CostTracker`.

    Parameters
    ----------
    tracker:
        The :class:`CostTracker` instance to report from.
    """

    def __init__(self, tracker: CostTracker) -> None:
        self._tracker = tracker

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def to_csv(
        self,
        output_path: Path,
        period: str = "all",
        reference_date: date | None = None,
    ) -> int:
        """Write a CSV usage report.

        Parameters
        ----------
        output_path:
            Destination CSV file path.
        period:
            ``"daily"``, ``"weekly"``, ``"monthly"``, or ``"all"``
            (default: ``"all"``).
        reference_date:
            Reference date for period filtering (defaults to today).

        Returns
        -------
        int
            Number of records written.
        """
        records = self._filter_by_period(period, reference_date)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "timestamp",
            "task_id",
            "model",
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "cost_usd",
        ]

        with output_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for record in records:
                writer.writerow(
                    {
                        "timestamp": record.timestamp.isoformat(),
                        "task_id": record.task_id,
                        "model": record.model,
                        "input_tokens": record.input_tokens,
                        "output_tokens": record.output_tokens,
                        "total_tokens": record.total_tokens,
                        "cost_usd": f"{record.cost_usd:.6f}",
                    }
                )

        return len(records)

    def summary(self, period: str = "all", reference_date: date | None = None) -> dict[str, object]:
        """Return a summary dict with aggregate statistics.

        Parameters
        ----------
        period:
            ``"daily"``, ``"weekly"``, ``"monthly"``, or ``"all"``.
        reference_date:
            Reference date for period filtering.

        Returns
        -------
        dict[str, object]
            Summary containing ``total_cost_usd``, ``total_tokens``,
            ``call_count``, ``by_model``, and ``by_task`` breakdowns.
        """
        records = self._filter_by_period(period, reference_date)

        total_cost = sum(r.cost_usd for r in records)
        total_tokens = sum(r.total_tokens for r in records)

        by_model: dict[str, dict[str, object]] = {}
        by_task: dict[str, float] = {}

        for record in records:
            model = record.model
            if model not in by_model:
                by_model[model] = {"cost_usd": 0.0, "tokens": 0, "calls": 0}
            by_model[model]["cost_usd"] = float(by_model[model]["cost_usd"]) + record.cost_usd
            by_model[model]["tokens"] = int(by_model[model]["tokens"]) + record.total_tokens
            by_model[model]["calls"] = int(by_model[model]["calls"]) + 1

            by_task[record.task_id] = by_task.get(record.task_id, 0.0) + record.cost_usd

        return {
            "period": period,
            "call_count": len(records),
            "total_cost_usd": round(total_cost, 6),
            "total_tokens": total_tokens,
            "by_model": by_model,
            "by_task": by_task,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _filter_by_period(
        self,
        period: str,
        reference_date: date | None,
    ) -> list[UsageRecord]:
        """Filter records to the requested period."""
        today = reference_date or date.today()
        all_records = self._tracker.all_records()

        match period:
            case "daily":
                return [r for r in all_records if r.timestamp.date() == today]
            case "weekly":
                start = today - timedelta(days=today.weekday())
                return [r for r in all_records if start <= r.timestamp.date() <= today]
            case "monthly":
                return [
                    r
                    for r in all_records
                    if r.timestamp.year == today.year and r.timestamp.month == today.month
                ]
            case _:
                return all_records
