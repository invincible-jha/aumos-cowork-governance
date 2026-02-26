"""API token usage and cost tracker.

CostTracker accumulates per-call usage records and maintains running
totals. Records are stored in memory and can be persisted to JSONL via
the AuditLogger.

Example
-------
>>> tracker = CostTracker()
>>> tracker.record(task_id="t1", model="claude-opus-4", input_tokens=1000,
...                output_tokens=200, cost_usd=0.018)
>>> tracker.total_cost_usd()
0.018
>>> tracker.total_tokens()
1200
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Iterator


@dataclass
class UsageRecord:
    """A single API call usage record.

    Attributes
    ----------
    timestamp:
        UTC datetime of the API call.
    task_id:
        Caller-supplied task identifier.
    model:
        Model identifier used for the call.
    input_tokens:
        Number of input/prompt tokens.
    output_tokens:
        Number of output/completion tokens.
    cost_usd:
        Actual or estimated cost in USD.
    metadata:
        Optional additional key-value pairs.
    """

    timestamp: datetime
    task_id: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    metadata: dict[str, object] = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        """Sum of input and output tokens."""
        return self.input_tokens + self.output_tokens


class CostTracker:
    """Thread-safe in-memory tracker for API token usage and costs.

    Parameters
    ----------
    session_id:
        Optional identifier for the current tracking session.
    """

    def __init__(self, session_id: str | None = None) -> None:
        self._session_id = session_id or "default"
        self._records: list[UsageRecord] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def record(
        self,
        task_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        metadata: dict[str, object] | None = None,
        timestamp: datetime | None = None,
    ) -> UsageRecord:
        """Record a single API call usage entry.

        Parameters
        ----------
        task_id:
            Caller-supplied task or request identifier.
        model:
            Model identifier (e.g., ``"claude-opus-4"``).
        input_tokens:
            Number of prompt/input tokens consumed.
        output_tokens:
            Number of completion/output tokens produced.
        cost_usd:
            Actual or estimated cost in USD.
        metadata:
            Optional additional key-value pairs to store with the record.
        timestamp:
            Override the record timestamp (defaults to UTC now).

        Returns
        -------
        UsageRecord
            The newly created record.
        """
        record = UsageRecord(
            timestamp=timestamp or datetime.now(tz=timezone.utc),
            task_id=task_id,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost_usd,
            metadata=metadata or {},
        )
        with self._lock:
            self._records.append(record)
        return record

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def all_records(self) -> list[UsageRecord]:
        """Return a snapshot of all usage records."""
        with self._lock:
            return list(self._records)

    def records_for_task(self, task_id: str) -> list[UsageRecord]:
        """Return all records for a specific task identifier."""
        with self._lock:
            return [r for r in self._records if r.task_id == task_id]

    def records_for_date(self, target_date: date) -> list[UsageRecord]:
        """Return all records for a specific calendar date (UTC).

        Parameters
        ----------
        target_date:
            The calendar date to filter by.
        """
        with self._lock:
            return [r for r in self._records if r.timestamp.date() == target_date]

    def total_cost_usd(self, target_date: date | None = None) -> float:
        """Return total cost in USD, optionally filtered to a date.

        Parameters
        ----------
        target_date:
            When supplied, only include records from that date.
        """
        records = self.records_for_date(target_date) if target_date else self.all_records()
        return sum(r.cost_usd for r in records)

    def total_tokens(self, target_date: date | None = None) -> int:
        """Return total token count, optionally filtered to a date."""
        records = self.records_for_date(target_date) if target_date else self.all_records()
        return sum(r.total_tokens for r in records)

    def cost_by_model(self) -> dict[str, float]:
        """Return a breakdown of total cost grouped by model name."""
        breakdown: dict[str, float] = {}
        for record in self.all_records():
            breakdown[record.model] = breakdown.get(record.model, 0.0) + record.cost_usd
        return breakdown

    def cost_by_task(self) -> dict[str, float]:
        """Return a breakdown of total cost grouped by task identifier."""
        breakdown: dict[str, float] = {}
        for record in self.all_records():
            breakdown[record.task_id] = breakdown.get(record.task_id, 0.0) + record.cost_usd
        return breakdown

    def iter_records(self) -> Iterator[UsageRecord]:
        """Yield all usage records one at a time."""
        with self._lock:
            yield from list(self._records)

    def reset(self) -> None:
        """Clear all recorded usage data."""
        with self._lock:
            self._records.clear()

    @property
    def session_id(self) -> str:
        """The session identifier for this tracker."""
        return self._session_id
