"""Audit log search utilities.

AuditSearch wraps an AuditLogger and provides ergonomic search methods
for filtering audit records by date range, event type, agent identifier,
and file path.

Example
-------
>>> from pathlib import Path
>>> from aumos_cowork_governance.audit.logger import AuditLogger
>>> from aumos_cowork_governance.audit.search import AuditSearch
>>> audit = AuditLogger(Path("/tmp/audit.jsonl"))
>>> search = AuditSearch(audit)
>>> results = search.by_event("policy_block")
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator

from aumos_cowork_governance.audit.logger import AuditLogger


class AuditSearch:
    """Provides search and filtering over an :class:`AuditLogger` instance.

    Parameters
    ----------
    logger:
        The audit logger whose records will be searched.
    """

    def __init__(self, logger: AuditLogger) -> None:
        self._logger = logger

    # ------------------------------------------------------------------
    # Public search methods
    # ------------------------------------------------------------------

    def by_date_range(
        self,
        start: datetime,
        end: datetime,
    ) -> list[dict[str, object]]:
        """Return records whose timestamps fall within [start, end].

        Parameters
        ----------
        start:
            Inclusive lower bound (timezone-aware recommended).
        end:
            Inclusive upper bound (timezone-aware recommended).

        Returns
        -------
        list[dict[str, object]]
            Matching records in chronological order.
        """
        results: list[dict[str, object]] = []
        for record in self._logger.read_all():
            ts = self._parse_timestamp(record.get("timestamp"))
            if ts is None:
                continue
            if start <= ts <= end:
                results.append(record)
        return results

    def by_event(self, event_type: str) -> list[dict[str, object]]:
        """Return records with a specific ``event`` field value.

        Parameters
        ----------
        event_type:
            Exact string to match against the ``event`` field.
        """
        return [r for r in self._logger.read_all() if r.get("event") == event_type]

    def by_agent(self, agent_id: str) -> list[dict[str, object]]:
        """Return records produced by a specific agent.

        Parameters
        ----------
        agent_id:
            Exact string to match against the ``agent`` or ``agent_id``
            field.
        """
        results: list[dict[str, object]] = []
        for record in self._logger.read_all():
            if record.get("agent") == agent_id or record.get("agent_id") == agent_id:
                results.append(record)
        return results

    def by_file_path(self, path_prefix: str) -> list[dict[str, object]]:
        """Return records where the ``path`` field starts with ``path_prefix``.

        Parameters
        ----------
        path_prefix:
            Prefix to match against the ``path`` field.
        """
        results: list[dict[str, object]] = []
        for record in self._logger.read_all():
            path_value = record.get("path", "")
            if isinstance(path_value, str) and path_value.startswith(path_prefix):
                results.append(record)
            # Also check nested action_context.path
            context = record.get("action_context", {})
            if isinstance(context, dict):
                ctx_path = context.get("path", "")
                if isinstance(ctx_path, str) and ctx_path.startswith(path_prefix):
                    results.append(record)
        # Deduplicate (a record could match both checks above).
        seen: set[int] = set()
        deduped: list[dict[str, object]] = []
        for r in results:
            rid = id(r)
            if rid not in seen:
                seen.add(rid)
                deduped.append(r)
        return deduped

    def by_policy(self, policy_name: str) -> list[dict[str, object]]:
        """Return records associated with a specific policy name.

        Parameters
        ----------
        policy_name:
            Exact string to match against the ``policy`` field.
        """
        return [r for r in self._logger.read_all() if r.get("policy") == policy_name]

    def by_session(self, session_id: str) -> list[dict[str, object]]:
        """Return all records from a specific session.

        Parameters
        ----------
        session_id:
            UUID session identifier.
        """
        return [r for r in self._logger.read_all() if r.get("session_id") == session_id]

    def multi_filter(
        self,
        event_type: str | None = None,
        agent_id: str | None = None,
        path_prefix: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
    ) -> list[dict[str, object]]:
        """Apply multiple filters simultaneously (AND semantics).

        Parameters
        ----------
        event_type:
            Optional exact event type filter.
        agent_id:
            Optional agent identifier filter.
        path_prefix:
            Optional path prefix filter.
        start:
            Optional inclusive start datetime.
        end:
            Optional inclusive end datetime.

        Returns
        -------
        list[dict[str, object]]
            Records matching all supplied filters.
        """
        results: list[dict[str, object]] = []
        for record in self._logger.read_all():
            if event_type is not None and record.get("event") != event_type:
                continue
            if agent_id is not None:
                if record.get("agent") != agent_id and record.get("agent_id") != agent_id:
                    continue
            if path_prefix is not None:
                path_value = record.get("path", "")
                if not isinstance(path_value, str) or not path_value.startswith(path_prefix):
                    continue
            if start is not None or end is not None:
                ts = self._parse_timestamp(record.get("timestamp"))
                if ts is None:
                    continue
                if start is not None and ts < start:
                    continue
                if end is not None and ts > end:
                    continue
            results.append(record)
        return results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_timestamp(self, raw: object) -> datetime | None:
        """Parse an ISO-8601 timestamp string into an aware datetime."""
        if not isinstance(raw, str):
            return None
        try:
            dt = datetime.fromisoformat(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            return None
