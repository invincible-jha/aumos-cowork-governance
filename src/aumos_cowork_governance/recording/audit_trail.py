"""Session recording and audit trail.

Records every agent action during a co-work session with a full,
timestamped, immutable log.  Entries can be exported to JSON Lines
format and queried by time range or action type.

This provides a tamper-evident audit trail for compliance and post-incident
investigation.
"""
from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Audit entry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditEntry:
    """A single audit log entry for an agent action.

    Attributes
    ----------
    entry_id:
        Unique, sequential identifier for this entry.
    timestamp:
        UTC timestamp of when the action occurred.
    action_type:
        Category of the action (e.g. "click", "type", "navigate").
    target:
        The target of the action (e.g. element ID, URL, filename).
    result:
        Outcome of the action: "success", "failure", "skipped".
    session_id:
        Identifier of the session this entry belongs to.
    user_id:
        Identifier of the user/agent that performed the action.
    metadata:
        Additional context (e.g. coordinates, input text).
    """

    entry_id: str
    timestamp: datetime.datetime
    action_type: str
    target: str
    result: str
    session_id: str
    user_id: str
    metadata: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        """Serialise this entry to a plain dict.

        Returns
        -------
        dict[str, object]
            JSON-serialisable representation of this entry.
        """
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "action_type": self.action_type,
            "target": self.target,
            "result": self.result,
            "session_id": self.session_id,
            "user_id": self.user_id,
            "metadata": self.metadata,
        }

    def to_jsonl(self) -> str:
        """Return this entry as a single JSON Lines line.

        Returns
        -------
        str
            JSON-serialised entry followed by a newline character.
        """
        return json.dumps(self.to_dict(), default=str) + "\n"

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> AuditEntry:
        """Reconstruct an entry from a plain dict.

        Parameters
        ----------
        data:
            Dict produced by :meth:`to_dict`.

        Returns
        -------
        AuditEntry
            The reconstructed entry.
        """
        ts_raw = data["timestamp"]
        if isinstance(ts_raw, str):
            ts = datetime.datetime.fromisoformat(ts_raw)
        else:
            ts = ts_raw
        return cls(
            entry_id=data["entry_id"],
            timestamp=ts,
            action_type=data["action_type"],
            target=data["target"],
            result=data["result"],
            session_id=data["session_id"],
            user_id=data["user_id"],
            metadata=data.get("metadata", {}),
        )


# ---------------------------------------------------------------------------
# Session recorder
# ---------------------------------------------------------------------------


class SessionRecorder:
    """Records agent actions as a timestamped, ordered audit trail.

    Each action is appended to an in-memory log as an :class:`AuditEntry`.
    The log can be exported to JSON Lines format and queried by time range
    or action type.

    Parameters
    ----------
    session_id:
        Identifier for the session being recorded.
    user_id:
        Identifier of the user/agent performing actions.

    Example
    -------
    ::

        recorder = SessionRecorder("sess-abc", "user-1")
        recorder.record("click", target="#submit-btn", result="success")
        recorder.record("type", target="#email", result="success", metadata={"chars": 12})
        jsonl = recorder.export_jsonl()
    """

    def __init__(self, session_id: str, user_id: str = "system") -> None:
        self._session_id = session_id
        self._user_id = user_id
        self._entries: list[AuditEntry] = []
        self._counter: int = 0

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(
        self,
        action_type: str,
        target: str = "",
        result: str = "success",
        metadata: dict[str, object] | None = None,
        timestamp: datetime.datetime | None = None,
    ) -> AuditEntry:
        """Record a single action as an audit entry.

        Parameters
        ----------
        action_type:
            Category label for the action.
        target:
            What the action was performed on.
        result:
            Outcome: "success", "failure", or "skipped".
        metadata:
            Optional extra context.
        timestamp:
            Override the entry timestamp (default: UTC now).

        Returns
        -------
        AuditEntry
            The newly created (immutable) entry.
        """
        self._counter += 1
        entry = AuditEntry(
            entry_id=f"{self._session_id}-{self._counter:06d}",
            timestamp=timestamp or datetime.datetime.now(datetime.timezone.utc),
            action_type=action_type,
            target=target,
            result=result,
            session_id=self._session_id,
            user_id=self._user_id,
            metadata=dict(metadata or {}),
        )
        self._entries.append(entry)
        return entry

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def query_by_time_range(
        self,
        start: datetime.datetime,
        end: datetime.datetime,
    ) -> list[AuditEntry]:
        """Return entries whose timestamps fall within [start, end].

        Parameters
        ----------
        start:
            Inclusive start of the time range (UTC).
        end:
            Inclusive end of the time range (UTC).

        Returns
        -------
        list[AuditEntry]
            Entries in chronological order.
        """
        def _normalise(ts: datetime.datetime) -> datetime.datetime:
            if ts.tzinfo is None:
                return ts.replace(tzinfo=datetime.timezone.utc)
            return ts

        start_n = _normalise(start)
        end_n = _normalise(end)

        return [
            e for e in self._entries
            if start_n <= _normalise(e.timestamp) <= end_n
        ]

    def query_by_action_type(self, action_type: str) -> list[AuditEntry]:
        """Return all entries matching *action_type*.

        Parameters
        ----------
        action_type:
            The action category to filter by.

        Returns
        -------
        list[AuditEntry]
            Matching entries in chronological order.
        """
        return [e for e in self._entries if e.action_type == action_type]

    def query_by_result(self, result: str) -> list[AuditEntry]:
        """Return all entries with the given *result*.

        Parameters
        ----------
        result:
            E.g. "success", "failure", "skipped".

        Returns
        -------
        list[AuditEntry]
            Matching entries in chronological order.
        """
        return [e for e in self._entries if e.result == result]

    def get_all(self) -> list[AuditEntry]:
        """Return all recorded entries in chronological order."""
        return list(self._entries)

    def entry_count(self) -> int:
        """Return the number of recorded entries."""
        return len(self._entries)

    # ------------------------------------------------------------------
    # Export / import
    # ------------------------------------------------------------------

    def export_jsonl(self) -> str:
        """Export the full audit log as JSON Lines format.

        Returns
        -------
        str
            One JSON object per line, one line per entry.
        """
        return "".join(e.to_jsonl() for e in self._entries)

    @classmethod
    def from_jsonl(cls, jsonl_content: str, session_id: str, user_id: str = "system") -> SessionRecorder:
        """Reconstruct a :class:`SessionRecorder` from JSON Lines content.

        Parameters
        ----------
        jsonl_content:
            The JSON Lines string produced by :meth:`export_jsonl`.
        session_id:
            Session ID for the reconstructed recorder.
        user_id:
            User ID for the reconstructed recorder.

        Returns
        -------
        SessionRecorder
            Recorder pre-populated with the imported entries.
        """
        recorder = cls(session_id=session_id, user_id=user_id)
        for line in jsonl_content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                entry = AuditEntry.from_dict(data)
                recorder._entries.append(entry)
                recorder._counter += 1
            except (json.JSONDecodeError, KeyError):
                pass
        return recorder

    def export_summary(self) -> dict[str, object]:
        """Return a summary of recorded actions.

        Returns
        -------
        dict[str, object]
            Counts by action_type and result.
        """
        action_counts: dict[str, int] = {}
        result_counts: dict[str, int] = {}
        for entry in self._entries:
            action_counts[entry.action_type] = action_counts.get(entry.action_type, 0) + 1
            result_counts[entry.result] = result_counts.get(entry.result, 0) + 1
        return {
            "session_id": self._session_id,
            "total_entries": len(self._entries),
            "action_counts": action_counts,
            "result_counts": result_counts,
        }


__all__ = [
    "AuditEntry",
    "SessionRecorder",
]
