"""Append-only JSONL audit logger.

All governance events are written as newline-delimited JSON records.
Each record carries a UTC ISO-8601 timestamp, a session identifier, and
arbitrary event fields supplied by the caller.

Thread-safety is achieved with a threading.Lock so the logger is safe to
call from multiple threads within the same process.

Example
-------
>>> from pathlib import Path
>>> logger = AuditLogger(Path("/tmp/audit.jsonl"))
>>> logger.log({"event": "file_read", "path": "/data/report.csv", "agent": "analyst"})
>>> entries = logger.read_all()
>>> len(entries)
1
"""
from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator


class AuditLogger:
    """Append-only JSONL audit logger.

    Parameters
    ----------
    log_path:
        Path to the ``.jsonl`` audit file.  Parent directories are created
        automatically on first write.
    session_id:
        Optional session identifier stamped on every record.  A random UUID
        is generated if not supplied.
    """

    def __init__(
        self,
        log_path: Path,
        session_id: str | None = None,
    ) -> None:
        self._log_path = log_path
        self._session_id: str = session_id or str(uuid.uuid4())
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Write API
    # ------------------------------------------------------------------

    def log(self, entry: dict[str, object]) -> None:
        """Append a governance event record to the audit log.

        The following fields are automatically added (and cannot be
        overridden by the caller):

        - ``timestamp``  — UTC ISO-8601 datetime
        - ``session_id`` — session identifier

        Parameters
        ----------
        entry:
            Arbitrary event dictionary.  Must be JSON-serialisable.
        """
        record: dict[str, object] = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "session_id": self._session_id,
            **entry,
        }
        self._write(record)

    # ------------------------------------------------------------------
    # Read API
    # ------------------------------------------------------------------

    def read_all(self) -> list[dict[str, object]]:
        """Return all audit records from the log file.

        Returns
        -------
        list[dict[str, object]]
            Parsed records in chronological order.  Returns an empty list
            when the log file does not exist.
        """
        return list(self._iter_records())

    def query(self, filters: dict[str, object]) -> list[dict[str, object]]:
        """Return records matching all supplied filter key/value pairs.

        Parameters
        ----------
        filters:
            Dict of ``{field: expected_value}`` pairs.  A record matches
            when every field equals the expected value (AND semantics).
            Nested field access is not supported — top-level keys only.

        Example
        -------
        >>> logger.query({"event": "policy_block", "agent": "analyst"})
        [...]
        """
        results: list[dict[str, object]] = []
        for record in self._iter_records():
            if all(record.get(k) == v for k, v in filters.items()):
                results.append(record)
        return results

    def count(self) -> int:
        """Return the total number of audit records."""
        return sum(1 for _ in self._iter_records())

    def last_n(self, n: int) -> list[dict[str, object]]:
        """Return the ``n`` most recent audit records.

        Parameters
        ----------
        n:
            Maximum number of records to return.
        """
        all_records = list(self._iter_records())
        return all_records[-n:] if n < len(all_records) else all_records

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write(self, record: dict[str, object]) -> None:
        """Write a single record to the JSONL file under the lock."""
        with self._lock:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")

    def _iter_records(self) -> Iterator[dict[str, object]]:
        """Yield parsed records from the log file one at a time."""
        if not self._log_path.exists():
            return
        with self._lock:
            with self._log_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            pass  # Skip malformed lines silently.

    @property
    def log_path(self) -> Path:
        """The filesystem path of the audit log file."""
        return self._log_path

    @property
    def session_id(self) -> str:
        """The session identifier stamped on every record."""
        return self._session_id
