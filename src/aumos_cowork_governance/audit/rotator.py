"""Daily audit log rotation with configurable retention.

The LogRotator renames the current audit log to a date-stamped archive file
and removes archives older than the retention window.

Rotation is idempotent — if the current log file is already from today,
no rotation occurs.

Example
-------
>>> from pathlib import Path
>>> from aumos_cowork_governance.audit.rotator import LogRotator
>>> rotator = LogRotator(Path("/var/log/cowork"), retention_days=90)
>>> rotator.rotate_if_needed()
"""
from __future__ import annotations

import logging
from datetime import date, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


class LogRotator:
    """Manages daily rotation and retention of JSONL audit log files.

    Parameters
    ----------
    log_dir:
        Directory containing the audit logs.
    log_filename:
        Base filename for the active audit log (default: ``audit.jsonl``).
    retention_days:
        How many days of archived logs to keep.  Older archives are deleted.
    """

    _ARCHIVE_SUFFIX: str = ".jsonl"

    def __init__(
        self,
        log_dir: Path,
        log_filename: str = "audit.jsonl",
        retention_days: int = 90,
    ) -> None:
        self._log_dir = log_dir
        self._log_filename = log_filename
        self._retention_days = retention_days

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def rotate_if_needed(self, today: date | None = None) -> bool:
        """Rotate the active log if it was last modified on a previous day.

        Parameters
        ----------
        today:
            Override the current date (useful for testing).

        Returns
        -------
        bool
            ``True`` when a rotation actually occurred.
        """
        current_log = self._log_dir / self._log_filename
        if not current_log.exists():
            return False

        effective_today = today or date.today()
        last_modified_date = date.fromtimestamp(current_log.stat().st_mtime)

        if last_modified_date >= effective_today:
            return False

        archive_name = f"audit-{last_modified_date.isoformat()}.jsonl"
        archive_path = self._log_dir / archive_name
        current_log.rename(archive_path)
        logger.info("Rotated audit log to %s", archive_path)

        self._purge_old_archives(effective_today)
        return True

    def force_rotate(self, today: date | None = None) -> Path:
        """Force rotation regardless of the last-modified date.

        Parameters
        ----------
        today:
            Override the current date stamp used in the archive filename.

        Returns
        -------
        Path
            Path of the newly created archive file.
        """
        effective_today = today or date.today()
        current_log = self._log_dir / self._log_filename

        archive_name = f"audit-{effective_today.isoformat()}.jsonl"
        archive_path = self._log_dir / archive_name

        if current_log.exists():
            current_log.rename(archive_path)
            logger.info("Force-rotated audit log to %s", archive_path)
        else:
            archive_path.touch()

        self._purge_old_archives(effective_today)
        return archive_path

    def list_archives(self) -> list[Path]:
        """Return a sorted list of all archive log files in the log directory.

        Returns
        -------
        list[Path]
            Paths sorted by filename (oldest first).
        """
        if not self._log_dir.exists():
            return []
        return sorted(
            p
            for p in self._log_dir.iterdir()
            if p.is_file()
            and p.name.startswith("audit-")
            and p.suffix == self._ARCHIVE_SUFFIX
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _purge_old_archives(self, today: date) -> None:
        """Delete archive files older than the retention window."""
        cutoff = today - timedelta(days=self._retention_days)
        for archive in self.list_archives():
            date_str = archive.stem.removeprefix("audit-")
            try:
                archive_date = date.fromisoformat(date_str)
            except ValueError:
                continue
            if archive_date < cutoff:
                archive.unlink(missing_ok=True)
                logger.info("Purged old audit archive: %s", archive)
