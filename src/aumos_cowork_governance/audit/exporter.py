"""Audit log exporter.

Exports audit records to CSV or JSON formats for external analysis,
compliance evidence packages, or long-term archival.

Example
-------
>>> from pathlib import Path
>>> from aumos_cowork_governance.audit.logger import AuditLogger
>>> from aumos_cowork_governance.audit.exporter import AuditExporter
>>> audit = AuditLogger(Path("/tmp/audit.jsonl"))
>>> exporter = AuditExporter(audit)
>>> exporter.to_csv(Path("/tmp/audit_export.csv"))
>>> exporter.to_json(Path("/tmp/audit_export.json"))
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

from aumos_cowork_governance.audit.logger import AuditLogger


class AuditExporter:
    """Exports audit log records to structured file formats.

    Parameters
    ----------
    logger:
        The :class:`AuditLogger` instance to export from.
    """

    def __init__(self, logger: AuditLogger) -> None:
        self._logger = logger

    # ------------------------------------------------------------------
    # Export methods
    # ------------------------------------------------------------------

    def to_csv(
        self,
        output_path: Path,
        records: list[dict[str, object]] | None = None,
    ) -> int:
        """Export audit records to a CSV file.

        The CSV column set is the union of all keys across all records.
        Records missing a key have an empty cell for that column.

        Parameters
        ----------
        output_path:
            Destination path for the CSV file.
        records:
            Optional pre-filtered record list.  When omitted, all records
            from the logger are exported.

        Returns
        -------
        int
            Number of records written.
        """
        data = records if records is not None else self._logger.read_all()
        if not data:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text("", encoding="utf-8")
            return 0

        # Collect the union of all keys, preserving insertion order.
        fieldnames: list[str] = []
        seen: set[str] = set()
        for record in data:
            for key in record:
                if key not in seen:
                    fieldnames.append(key)
                    seen.add(key)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for record in data:
                # Flatten nested dicts to JSON strings for CSV compatibility.
                flat: dict[str, object] = {}
                for k, v in record.items():
                    if isinstance(v, (dict, list)):
                        flat[k] = json.dumps(v, default=str)
                    else:
                        flat[k] = v
                writer.writerow(flat)

        return len(data)

    def to_json(
        self,
        output_path: Path,
        records: list[dict[str, object]] | None = None,
        indent: int = 2,
    ) -> int:
        """Export audit records to a formatted JSON array file.

        Parameters
        ----------
        output_path:
            Destination path for the JSON file.
        records:
            Optional pre-filtered record list.
        indent:
            JSON indentation level (default: 2).

        Returns
        -------
        int
            Number of records written.
        """
        data = records if records is not None else self._logger.read_all()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=indent, default=str)
        return len(data)

    def to_jsonl(
        self,
        output_path: Path,
        records: list[dict[str, object]] | None = None,
    ) -> int:
        """Export audit records to a JSONL (newline-delimited JSON) file.

        Parameters
        ----------
        output_path:
            Destination path for the JSONL file.
        records:
            Optional pre-filtered record list.

        Returns
        -------
        int
            Number of records written.
        """
        data = records if records is not None else self._logger.read_all()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as fh:
            for record in data:
                fh.write(json.dumps(record, default=str) + "\n")
        return len(data)
