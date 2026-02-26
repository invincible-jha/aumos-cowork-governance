"""Tests for AuditLogger."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aumos_cowork_governance.audit.logger import AuditLogger


@pytest.fixture()
def log_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture()
def logger(log_path: Path) -> AuditLogger:
    return AuditLogger(log_path, session_id="test-session-123")


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_custom_session_id(self, log_path: Path) -> None:
        audit = AuditLogger(log_path, session_id="my-session")
        assert audit.session_id == "my-session"

    def test_auto_session_id_generated(self, log_path: Path) -> None:
        audit = AuditLogger(log_path)
        assert audit.session_id  # non-empty UUID-like string

    def test_log_path_property(self, log_path: Path) -> None:
        audit = AuditLogger(log_path)
        assert audit.log_path == log_path


# ---------------------------------------------------------------------------
# log — writing
# ---------------------------------------------------------------------------


class TestLog:
    def test_log_creates_file(self, logger: AuditLogger, log_path: Path) -> None:
        logger.log({"event": "test"})
        assert log_path.exists()

    def test_log_writes_json_line(self, logger: AuditLogger, log_path: Path) -> None:
        logger.log({"event": "file_read", "path": "/data/report.csv"})
        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["event"] == "file_read"
        assert record["path"] == "/data/report.csv"

    def test_log_adds_timestamp(self, logger: AuditLogger) -> None:
        logger.log({"event": "test"})
        records = logger.read_all()
        assert "timestamp" in records[0]

    def test_log_adds_session_id(self, logger: AuditLogger) -> None:
        logger.log({"event": "test"})
        records = logger.read_all()
        assert records[0]["session_id"] == "test-session-123"

    def test_log_multiple_entries_appended(self, logger: AuditLogger, log_path: Path) -> None:
        logger.log({"event": "first"})
        logger.log({"event": "second"})
        lines = log_path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2

    def test_log_creates_parent_dirs(self, tmp_path: Path) -> None:
        nested = tmp_path / "deep" / "nested" / "audit.jsonl"
        audit = AuditLogger(nested)
        audit.log({"event": "test"})
        assert nested.exists()

    def test_log_caller_fields_in_record(self, logger: AuditLogger) -> None:
        logger.log({"event": "policy_block", "agent": "analyst", "cost": 0.5})
        records = logger.read_all()
        assert records[0]["agent"] == "analyst"
        assert records[0]["cost"] == 0.5


# ---------------------------------------------------------------------------
# read_all
# ---------------------------------------------------------------------------


class TestReadAll:
    def test_read_all_empty_when_no_file(self, log_path: Path) -> None:
        audit = AuditLogger(log_path)
        assert audit.read_all() == []

    def test_read_all_returns_all_records(self, logger: AuditLogger) -> None:
        for i in range(5):
            logger.log({"index": i})
        records = logger.read_all()
        assert len(records) == 5

    def test_read_all_skips_malformed_lines(self, logger: AuditLogger, log_path: Path) -> None:
        logger.log({"event": "good"})
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write("not-valid-json\n")
        logger.log({"event": "also-good"})
        records = logger.read_all()
        assert len(records) == 2

    def test_read_all_skips_blank_lines(self, logger: AuditLogger, log_path: Path) -> None:
        logger.log({"event": "good"})
        with log_path.open("a", encoding="utf-8") as fh:
            fh.write("\n\n")
        records = logger.read_all()
        assert len(records) == 1


# ---------------------------------------------------------------------------
# query
# ---------------------------------------------------------------------------


class TestQuery:
    def test_query_matching_single_field(self, logger: AuditLogger) -> None:
        logger.log({"event": "file_read", "agent": "analyst"})
        logger.log({"event": "file_write", "agent": "analyst"})
        results = logger.query({"event": "file_read"})
        assert len(results) == 1
        assert results[0]["event"] == "file_read"

    def test_query_and_semantics(self, logger: AuditLogger) -> None:
        logger.log({"event": "policy_block", "agent": "analyst"})
        logger.log({"event": "policy_block", "agent": "bot"})
        results = logger.query({"event": "policy_block", "agent": "analyst"})
        assert len(results) == 1

    def test_query_no_match_returns_empty(self, logger: AuditLogger) -> None:
        logger.log({"event": "file_read"})
        results = logger.query({"event": "nonexistent"})
        assert results == []

    def test_query_empty_filters_returns_all(self, logger: AuditLogger) -> None:
        logger.log({"event": "a"})
        logger.log({"event": "b"})
        results = logger.query({})
        assert len(results) == 2


# ---------------------------------------------------------------------------
# count
# ---------------------------------------------------------------------------


class TestCount:
    def test_count_zero_when_empty(self, log_path: Path) -> None:
        audit = AuditLogger(log_path)
        assert audit.count() == 0

    def test_count_after_writes(self, logger: AuditLogger) -> None:
        for _ in range(4):
            logger.log({"event": "x"})
        assert logger.count() == 4


# ---------------------------------------------------------------------------
# last_n
# ---------------------------------------------------------------------------


class TestLastN:
    def test_last_n_fewer_than_total(self, logger: AuditLogger) -> None:
        for i in range(5):
            logger.log({"index": i})
        results = logger.last_n(3)
        assert len(results) == 3
        assert results[-1]["index"] == 4

    def test_last_n_more_than_total_returns_all(self, logger: AuditLogger) -> None:
        for i in range(3):
            logger.log({"index": i})
        results = logger.last_n(10)
        assert len(results) == 3

    def test_last_1_returns_most_recent(self, logger: AuditLogger) -> None:
        logger.log({"seq": "first"})
        logger.log({"seq": "second"})
        results = logger.last_n(1)
        assert results[0]["seq"] == "second"
