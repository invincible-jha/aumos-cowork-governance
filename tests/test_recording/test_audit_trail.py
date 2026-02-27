"""Tests for aumos_cowork_governance.recording.audit_trail."""
from __future__ import annotations

import datetime
import json

import pytest

from aumos_cowork_governance.recording.audit_trail import (
    AuditEntry,
    SessionRecorder,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def recorder() -> SessionRecorder:
    return SessionRecorder(session_id="sess-test", user_id="user-1")


@pytest.fixture()
def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


# ---------------------------------------------------------------------------
# AuditEntry
# ---------------------------------------------------------------------------


class TestAuditEntry:
    def test_entry_is_frozen(self) -> None:
        ts = datetime.datetime.now(datetime.timezone.utc)
        entry = AuditEntry(
            entry_id="e-001",
            timestamp=ts,
            action_type="click",
            target="#btn",
            result="success",
            session_id="s-1",
            user_id="u-1",
            metadata={},
        )
        with pytest.raises((AttributeError, TypeError)):
            entry.action_type = "other"  # type: ignore[misc]

    def test_to_dict_roundtrip(self) -> None:
        ts = datetime.datetime.now(datetime.timezone.utc)
        entry = AuditEntry(
            entry_id="e-001",
            timestamp=ts,
            action_type="click",
            target="#btn",
            result="success",
            session_id="s-1",
            user_id="u-1",
            metadata={"x": 10},
        )
        data = entry.to_dict()
        assert data["entry_id"] == "e-001"
        assert data["action_type"] == "click"
        assert data["target"] == "#btn"
        assert data["result"] == "success"
        assert data["session_id"] == "s-1"
        assert data["user_id"] == "u-1"
        assert data["metadata"] == {"x": 10}
        assert isinstance(data["timestamp"], str)

    def test_to_jsonl_ends_with_newline(self) -> None:
        ts = datetime.datetime.now(datetime.timezone.utc)
        entry = AuditEntry(
            entry_id="e-001",
            timestamp=ts,
            action_type="type",
            target="#field",
            result="success",
            session_id="s-1",
            user_id="u-1",
            metadata={},
        )
        jsonl = entry.to_jsonl()
        assert jsonl.endswith("\n")

    def test_to_jsonl_is_valid_json(self) -> None:
        ts = datetime.datetime.now(datetime.timezone.utc)
        entry = AuditEntry(
            entry_id="e-001",
            timestamp=ts,
            action_type="navigate",
            target="https://example.com",
            result="success",
            session_id="s-1",
            user_id="u-1",
            metadata={"status_code": 200},
        )
        jsonl = entry.to_jsonl()
        parsed = json.loads(jsonl.strip())
        assert parsed["action_type"] == "navigate"
        assert parsed["metadata"]["status_code"] == 200

    def test_from_dict_reconstructs_entry(self) -> None:
        ts = datetime.datetime.now(datetime.timezone.utc)
        original = AuditEntry(
            entry_id="e-002",
            timestamp=ts,
            action_type="click",
            target="#submit",
            result="failure",
            session_id="s-2",
            user_id="u-2",
            metadata={"error": "timeout"},
        )
        data = original.to_dict()
        reconstructed = AuditEntry.from_dict(data)
        assert reconstructed.entry_id == original.entry_id
        assert reconstructed.action_type == original.action_type
        assert reconstructed.result == original.result
        assert reconstructed.metadata == original.metadata

    def test_from_dict_parses_iso_timestamp(self) -> None:
        data = {
            "entry_id": "e-003",
            "timestamp": "2024-01-15T10:30:00+00:00",
            "action_type": "type",
            "target": "#field",
            "result": "success",
            "session_id": "s-1",
            "user_id": "u-1",
            "metadata": {},
        }
        entry = AuditEntry.from_dict(data)
        assert entry.timestamp.year == 2024
        assert entry.timestamp.month == 1
        assert entry.timestamp.day == 15

    def test_from_dict_missing_metadata_defaults_to_empty(self) -> None:
        ts = datetime.datetime.now(datetime.timezone.utc)
        data = {
            "entry_id": "e-004",
            "timestamp": ts.isoformat(),
            "action_type": "click",
            "target": "#x",
            "result": "success",
            "session_id": "s-1",
            "user_id": "u-1",
        }
        entry = AuditEntry.from_dict(data)
        assert entry.metadata == {}


# ---------------------------------------------------------------------------
# SessionRecorder — recording
# ---------------------------------------------------------------------------


class TestSessionRecorderRecording:
    def test_record_returns_audit_entry(self, recorder: SessionRecorder) -> None:
        entry = recorder.record("click", target="#btn")
        assert isinstance(entry, AuditEntry)

    def test_record_increments_counter(self, recorder: SessionRecorder) -> None:
        recorder.record("click")
        recorder.record("type")
        assert recorder.entry_count() == 2

    def test_entry_id_format(self, recorder: SessionRecorder) -> None:
        entry = recorder.record("click")
        assert entry.entry_id == "sess-test-000001"

    def test_entry_id_sequential(self, recorder: SessionRecorder) -> None:
        e1 = recorder.record("click")
        e2 = recorder.record("type")
        assert e1.entry_id == "sess-test-000001"
        assert e2.entry_id == "sess-test-000002"

    def test_record_default_result_success(self, recorder: SessionRecorder) -> None:
        entry = recorder.record("click")
        assert entry.result == "success"

    def test_record_custom_result(self, recorder: SessionRecorder) -> None:
        entry = recorder.record("click", result="failure")
        assert entry.result == "failure"

    def test_record_metadata_deep_copied(self, recorder: SessionRecorder) -> None:
        meta = {"chars": 5}
        entry = recorder.record("type", metadata=meta)
        meta["chars"] = 99
        assert entry.metadata["chars"] == 5

    def test_record_session_and_user_ids(self, recorder: SessionRecorder) -> None:
        entry = recorder.record("click")
        assert entry.session_id == "sess-test"
        assert entry.user_id == "user-1"

    def test_record_custom_timestamp(self, recorder: SessionRecorder) -> None:
        ts = datetime.datetime(2024, 6, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        entry = recorder.record("click", timestamp=ts)
        assert entry.timestamp == ts

    def test_record_auto_utc_timestamp(self, recorder: SessionRecorder) -> None:
        entry = recorder.record("click")
        assert entry.timestamp.tzinfo is not None


# ---------------------------------------------------------------------------
# SessionRecorder — querying
# ---------------------------------------------------------------------------


class TestSessionRecorderQuery:
    def test_get_all_returns_all_entries(self, recorder: SessionRecorder) -> None:
        recorder.record("click")
        recorder.record("type")
        recorder.record("navigate")
        all_entries = recorder.get_all()
        assert len(all_entries) == 3

    def test_get_all_returns_copy(self, recorder: SessionRecorder) -> None:
        recorder.record("click")
        entries = recorder.get_all()
        entries.clear()
        assert recorder.entry_count() == 1

    def test_query_by_action_type(self, recorder: SessionRecorder) -> None:
        recorder.record("click")
        recorder.record("type")
        recorder.record("click")
        clicks = recorder.query_by_action_type("click")
        assert len(clicks) == 2
        assert all(e.action_type == "click" for e in clicks)

    def test_query_by_action_type_no_match(self, recorder: SessionRecorder) -> None:
        recorder.record("click")
        result = recorder.query_by_action_type("navigate")
        assert result == []

    def test_query_by_result(self, recorder: SessionRecorder) -> None:
        recorder.record("click", result="success")
        recorder.record("click", result="failure")
        recorder.record("type", result="success")
        failures = recorder.query_by_result("failure")
        assert len(failures) == 1
        assert failures[0].result == "failure"

    def test_query_by_time_range(self, recorder: SessionRecorder) -> None:
        t1 = datetime.datetime(2024, 1, 1, 10, 0, 0, tzinfo=datetime.timezone.utc)
        t2 = datetime.datetime(2024, 1, 1, 11, 0, 0, tzinfo=datetime.timezone.utc)
        t3 = datetime.datetime(2024, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        recorder.record("a", timestamp=t1)
        recorder.record("b", timestamp=t2)
        recorder.record("c", timestamp=t3)

        start = datetime.datetime(2024, 1, 1, 10, 30, 0, tzinfo=datetime.timezone.utc)
        end = datetime.datetime(2024, 1, 1, 11, 30, 0, tzinfo=datetime.timezone.utc)
        results = recorder.query_by_time_range(start, end)
        assert len(results) == 1
        assert results[0].action_type == "b"

    def test_query_by_time_range_inclusive(self, recorder: SessionRecorder) -> None:
        t1 = datetime.datetime(2024, 1, 1, 10, 0, 0, tzinfo=datetime.timezone.utc)
        t2 = datetime.datetime(2024, 1, 1, 11, 0, 0, tzinfo=datetime.timezone.utc)
        recorder.record("a", timestamp=t1)
        recorder.record("b", timestamp=t2)
        results = recorder.query_by_time_range(t1, t2)
        assert len(results) == 2

    def test_query_by_time_range_naive_datetimes(self, recorder: SessionRecorder) -> None:
        t1 = datetime.datetime(2024, 1, 1, 10, 0, 0, tzinfo=datetime.timezone.utc)
        recorder.record("a", timestamp=t1)
        # Naive datetimes should be normalised to UTC
        start = datetime.datetime(2024, 1, 1, 9, 0, 0)
        end = datetime.datetime(2024, 1, 1, 11, 0, 0)
        results = recorder.query_by_time_range(start, end)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# SessionRecorder — export / import
# ---------------------------------------------------------------------------


class TestSessionRecorderExport:
    def test_export_jsonl_one_line_per_entry(self, recorder: SessionRecorder) -> None:
        recorder.record("click")
        recorder.record("type")
        jsonl = recorder.export_jsonl()
        lines = [ln for ln in jsonl.splitlines() if ln.strip()]
        assert len(lines) == 2

    def test_export_jsonl_each_line_valid_json(self, recorder: SessionRecorder) -> None:
        recorder.record("click")
        recorder.record("navigate")
        jsonl = recorder.export_jsonl()
        for line in jsonl.splitlines():
            if line.strip():
                parsed = json.loads(line)
                assert "entry_id" in parsed

    def test_from_jsonl_reconstructs_entries(self, recorder: SessionRecorder) -> None:
        recorder.record("click", target="#btn", result="success")
        recorder.record("type", target="#field", result="success", metadata={"chars": 5})
        jsonl = recorder.export_jsonl()

        new_recorder = SessionRecorder.from_jsonl(jsonl, session_id="sess-test", user_id="user-1")
        assert new_recorder.entry_count() == 2

    def test_from_jsonl_preserves_action_types(self, recorder: SessionRecorder) -> None:
        recorder.record("click")
        recorder.record("navigate")
        jsonl = recorder.export_jsonl()

        restored = SessionRecorder.from_jsonl(jsonl, session_id="sess-test")
        types = [e.action_type for e in restored.get_all()]
        assert types == ["click", "navigate"]

    def test_from_jsonl_skips_malformed_lines(self) -> None:
        bad_jsonl = "not-valid-json\n{\"entry_id\":\"x\"}\n"
        recorder = SessionRecorder.from_jsonl(bad_jsonl, session_id="sess-test")
        # Both lines are skipped (first is bad JSON, second is missing required keys)
        assert recorder.entry_count() == 0

    def test_from_jsonl_empty_string(self) -> None:
        recorder = SessionRecorder.from_jsonl("", session_id="sess-test")
        assert recorder.entry_count() == 0

    def test_export_summary_structure(self, recorder: SessionRecorder) -> None:
        recorder.record("click", result="success")
        recorder.record("type", result="success")
        recorder.record("click", result="failure")
        summary = recorder.export_summary()
        assert summary["session_id"] == "sess-test"
        assert summary["total_entries"] == 3
        assert summary["action_counts"]["click"] == 2
        assert summary["action_counts"]["type"] == 1
        assert summary["result_counts"]["success"] == 2
        assert summary["result_counts"]["failure"] == 1

    def test_export_summary_empty_recorder(self, recorder: SessionRecorder) -> None:
        summary = recorder.export_summary()
        assert summary["total_entries"] == 0
        assert summary["action_counts"] == {}
        assert summary["result_counts"] == {}
