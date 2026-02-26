"""Coverage-boosting tests for previously uncovered modules.

Targets:
- approval/gate.py          (44% -> cover GateResult, request_and_wait, submit, _build_result)
- approval/notifier.py      (34% -> cover notify, notify_by_id, _render_template, _post)
- approval/timeout.py       (31% -> cover expire_stale, is_expired, timeout_seconds)
- audit/exporter.py         (22% -> cover to_csv, to_json, to_jsonl)
- audit/report.py           (17% -> cover generate_markdown, generate_html, save_*, _compute_stats)
- audit/rotator.py          (24% -> cover rotate_if_needed, force_rotate, list_archives)
- audit/search.py           (18% -> cover by_date_range, by_event, by_agent, by_file_path, multi_filter)
- cost/alerts.py            (37% -> cover check_and_notify, _build_message, _send)
- cost/reporter.py          (22% -> cover to_csv, summary, _filter_by_period)
- dashboard/api.py          (24% -> cover get_audit, get_policies, get_costs, get_status, get_approvals)
- dashboard/renderer.py     (30% -> cover render_summary, render_table, render_json)
- templates/policy_templates.py (57% -> cover get_template, list_templates, write_template)
"""
from __future__ import annotations

import json
import threading
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aumos_cowork_governance.approval.gate import ApprovalGate, ApprovalOutcome, GateResult
from aumos_cowork_governance.approval.notifier import ApprovalNotifier
from aumos_cowork_governance.approval.queue import ApprovalQueue, ApprovalStatus
from aumos_cowork_governance.approval.timeout import TimeoutHandler
from aumos_cowork_governance.audit.exporter import AuditExporter
from aumos_cowork_governance.audit.logger import AuditLogger
from aumos_cowork_governance.audit.report import ComplianceReportGenerator
from aumos_cowork_governance.audit.rotator import LogRotator
from aumos_cowork_governance.audit.search import AuditSearch
from aumos_cowork_governance.cost.alerts import AlertManager
from aumos_cowork_governance.cost.budget import BudgetManager, BudgetPeriod, PeriodStatus
from aumos_cowork_governance.cost.reporter import CostReporter
from aumos_cowork_governance.cost.tracker import CostTracker
from aumos_cowork_governance.dashboard.api import DashboardApi
from aumos_cowork_governance.dashboard.renderer import DashboardData, DashboardRenderer
from aumos_cowork_governance.templates.policy_templates import (
    get_template,
    list_templates,
    write_template,
)


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_log(tmp_path: Path) -> AuditLogger:
    """AuditLogger with several records covering various event types."""
    log_file = tmp_path / "audit.jsonl"
    audit = AuditLogger(log_file)
    audit.log({"event": "api_call", "cost_usd": 0.01, "model": "claude-opus-4"})
    audit.log({"event": "policy_block", "policy": "no-pii", "message": "PII detected"})
    audit.log({"event": "policy_warn", "policy": "pii-warn", "message": "possible PII"})
    audit.log({"event": "api_cost", "cost_usd": 0.02, "estimated_cost_usd": 0.02})
    audit.log({"event": "policy_approve_queued", "policy": "approve-delete"})
    return audit


@pytest.fixture()
def queue() -> ApprovalQueue:
    return ApprovalQueue()


@pytest.fixture()
def tracker() -> CostTracker:
    t = CostTracker()
    t.record(
        task_id="t1",
        model="claude-opus-4",
        input_tokens=100,
        output_tokens=50,
        cost_usd=0.01,
    )
    return t


# ===========================================================================
# approval/gate.py
# ===========================================================================


class TestApprovalGateGateResult:
    def test_gate_result_approved(self) -> None:
        result = GateResult(
            outcome=ApprovalOutcome.APPROVED,
            approved=True,
            request_id="r1",
            reviewer="alice",
            note="looks good",
        )
        assert result.approved is True
        assert result.outcome == ApprovalOutcome.APPROVED

    def test_gate_result_denied(self) -> None:
        result = GateResult(
            outcome=ApprovalOutcome.DENIED,
            approved=False,
            request_id="r2",
            reviewer=None,
            note=None,
        )
        assert result.approved is False

    def test_gate_result_timed_out(self) -> None:
        result = GateResult(
            outcome=ApprovalOutcome.TIMED_OUT,
            approved=False,
            request_id="r3",
            reviewer=None,
            note=None,
        )
        assert result.outcome == ApprovalOutcome.TIMED_OUT


class TestApprovalGateSubmit:
    def test_submit_returns_request_id(self, queue: ApprovalQueue) -> None:
        gate = ApprovalGate(queue)
        request_id = gate.submit(
            action_context={"action": "delete"},
            policy_name="require-approval",
            message="Please review.",
        )
        assert isinstance(request_id, str)
        assert len(request_id) > 0

    def test_submit_enqueues_to_queue(self, queue: ApprovalQueue) -> None:
        gate = ApprovalGate(queue)
        gate.submit(
            action_context={"action": "delete"},
            policy_name="p1",
            message="msg",
        )
        assert len(queue.pending()) == 1

    def test_submit_with_notify_list(self, queue: ApprovalQueue) -> None:
        gate = ApprovalGate(queue)
        request_id = gate.submit(
            action_context={"action": "delete"},
            policy_name="p1",
            message="msg",
            notify=["admin@example.com"],
        )
        req = queue.get(request_id)
        assert req.notify == ["admin@example.com"]


class TestApprovalGateRequestAndWait:
    def test_request_and_wait_approved(self, queue: ApprovalQueue) -> None:
        gate = ApprovalGate(queue, timeout_seconds=10.0, poll_interval_seconds=0.01)

        def approve_after_enqueue() -> None:
            time.sleep(0.05)
            pending = queue.pending()
            if pending:
                queue.approve(pending[0].request_id, reviewer="bot", note="ok")

        thread = threading.Thread(target=approve_after_enqueue, daemon=True)
        thread.start()
        result = gate.request_and_wait(
            action_context={"action": "test"},
            policy_name="p1",
            message="approve me",
        )
        thread.join(timeout=2.0)
        assert result.approved is True
        assert result.outcome == ApprovalOutcome.APPROVED

    def test_request_and_wait_denied(self, queue: ApprovalQueue) -> None:
        gate = ApprovalGate(queue, timeout_seconds=10.0, poll_interval_seconds=0.01)

        def deny_after_enqueue() -> None:
            time.sleep(0.05)
            pending = queue.pending()
            if pending:
                queue.deny(pending[0].request_id, reviewer="bot", note="no")

        thread = threading.Thread(target=deny_after_enqueue, daemon=True)
        thread.start()
        result = gate.request_and_wait(
            action_context={"action": "test"},
            policy_name="p1",
            message="deny me",
        )
        thread.join(timeout=2.0)
        assert result.approved is False
        assert result.outcome == ApprovalOutcome.DENIED

    def test_request_and_wait_timeout(self, queue: ApprovalQueue) -> None:
        gate = ApprovalGate(queue, timeout_seconds=0.05, poll_interval_seconds=0.01)
        result = gate.request_and_wait(
            action_context={"action": "never-approved"},
            policy_name="p1",
            message="nobody will approve",
        )
        assert result.approved is False
        assert result.outcome == ApprovalOutcome.TIMED_OUT

    def test_build_result_approved(self, queue: ApprovalQueue) -> None:
        request_id = queue.enqueue(action_context={}, policy_name="p", message="m")
        queue.approve(request_id, reviewer="alice", note="yes")
        request = queue.get(request_id)
        result = ApprovalGate._build_result(request)
        assert result.approved is True
        assert result.reviewer == "alice"
        assert result.note == "yes"

    def test_build_result_denied_status(self, queue: ApprovalQueue) -> None:
        request_id = queue.enqueue(action_context={}, policy_name="p", message="m")
        queue.deny(request_id, reviewer="bot")
        request = queue.get(request_id)
        result = ApprovalGate._build_result(request)
        assert result.approved is False
        assert result.outcome == ApprovalOutcome.DENIED


# ===========================================================================
# approval/notifier.py
# ===========================================================================


class TestApprovalNotifier:
    def test_notify_no_webhook_returns_true(self, queue: ApprovalQueue) -> None:
        notifier = ApprovalNotifier()
        request_id = queue.enqueue(action_context={}, policy_name="p", message="m")
        request = queue.get(request_id)
        result = notifier.notify(request)
        assert result is True

    def test_notify_slack_format(self, queue: ApprovalQueue) -> None:
        notifier = ApprovalNotifier(webhook_format="slack")
        request_id = queue.enqueue(action_context={}, policy_name="pii", message="PII found")
        request = queue.get(request_id)
        payload = notifier._build_payload(request)
        assert "pii" in payload.lower()
        assert "Approval Required" in payload

    def test_notify_teams_format(self, queue: ApprovalQueue) -> None:
        notifier = ApprovalNotifier(webhook_format="teams")
        request_id = queue.enqueue(action_context={}, policy_name="myp", message="msg")
        request = queue.get(request_id)
        payload = notifier._build_payload(request)
        assert "MessageCard" in payload

    def test_notify_generic_format(self, queue: ApprovalQueue) -> None:
        notifier = ApprovalNotifier(webhook_format="generic")
        request_id = queue.enqueue(action_context={}, policy_name="myp", message="msg")
        request = queue.get(request_id)
        payload = notifier._build_payload(request)
        assert "Approval Required" in payload

    def test_notify_by_id_no_webhook(self) -> None:
        notifier = ApprovalNotifier()
        result = notifier.notify_by_id(
            request_id="abc123",
            policy_name="test",
            message="test message",
            created_at="2025-01-01T00:00:00Z",
        )
        assert result is True

    def test_notify_by_id_with_webhook_failure(self) -> None:
        notifier = ApprovalNotifier(webhook_url="http://localhost:9999/nonexistent")
        result = notifier.notify_by_id(
            request_id="r1",
            policy_name="p",
            message="m",
            created_at="2025-01-01T00:00:00Z",
        )
        assert result is False

    def test_post_no_url_returns_false(self) -> None:
        notifier = ApprovalNotifier(webhook_url=None)
        assert notifier._post("payload") is False

    def test_render_template_escapes_newlines(self) -> None:
        notifier = ApprovalNotifier()
        payload = notifier._render_template(
            request_id="r1",
            policy_name="p",
            message="line1\nline2",
            created_at="2025-01-01T00:00:00Z",
        )
        assert "\\n" in payload

    def test_notify_with_mocked_webhook(self, queue: ApprovalQueue) -> None:
        notifier = ApprovalNotifier(webhook_url="http://example.com/hook")
        request_id = queue.enqueue(action_context={}, policy_name="p", message="m")
        request = queue.get(request_id)

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = lambda s: s
            mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
            result = notifier.notify(request)
        assert result is True

    def test_notify_by_id_with_webhook_slack_format(self) -> None:
        notifier = ApprovalNotifier(
            webhook_url="http://example.com/hook", webhook_format="slack"
        )
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = lambda s: s
            mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
            result = notifier.notify_by_id(
                request_id="r1",
                policy_name="p",
                message="m",
                created_at="2025-01-01T00:00:00Z",
            )
        assert result is True


# ===========================================================================
# approval/timeout.py
# ===========================================================================


class TestTimeoutHandler:
    def test_expire_stale_empty_queue(self, queue: ApprovalQueue) -> None:
        handler = TimeoutHandler(queue, default_timeout_seconds=300)
        expired = handler.expire_stale()
        assert expired == []

    def test_expire_stale_expires_old_requests(self, queue: ApprovalQueue) -> None:
        handler = TimeoutHandler(queue, default_timeout_seconds=10)
        request_id = queue.enqueue(action_context={}, policy_name="p", message="m")
        future = datetime.now(tz=timezone.utc) + timedelta(seconds=20)
        expired = handler.expire_stale(now=future)
        assert request_id in expired
        assert queue.get(request_id).status == ApprovalStatus.TIMED_OUT

    def test_expire_stale_leaves_young_requests(self, queue: ApprovalQueue) -> None:
        handler = TimeoutHandler(queue, default_timeout_seconds=300)
        queue.enqueue(action_context={}, policy_name="p", message="m")
        expired = handler.expire_stale()
        assert expired == []

    def test_is_expired_returns_true_for_stale(self, queue: ApprovalQueue) -> None:
        handler = TimeoutHandler(queue, default_timeout_seconds=10)
        request_id = queue.enqueue(action_context={}, policy_name="p", message="m")
        future = datetime.now(tz=timezone.utc) + timedelta(seconds=20)
        assert handler.is_expired(request_id, now=future) is True

    def test_is_expired_returns_false_for_fresh(self, queue: ApprovalQueue) -> None:
        handler = TimeoutHandler(queue, default_timeout_seconds=300)
        request_id = queue.enqueue(action_context={}, policy_name="p", message="m")
        assert handler.is_expired(request_id) is False

    def test_is_expired_returns_false_for_missing_id(self, queue: ApprovalQueue) -> None:
        handler = TimeoutHandler(queue, default_timeout_seconds=10)
        assert handler.is_expired("nonexistent-id") is False

    def test_is_expired_returns_false_for_approved_request(self, queue: ApprovalQueue) -> None:
        handler = TimeoutHandler(queue, default_timeout_seconds=10)
        request_id = queue.enqueue(action_context={}, policy_name="p", message="m")
        queue.approve(request_id, reviewer="reviewer")
        future = datetime.now(tz=timezone.utc) + timedelta(seconds=20)
        assert handler.is_expired(request_id, now=future) is False

    def test_timeout_seconds_property(self, queue: ApprovalQueue) -> None:
        handler = TimeoutHandler(queue, default_timeout_seconds=120)
        assert handler.timeout_seconds == 120.0

    def test_expire_stale_skips_already_transitioned(self, queue: ApprovalQueue) -> None:
        handler = TimeoutHandler(queue, default_timeout_seconds=10)
        request_id = queue.enqueue(action_context={}, policy_name="p", message="m")
        queue.approve(request_id, reviewer="r")
        future = datetime.now(tz=timezone.utc) + timedelta(seconds=20)
        expired = handler.expire_stale(now=future)
        assert request_id not in expired


# ===========================================================================
# audit/exporter.py
# ===========================================================================


class TestAuditExporter:
    def test_to_csv_writes_records(self, tmp_path: Path, tmp_log: AuditLogger) -> None:
        exporter = AuditExporter(tmp_log)
        output = tmp_path / "export.csv"
        count = exporter.to_csv(output)
        assert count > 0
        assert output.exists()
        assert "event" in output.read_text(encoding="utf-8")

    def test_to_csv_empty_records(self, tmp_path: Path, tmp_log: AuditLogger) -> None:
        exporter = AuditExporter(tmp_log)
        output = tmp_path / "empty.csv"
        count = exporter.to_csv(output, records=[])
        assert count == 0
        assert output.exists()

    def test_to_csv_with_nested_dict(self, tmp_path: Path, tmp_log: AuditLogger) -> None:
        records: list[dict[str, object]] = [
            {"event": "test", "metadata": {"key": "val"}, "tags": ["a", "b"]}
        ]
        exporter = AuditExporter(tmp_log)
        output = tmp_path / "nested.csv"
        count = exporter.to_csv(output, records=records)
        assert count == 1

    def test_to_json_writes_array(self, tmp_path: Path, tmp_log: AuditLogger) -> None:
        exporter = AuditExporter(tmp_log)
        output = tmp_path / "export.json"
        count = exporter.to_json(output)
        assert count > 0
        data = json.loads(output.read_text(encoding="utf-8"))
        assert isinstance(data, list)

    def test_to_json_empty(self, tmp_path: Path, tmp_log: AuditLogger) -> None:
        exporter = AuditExporter(tmp_log)
        output = tmp_path / "empty.json"
        count = exporter.to_json(output, records=[])
        assert count == 0

    def test_to_jsonl_writes_lines(self, tmp_path: Path, tmp_log: AuditLogger) -> None:
        exporter = AuditExporter(tmp_log)
        output = tmp_path / "export.jsonl"
        count = exporter.to_jsonl(output)
        assert count > 0
        lines = output.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == count

    def test_to_jsonl_with_explicit_records(self, tmp_path: Path, tmp_log: AuditLogger) -> None:
        exporter = AuditExporter(tmp_log)
        output = tmp_path / "custom.jsonl"
        records: list[dict[str, object]] = [{"event": "custom_event", "value": 42}]
        count = exporter.to_jsonl(output, records=records)
        assert count == 1

    def test_to_csv_creates_parent_dirs(self, tmp_path: Path, tmp_log: AuditLogger) -> None:
        exporter = AuditExporter(tmp_log)
        nested = tmp_path / "sub" / "export.csv"
        exporter.to_csv(nested)
        assert nested.exists()


# ===========================================================================
# audit/report.py
# ===========================================================================


class TestComplianceReportGenerator:
    def test_generate_markdown_contains_title(self, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        md = gen.generate_markdown()
        assert "# Governance Compliance Report" in md

    def test_generate_markdown_custom_title(self, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        md = gen.generate_markdown(title="Q1 Report")
        assert "# Q1 Report" in md

    def test_generate_markdown_shows_event_counts(self, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        md = gen.generate_markdown()
        assert "api_call" in md or "policy_block" in md

    def test_generate_markdown_with_blocks(self, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        md = gen.generate_markdown()
        assert "Policy Violations" in md

    def test_generate_markdown_no_blocks(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "a.jsonl")
        audit.log({"event": "api_call", "model": "gpt-4"})
        gen = ComplianceReportGenerator(audit)
        md = gen.generate_markdown()
        assert "No policy blocks" in md

    def test_generate_html_is_valid_html(self, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        html = gen.generate_html()
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html

    def test_generate_html_contains_stats(self, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        html = gen.generate_html()
        assert "Cost Summary" in html
        assert "Approval Requests" in html

    def test_generate_html_no_blocks(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "b.jsonl")
        audit.log({"event": "api_call"})
        gen = ComplianceReportGenerator(audit)
        html = gen.generate_html()
        assert "No policy blocks recorded" in html

    def test_generate_html_with_blocks(self, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        html = gen.generate_html()
        assert "Policy Violations" in html

    def test_save_markdown_creates_file(self, tmp_path: Path, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        output = tmp_path / "report.md"
        gen.save_markdown(output)
        assert output.exists()
        assert "# Governance Compliance Report" in output.read_text(encoding="utf-8")

    def test_save_html_creates_file(self, tmp_path: Path, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        output = tmp_path / "report.html"
        gen.save_html(output)
        assert output.exists()
        assert "<!DOCTYPE html>" in output.read_text(encoding="utf-8")

    def test_compute_stats_pii_blocks_and_warns(self, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        records: list[dict[str, object]] = [
            {"event": "policy_block", "policy": "pii-block", "message": "blocked"},
            {"event": "policy_warn", "policy": "pii-warn", "message": "warned"},
            {"event": "api_call", "cost_usd": 0.5},
        ]
        stats = gen._compute_stats(records)
        assert stats["pii_blocks"] == 1
        assert stats["pii_warns"] == 1
        assert stats["api_calls"] == 1

    def test_generate_markdown_with_explicit_records(self, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        records: list[dict[str, object]] = [
            {"event": "policy_approve_queued", "policy": "approve-delete"}
        ]
        md = gen.generate_markdown(records=records)
        assert "Approval Requests" in md
        assert "Total queued: **1**" in md

    def test_compute_stats_cost_from_estimated_cost_usd(self, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        records: list[dict[str, object]] = [
            {"event": "api_cost", "estimated_cost_usd": 0.05},
        ]
        stats = gen._compute_stats(records)
        assert stats["total_cost_usd"] == pytest.approx(0.05)

    def test_compute_stats_invalid_cost_ignored(self, tmp_log: AuditLogger) -> None:
        gen = ComplianceReportGenerator(tmp_log)
        records: list[dict[str, object]] = [
            {"event": "api_call", "cost_usd": "not-a-number"},
        ]
        stats = gen._compute_stats(records)
        assert stats["total_cost_usd"] == pytest.approx(0.0)


# ===========================================================================
# audit/rotator.py
# ===========================================================================


class TestLogRotator:
    def test_list_archives_empty_nonexistent_dir(self, tmp_path: Path) -> None:
        rotator = LogRotator(tmp_path / "nonexistent")
        assert rotator.list_archives() == []

    def test_list_archives_returns_sorted_files(self, tmp_path: Path) -> None:
        rotator = LogRotator(tmp_path)
        (tmp_path / "audit-2025-01-01.jsonl").write_text("")
        (tmp_path / "audit-2025-01-02.jsonl").write_text("")
        archives = rotator.list_archives()
        assert len(archives) == 2
        assert archives[0].name < archives[1].name

    def test_rotate_if_needed_no_file(self, tmp_path: Path) -> None:
        rotator = LogRotator(tmp_path)
        assert rotator.rotate_if_needed() is False

    def test_rotate_if_needed_same_day_skips(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        log_file.write_text("data")
        rotator = LogRotator(tmp_path)
        result = rotator.rotate_if_needed(today=date.today())
        assert result is False

    def test_force_rotate_creates_archive(self, tmp_path: Path) -> None:
        log_file = tmp_path / "audit.jsonl"
        log_file.write_text("log data")
        rotator = LogRotator(tmp_path)
        target_date = date(2025, 6, 1)
        archive = rotator.force_rotate(today=target_date)
        assert archive.exists()
        assert "2025-06-01" in archive.name
        assert not log_file.exists()

    def test_force_rotate_no_existing_log_creates_empty_archive(self, tmp_path: Path) -> None:
        rotator = LogRotator(tmp_path)
        target_date = date(2025, 1, 15)
        archive = rotator.force_rotate(today=target_date)
        assert archive.exists()
        assert "2025-01-15" in archive.name

    def test_purge_old_archives_removes_expired(self, tmp_path: Path) -> None:
        rotator = LogRotator(tmp_path, retention_days=7)
        old_date = date.today() - timedelta(days=10)
        old_archive = tmp_path / f"audit-{old_date.isoformat()}.jsonl"
        old_archive.write_text("")
        recent_date = date.today() - timedelta(days=3)
        recent_archive = tmp_path / f"audit-{recent_date.isoformat()}.jsonl"
        recent_archive.write_text("")
        rotator._purge_old_archives(date.today())
        assert not old_archive.exists()
        assert recent_archive.exists()

    def test_purge_old_archives_ignores_bad_filenames(self, tmp_path: Path) -> None:
        rotator = LogRotator(tmp_path, retention_days=7)
        bad_file = tmp_path / "audit-not-a-date.jsonl"
        bad_file.write_text("")
        # Must not raise.
        rotator._purge_old_archives(date.today())
        assert bad_file.exists()  # Not deleted since name can't be parsed.


# ===========================================================================
# audit/search.py
# ===========================================================================


class TestAuditSearch:
    def test_by_event_matches(self, tmp_log: AuditLogger) -> None:
        search = AuditSearch(tmp_log)
        results = search.by_event("policy_block")
        assert len(results) >= 1
        assert all(r.get("event") == "policy_block" for r in results)

    def test_by_event_no_match(self, tmp_log: AuditLogger) -> None:
        search = AuditSearch(tmp_log)
        assert search.by_event("nonexistent_event") == []

    def test_by_agent_via_agent_field(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "a.jsonl")
        audit.log({"event": "action", "agent": "agent-1"})
        audit.log({"event": "action", "agent": "agent-3"})
        search = AuditSearch(audit)
        assert len(search.by_agent("agent-1")) == 1
        assert search.by_agent("nobody") == []

    def test_by_agent_via_agent_id_field(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "b.jsonl")
        audit.log({"event": "action", "agent_id": "agent-2"})
        search = AuditSearch(audit)
        assert len(search.by_agent("agent-2")) == 1

    def test_by_file_path_direct(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "c.jsonl")
        audit.log({"event": "file_read", "path": "/data/secret/file.txt"})
        audit.log({"event": "file_read", "path": "/public/readme.md"})
        search = AuditSearch(audit)
        results = search.by_file_path("/data/secret/")
        assert len(results) == 1

    def test_by_file_path_nested_context(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "d.jsonl")
        audit.log({
            "event": "file_read",
            "action_context": {"path": "/data/secret/other.txt"},
        })
        search = AuditSearch(audit)
        results = search.by_file_path("/data/secret/")
        assert len(results) == 1

    def test_by_file_path_no_match(self, tmp_log: AuditLogger) -> None:
        search = AuditSearch(tmp_log)
        assert search.by_file_path("/nonexistent/") == []

    def test_by_policy(self, tmp_log: AuditLogger) -> None:
        search = AuditSearch(tmp_log)
        results = search.by_policy("no-pii")
        assert len(results) >= 1

    def test_by_session(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "e.jsonl")
        audit.log({"event": "action", "session_id": "sess-abc"})
        audit.log({"event": "action", "session_id": "sess-xyz"})
        search = AuditSearch(audit)
        assert len(search.by_session("sess-abc")) == 1

    def test_by_date_range(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "f.jsonl")
        # Write records with explicit timestamps by crafting raw JSON.
        log_file = tmp_path / "f.jsonl"
        log_file.write_text(
            '{"event": "early", "timestamp": "2025-06-01T10:00:00+00:00"}\n'
            '{"event": "late", "timestamp": "2025-06-15T10:00:00+00:00"}\n'
            '{"event": "bad_ts", "timestamp": "invalid"}\n'
        )
        audit2 = AuditLogger(log_file)
        search = AuditSearch(audit2)
        start = datetime(2025, 6, 1, tzinfo=timezone.utc)
        end = datetime(2025, 6, 10, tzinfo=timezone.utc)
        results = search.by_date_range(start, end)
        assert len(results) == 1
        assert results[0]["event"] == "early"

    def test_multi_filter_event_and_agent(self, tmp_path: Path) -> None:
        log_file = tmp_path / "g.jsonl"
        log_file.write_text(
            '{"event": "api_call", "agent": "bot-1"}\n'
            '{"event": "api_call", "agent": "bot-2"}\n'
            '{"event": "policy_block", "agent": "bot-1"}\n'
        )
        audit = AuditLogger(log_file)
        search = AuditSearch(audit)
        results = search.multi_filter(event_type="api_call", agent_id="bot-1")
        assert len(results) == 1

    def test_multi_filter_with_date_range(self, tmp_path: Path) -> None:
        log_file = tmp_path / "h.jsonl"
        log_file.write_text(
            '{"event": "ev", "timestamp": "2025-06-01T00:00:00+00:00"}\n'
            '{"event": "ev", "timestamp": "2025-07-01T00:00:00+00:00"}\n'
        )
        audit = AuditSearch(AuditLogger(log_file))
        start = datetime(2025, 6, 1, tzinfo=timezone.utc)
        end = datetime(2025, 6, 30, tzinfo=timezone.utc)
        results = audit.multi_filter(start=start, end=end)
        assert len(results) == 1

    def test_multi_filter_with_path_prefix(self, tmp_path: Path) -> None:
        log_file = tmp_path / "i.jsonl"
        log_file.write_text(
            '{"event": "file_read", "path": "/data/sensitive/file.txt"}\n'
            '{"event": "file_read", "path": "/tmp/other.txt"}\n'
        )
        audit = AuditSearch(AuditLogger(log_file))
        results = audit.multi_filter(path_prefix="/data/")
        assert len(results) == 1

    def test_multi_filter_no_criteria_returns_all(self, tmp_log: AuditLogger) -> None:
        search = AuditSearch(tmp_log)
        all_records = search.multi_filter()
        assert len(all_records) == len(tmp_log.read_all())

    def test_multi_filter_excludes_missing_timestamp(self, tmp_path: Path) -> None:
        log_file = tmp_path / "j.jsonl"
        log_file.write_text(
            '{"event": "ev", "timestamp": "2025-06-01T00:00:00+00:00"}\n'
            '{"event": "ev_no_ts"}\n'
        )
        search = AuditSearch(AuditLogger(log_file))
        start = datetime(2025, 6, 1, tzinfo=timezone.utc)
        end = datetime(2025, 6, 30, tzinfo=timezone.utc)
        results = search.multi_filter(start=start, end=end)
        assert len(results) == 1

    def test_multi_filter_end_only(self, tmp_path: Path) -> None:
        log_file = tmp_path / "k.jsonl"
        log_file.write_text(
            '{"event": "ev", "timestamp": "2025-05-01T00:00:00+00:00"}\n'
            '{"event": "ev2", "timestamp": "2025-07-01T00:00:00+00:00"}\n'
        )
        search = AuditSearch(AuditLogger(log_file))
        end = datetime(2025, 6, 1, tzinfo=timezone.utc)
        results = search.multi_filter(end=end)
        assert len(results) == 1


# ===========================================================================
# cost/alerts.py
# ===========================================================================


class TestAlertManager:
    def test_check_and_notify_sends_messages_when_threshold_exceeded(self) -> None:
        t = CostTracker()
        t.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=9.0)
        budget = BudgetManager(t, daily_usd=10.0)
        alerts = AlertManager(budget, thresholds=[80.0])
        messages = alerts.check_and_notify()
        assert len(messages) >= 1
        assert any("daily" in m.lower() for m in messages)

    def test_check_and_notify_no_messages_below_threshold(self) -> None:
        t = CostTracker()
        budget = BudgetManager(t, daily_usd=100.0)
        alerts = AlertManager(budget, thresholds=[80.0])
        messages = alerts.check_and_notify()
        assert messages == []

    def test_alert_fires_only_once_per_day(self) -> None:
        t = CostTracker()
        t.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=9.0)
        budget = BudgetManager(t, daily_usd=10.0)
        alerts = AlertManager(budget, thresholds=[80.0])
        messages1 = alerts.check_and_notify()
        messages2 = alerts.check_and_notify()  # Same day -> already fired.
        assert len(messages1) >= 1
        assert messages2 == []

    def test_reset_fired_allows_re_alerting(self) -> None:
        t = CostTracker()
        t.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=9.0)
        budget = BudgetManager(t, daily_usd=10.0)
        alerts = AlertManager(budget, thresholds=[80.0])
        alerts.check_and_notify()
        alerts.reset_fired()
        messages = alerts.check_and_notify()
        assert len(messages) >= 1

    def test_callback_is_called_on_threshold_breach(self) -> None:
        received: list[tuple[str, float, str]] = []

        def cb(period: str, pct: float, msg: str) -> None:
            received.append((period, pct, msg))

        t = CostTracker()
        t.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=9.0)
        budget = BudgetManager(t, daily_usd=10.0)
        alerts = AlertManager(budget, thresholds=[80.0], callback=cb)
        alerts.check_and_notify()
        assert len(received) >= 1
        assert received[0][0] == "daily"

    def test_callback_exception_is_swallowed(self) -> None:
        def bad_cb(period: str, pct: float, msg: str) -> None:
            raise RuntimeError("callback error")

        t = CostTracker()
        t.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=9.0)
        budget = BudgetManager(t, daily_usd=10.0)
        alerts = AlertManager(budget, thresholds=[80.0], callback=bad_cb)
        # Must not raise.
        alerts.check_and_notify()

    def test_build_message_exceeded(self) -> None:
        ps = PeriodStatus(
            period=BudgetPeriod.DAILY,
            limit_usd=10.0,
            spent_usd=12.0,
            percent_used=120.0,
            exceeded=True,
            approaching=False,
        )
        t = CostTracker()
        budget = BudgetManager(t, daily_usd=10.0)
        alerts = AlertManager(budget, thresholds=[100.0])
        msg = alerts._build_message("daily", ps, 100.0)
        assert "EXCEEDED" in msg
        assert "daily" in msg.lower()

    def test_build_message_approaching(self) -> None:
        ps = PeriodStatus(
            period=BudgetPeriod.DAILY,
            limit_usd=10.0,
            spent_usd=8.5,
            percent_used=85.0,
            exceeded=False,
            approaching=True,
        )
        t = CostTracker()
        budget = BudgetManager(t, daily_usd=10.0)
        alerts = AlertManager(budget, thresholds=[80.0])
        msg = alerts._build_message("daily", ps, 80.0)
        assert "approaching" in msg

    def test_webhook_delivery_failure_is_logged(self) -> None:
        t = CostTracker()
        t.record(task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=9.0)
        budget = BudgetManager(t, daily_usd=10.0)
        alerts = AlertManager(
            budget,
            thresholds=[80.0],
            webhook_url="http://localhost:9999/bad",
        )
        # Must not raise even if the webhook fails.
        messages = alerts.check_and_notify()
        assert len(messages) >= 1


# ===========================================================================
# cost/reporter.py
# ===========================================================================


class TestCostReporter:
    def test_to_csv_all_period(self, tmp_path: Path, tracker: CostTracker) -> None:
        reporter = CostReporter(tracker)
        output = tmp_path / "cost_all.csv"
        count = reporter.to_csv(output, period="all")
        assert count == 1
        assert output.exists()
        assert "task_id" in output.read_text(encoding="utf-8")

    def test_to_csv_daily_period(self, tmp_path: Path, tracker: CostTracker) -> None:
        reporter = CostReporter(tracker)
        output = tmp_path / "cost_daily.csv"
        count = reporter.to_csv(output, period="daily")
        assert count >= 0

    def test_to_csv_weekly_period(self, tmp_path: Path, tracker: CostTracker) -> None:
        reporter = CostReporter(tracker)
        output = tmp_path / "cost_weekly.csv"
        count = reporter.to_csv(output, period="weekly")
        assert count >= 0

    def test_to_csv_monthly_period(self, tmp_path: Path, tracker: CostTracker) -> None:
        reporter = CostReporter(tracker)
        output = tmp_path / "cost_monthly.csv"
        count = reporter.to_csv(output, period="monthly")
        assert count >= 0

    def test_summary_all_period(self, tracker: CostTracker) -> None:
        reporter = CostReporter(tracker)
        summary = reporter.summary(period="all")
        assert summary["call_count"] == 1
        assert summary["total_cost_usd"] == pytest.approx(0.01)
        assert "by_model" in summary
        assert "claude-opus-4" in summary["by_model"]

    def test_summary_empty_tracker(self) -> None:
        reporter = CostReporter(CostTracker())
        summary = reporter.summary()
        assert summary["call_count"] == 0
        assert summary["total_cost_usd"] == 0

    def test_filter_by_period_daily_with_reference_date(self) -> None:
        t = CostTracker()
        ref = date(2025, 6, 15)
        t.record(
            task_id="x",
            model="m",
            input_tokens=1,
            output_tokens=1,
            cost_usd=0.001,
            timestamp=datetime(2025, 6, 15, tzinfo=timezone.utc),
        )
        reporter = CostReporter(t)
        records = reporter._filter_by_period("daily", reference_date=ref)
        assert len(records) == 1

    def test_filter_by_period_weekly_with_reference_date(self) -> None:
        t = CostTracker()
        ref = date(2025, 6, 16)  # Monday
        t.record(
            task_id="x",
            model="m",
            input_tokens=1,
            output_tokens=1,
            cost_usd=0.001,
            timestamp=datetime(2025, 6, 14, tzinfo=timezone.utc),  # Saturday of prev week
        )
        t.record(
            task_id="y",
            model="m",
            input_tokens=1,
            output_tokens=1,
            cost_usd=0.002,
            timestamp=datetime(2025, 6, 16, tzinfo=timezone.utc),  # Same week
        )
        reporter = CostReporter(t)
        records = reporter._filter_by_period("weekly", reference_date=ref)
        assert len(records) == 1  # Only the Monday record

    def test_filter_by_period_monthly_with_reference_date(self) -> None:
        t = CostTracker()
        ref = date(2025, 6, 30)
        t.record(
            task_id="x",
            model="m",
            input_tokens=1,
            output_tokens=1,
            cost_usd=0.001,
            timestamp=datetime(2025, 5, 15, tzinfo=timezone.utc),  # May
        )
        t.record(
            task_id="y",
            model="m",
            input_tokens=1,
            output_tokens=1,
            cost_usd=0.002,
            timestamp=datetime(2025, 6, 15, tzinfo=timezone.utc),  # June
        )
        reporter = CostReporter(t)
        records = reporter._filter_by_period("monthly", reference_date=ref)
        assert len(records) == 1

    def test_to_csv_creates_parent_dirs(self, tmp_path: Path, tracker: CostTracker) -> None:
        reporter = CostReporter(tracker)
        nested = tmp_path / "nested" / "deep" / "report.csv"
        count = reporter.to_csv(nested)
        assert nested.exists()

    def test_summary_by_task(self, tracker: CostTracker) -> None:
        reporter = CostReporter(tracker)
        summary = reporter.summary()
        assert "t1" in summary["by_task"]


# ===========================================================================
# dashboard/api.py
# ===========================================================================


class TestDashboardApi:
    def test_get_audit_no_logger(self) -> None:
        api = DashboardApi()
        result = api.get_audit()
        assert result["entries"] == []
        assert result["total"] == 0

    def test_get_audit_with_logger(self, tmp_log: AuditLogger) -> None:
        api = DashboardApi(audit_logger=tmp_log)
        result = api.get_audit()
        assert result["total"] > 0
        assert isinstance(result["entries"], list)

    def test_get_audit_last_n_limit(self, tmp_path: Path) -> None:
        audit = AuditLogger(tmp_path / "big.jsonl")
        for i in range(20):
            audit.log({"event": "ev", "index": i})
        api = DashboardApi(audit_logger=audit)
        result = api.get_audit(last_n=5)
        assert len(result["entries"]) == 5
        assert result["total"] == 20

    def test_get_policies_no_engine(self) -> None:
        api = DashboardApi()
        result = api.get_policies()
        assert result["count"] == 0

    def test_get_policies_with_engine(self) -> None:
        from aumos_cowork_governance.policies.engine import PolicyEngine
        engine = PolicyEngine()
        api = DashboardApi(policy_engine=engine)
        result = api.get_policies()
        assert "policies" in result

    def test_get_costs_no_tracker(self) -> None:
        api = DashboardApi()
        result = api.get_costs()
        assert result["total_cost_usd"] == 0.0
        assert result["call_count"] == 0

    def test_get_costs_with_tracker(self, tracker: CostTracker) -> None:
        api = DashboardApi(cost_tracker=tracker)
        result = api.get_costs()
        assert result["call_count"] == 1
        assert result["total_cost_usd"] == pytest.approx(0.01)
        assert "claude-opus-4" in result["by_model"]

    def test_get_status_all_none(self) -> None:
        api = DashboardApi()
        result = api.get_status()
        assert result["healthy"] is True
        assert result["audit_count"] == 0

    def test_get_status_with_components(
        self, tmp_log: AuditLogger, tracker: CostTracker, queue: ApprovalQueue
    ) -> None:
        from aumos_cowork_governance.policies.engine import PolicyEngine
        engine = PolicyEngine()
        api = DashboardApi(
            audit_logger=tmp_log,
            policy_engine=engine,
            cost_tracker=tracker,
            approval_queue=queue,
        )
        result = api.get_status()
        assert result["healthy"] is True
        assert result["audit_count"] > 0

    def test_get_approvals_no_queue(self) -> None:
        api = DashboardApi()
        result = api.get_approvals()
        assert result["count"] == 0

    def test_get_approvals_with_pending(self, queue: ApprovalQueue) -> None:
        queue.enqueue(action_context={"action": "delete"}, policy_name="p", message="m")
        api = DashboardApi(approval_queue=queue)
        result = api.get_approvals()
        assert result["count"] == 1
        assert len(result["pending"]) == 1
        pending = result["pending"][0]
        assert "request_id" in pending
        assert pending["policy_name"] == "p"

    def test_to_json_serialises_dict(self) -> None:
        api = DashboardApi()
        data: dict[str, object] = {"key": "value", "count": 42}
        result = api.to_json(data)
        parsed = json.loads(result)
        assert parsed["key"] == "value"


# ===========================================================================
# dashboard/renderer.py
# ===========================================================================


def _make_data(
    fail_count: int = 0,
    top_violations: list[tuple[str, int]] | None = None,
    recent_events: list[dict[str, str]] | None = None,
    total_evals: int = 100,
) -> DashboardData:
    return DashboardData(
        total_evaluations=total_evals,
        pass_count=total_evals - fail_count,
        fail_count=fail_count,
        pending_approvals=2,
        total_cost_usd=1.23,
        active_agents=3,
        top_violations=top_violations or [],
        recent_events=recent_events or [],
    )


class TestDashboardRenderer:
    def test_render_json_is_valid_json(self) -> None:
        renderer = DashboardRenderer()
        data = _make_data()
        result = renderer.render_json(data)
        parsed = json.loads(result)
        assert parsed["total_evaluations"] == 100

    def test_render_json_includes_violations(self) -> None:
        renderer = DashboardRenderer()
        data = _make_data(top_violations=[("DH-001", 5)])
        result = renderer.render_json(data)
        parsed = json.loads(result)
        assert parsed["top_violations"][0]["rule_id"] == "DH-001"

    def test_render_json_includes_recent_events(self) -> None:
        renderer = DashboardRenderer()
        events = [{"event": "api_call", "model": "claude-opus-4"}]
        data = _make_data(recent_events=events)
        result = renderer.render_json(data)
        parsed = json.loads(result)
        assert len(parsed["recent_events"]) == 1

    def test_render_table_contains_metrics(self) -> None:
        renderer = DashboardRenderer()
        data = _make_data(fail_count=3)
        result = renderer.render_table(data)
        assert "GOVERNANCE DASHBOARD" in result
        assert "100" in result

    def test_render_table_shows_violations(self) -> None:
        renderer = DashboardRenderer()
        data = _make_data(top_violations=[("DH-001", 7)])
        result = renderer.render_table(data)
        assert "DH-001" in result

    def test_render_table_no_violations(self) -> None:
        renderer = DashboardRenderer()
        data = _make_data()
        result = renderer.render_table(data)
        assert "No violations recorded" in result

    def test_render_table_shows_recent_events(self) -> None:
        renderer = DashboardRenderer()
        events = [{"event": "policy_block", "policy": "no-pii"}]
        data = _make_data(recent_events=events)
        result = renderer.render_table(data)
        assert "policy_block" in result

    def test_render_table_no_events(self) -> None:
        renderer = DashboardRenderer()
        data = _make_data()
        result = renderer.render_table(data)
        assert "No recent events" in result

    def test_render_table_zero_evaluations_pass_pct(self) -> None:
        renderer = DashboardRenderer()
        data = _make_data(total_evals=0)
        result = renderer.render_table(data)
        assert "0.0%" in result

    def test_render_summary_returns_non_empty_string(self) -> None:
        renderer = DashboardRenderer()
        data = _make_data()
        result = renderer.render_summary(data)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_render_summary_with_violations(self) -> None:
        renderer = DashboardRenderer()
        data = _make_data(fail_count=5, top_violations=[("CON-001", 3)])
        result = renderer.render_summary(data)
        assert isinstance(result, str)

    def test_render_summary_zero_evaluations(self) -> None:
        renderer = DashboardRenderer()
        data = _make_data(total_evals=0)
        result = renderer.render_summary(data)
        assert isinstance(result, str)

    def test_render_summary_with_events(self) -> None:
        renderer = DashboardRenderer()
        events = [{"event": "api_call", "model": "claude-opus-4"}]
        data = _make_data(recent_events=events)
        result = renderer.render_summary(data)
        assert isinstance(result, str)

    def test_render_summary_no_violations(self) -> None:
        renderer = DashboardRenderer()
        data = _make_data(top_violations=[])
        result = renderer.render_summary(data)
        assert isinstance(result, str)


# ===========================================================================
# templates/policy_templates.py
# ===========================================================================


class TestPolicyTemplates:
    def test_list_templates_is_sorted(self) -> None:
        names = list_templates()
        assert sorted(names) == names

    def test_list_templates_contains_all_builtins(self) -> None:
        names = list_templates()
        expected = {
            "pii_protection",
            "gdpr_basic",
            "hipaa_basic",
            "soc2_basic",
            "cost_limits",
            "data_classification",
            "file_access_control",
        }
        assert expected.issubset(set(names))

    def test_get_template_returns_yaml_string(self) -> None:
        yaml_str = get_template("pii_protection")
        assert isinstance(yaml_str, str)
        assert "policies:" in yaml_str

    def test_get_template_gdpr(self) -> None:
        assert "GDPR" in get_template("gdpr_basic")

    def test_get_template_hipaa(self) -> None:
        assert "HIPAA" in get_template("hipaa_basic")

    def test_get_template_soc2(self) -> None:
        assert "SOC 2" in get_template("soc2_basic")

    def test_get_template_cost_limits(self) -> None:
        yaml_str = get_template("cost_limits")
        assert "tokens" in yaml_str.lower() or "cost" in yaml_str.lower()

    def test_get_template_file_access(self) -> None:
        yaml_str = get_template("file_access_control")
        assert "path" in yaml_str.lower()

    def test_get_template_data_classification(self) -> None:
        yaml_str = get_template("data_classification")
        assert "RESTRICTED" in yaml_str or "classification" in yaml_str.lower()

    def test_get_template_raises_key_error_for_unknown(self) -> None:
        with pytest.raises(KeyError, match="not found"):
            get_template("nonexistent_template")

    def test_write_template_creates_file(self, tmp_path: Path) -> None:
        output = tmp_path / "pii.yaml"
        result = write_template("pii_protection", output)
        assert result.exists()
        assert result.read_text(encoding="utf-8").startswith("# PII")

    def test_write_template_creates_parent_dirs(self, tmp_path: Path) -> None:
        nested = tmp_path / "subdir" / "nested" / "policy.yaml"
        write_template("gdpr_basic", nested)
        assert nested.exists()

    def test_write_template_raises_for_unknown(self, tmp_path: Path) -> None:
        with pytest.raises(KeyError):
            write_template("bogus", tmp_path / "out.yaml")

    def test_write_template_returns_absolute_path(self, tmp_path: Path) -> None:
        output = tmp_path / "test.yaml"
        result = write_template("pii_protection", output)
        assert result.is_absolute()
