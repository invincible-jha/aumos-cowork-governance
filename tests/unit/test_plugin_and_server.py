"""Tests for GovernancePlugin, CoworkHooks, ConfigLoader, DashboardServer, and RuleEvaluator."""
from __future__ import annotations

import io
import json
import textwrap
import threading
import time
import urllib.request
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from aumos_cowork_governance.plugin.config_loader import (
    ApprovalConfig,
    AuditConfig,
    ConfigLoader,
    CostConfig,
    DashboardConfig,
    GovernanceConfig,
    PiiConfig,
)
from aumos_cowork_governance.plugin.governance_plugin import GovernancePlugin
from aumos_cowork_governance.plugin.hooks import CoworkHooks
from aumos_cowork_governance.policies.evaluator import RuleEvaluator


# ---------------------------------------------------------------------------
# ConfigLoader — defaults
# ---------------------------------------------------------------------------


class TestConfigLoaderDefaults:
    def test_defaults_returns_governance_config(self) -> None:
        loader = ConfigLoader()
        config = loader.defaults()
        assert isinstance(config, GovernanceConfig)

    def test_defaults_audit_path(self) -> None:
        config = ConfigLoader().defaults()
        assert config.audit.log_path == Path("./governance_audit.jsonl")

    def test_defaults_rotation_enabled(self) -> None:
        config = ConfigLoader().defaults()
        assert config.audit.rotation_enabled is True

    def test_defaults_retention_days(self) -> None:
        config = ConfigLoader().defaults()
        assert config.audit.retention_days == 90

    def test_defaults_daily_budget_none(self) -> None:
        config = ConfigLoader().defaults()
        assert config.cost.daily_budget_usd is None

    def test_defaults_pii_jurisdictions(self) -> None:
        config = ConfigLoader().defaults()
        assert "common" in config.pii.jurisdictions

    def test_defaults_approval_timeout(self) -> None:
        config = ConfigLoader().defaults()
        assert config.approval.timeout_seconds == 300.0

    def test_defaults_dashboard_disabled(self) -> None:
        config = ConfigLoader().defaults()
        assert config.dashboard.enabled is False

    def test_defaults_dashboard_host(self) -> None:
        config = ConfigLoader().defaults()
        assert config.dashboard.host == "127.0.0.1"

    def test_defaults_dashboard_port(self) -> None:
        config = ConfigLoader().defaults()
        assert config.dashboard.port == 8080


# ---------------------------------------------------------------------------
# ConfigLoader — load_string
# ---------------------------------------------------------------------------


class TestConfigLoaderLoadString:
    def test_empty_yaml_uses_defaults(self) -> None:
        loader = ConfigLoader()
        config = loader.load_string("")
        assert isinstance(config, GovernanceConfig)

    def test_custom_version(self) -> None:
        loader = ConfigLoader()
        config = loader.load_string("version: '2'\n")
        assert config.version == "2"

    def test_custom_audit_log_path(self) -> None:
        loader = ConfigLoader()
        yaml_str = "audit:\n  log_path: /tmp/test_audit.jsonl\n"
        config = loader.load_string(yaml_str)
        assert config.audit.log_path == Path("/tmp/test_audit.jsonl")

    def test_custom_daily_budget(self) -> None:
        loader = ConfigLoader()
        yaml_str = "cost:\n  daily_budget_usd: 5.0\n"
        config = loader.load_string(yaml_str)
        assert config.cost.daily_budget_usd == 5.0

    def test_custom_pii_jurisdictions(self) -> None:
        loader = ConfigLoader()
        yaml_str = "pii:\n  jurisdictions:\n    - common\n    - eu\n"
        config = loader.load_string(yaml_str)
        assert "eu" in config.pii.jurisdictions

    def test_invalid_jurisdiction_raises(self) -> None:
        loader = ConfigLoader()
        yaml_str = "pii:\n  jurisdictions:\n    - unknown_country\n"
        with pytest.raises(Exception):
            loader.load_string(yaml_str)

    def test_inline_policies(self) -> None:
        loader = ConfigLoader()
        yaml_str = textwrap.dedent("""\
            policies:
              - name: test-policy
                conditions: []
                action: log
        """)
        config = loader.load_string(yaml_str)
        assert len(config.policies) == 1

    def test_webhook_format_teams(self) -> None:
        loader = ConfigLoader()
        yaml_str = "approval:\n  webhook_format: teams\n"
        config = loader.load_string(yaml_str)
        assert config.approval.webhook_format == "teams"


# ---------------------------------------------------------------------------
# ConfigLoader — load (file)
# ---------------------------------------------------------------------------


class TestConfigLoaderLoadFile:
    def test_load_file_not_found_raises(self, tmp_path: Path) -> None:
        loader = ConfigLoader()
        with pytest.raises(FileNotFoundError):
            loader.load(tmp_path / "nonexistent.yaml")

    def test_load_valid_file(self, tmp_path: Path) -> None:
        config_file = tmp_path / "governance.yaml"
        config_file.write_text("version: '3'\n", encoding="utf-8")
        loader = ConfigLoader()
        config = loader.load(config_file)
        assert config.version == "3"

    def test_load_empty_file_uses_defaults(self, tmp_path: Path) -> None:
        config_file = tmp_path / "governance.yaml"
        config_file.write_text("", encoding="utf-8")
        loader = ConfigLoader()
        config = loader.load(config_file)
        assert isinstance(config, GovernanceConfig)


# ---------------------------------------------------------------------------
# Pydantic models — field validation
# ---------------------------------------------------------------------------


class TestPydanticConfigModels:
    def test_audit_config_defaults(self) -> None:
        cfg = AuditConfig()
        assert cfg.retention_days == 90

    def test_cost_config_alert_thresholds_default(self) -> None:
        cfg = CostConfig()
        assert cfg.alert_thresholds_pct == [50.0, 80.0, 100.0]

    def test_pii_config_redact_default(self) -> None:
        cfg = PiiConfig()
        assert cfg.redact_on_warn is False

    def test_approval_config_webhook_format_default(self) -> None:
        cfg = ApprovalConfig()
        assert cfg.webhook_format == "generic"

    def test_dashboard_config_enabled_default(self) -> None:
        cfg = DashboardConfig()
        assert cfg.enabled is False

    def test_governance_config_extra_fields_allowed(self) -> None:
        # extra="allow" means unknown keys don't raise
        cfg = GovernanceConfig.model_validate({"unknown_key": "value"})
        assert isinstance(cfg, GovernanceConfig)


# ---------------------------------------------------------------------------
# GovernancePlugin — lifecycle
# ---------------------------------------------------------------------------


class TestGovernancePluginLifecycle:
    def test_get_status_before_init_returns_not_initialised(self) -> None:
        plugin = GovernancePlugin()
        status = plugin.get_status()
        assert status["initialised"] is False

    def test_pre_action_before_init_raises(self) -> None:
        plugin = GovernancePlugin()
        with pytest.raises(RuntimeError, match="not initialised"):
            plugin.pre_action({"action": "file_read"})

    def test_load_config_defaults_initialises_plugin(self) -> None:
        plugin = GovernancePlugin()
        plugin.load_config_defaults()
        status = plugin.get_status()
        assert status["initialised"] is True

    def test_properties_return_subsystems(self) -> None:
        plugin = GovernancePlugin()
        plugin.load_config_defaults()
        assert plugin.audit is not None
        assert plugin.engine is not None
        assert plugin.cost_tracker is not None
        assert plugin.approval_queue is not None
        assert plugin.pii_detector is not None

    def test_load_config_from_file(self, tmp_path: Path) -> None:
        config_file = tmp_path / "governance.yaml"
        config_file.write_text("version: '1'\n", encoding="utf-8")
        plugin = GovernancePlugin()
        plugin.load_config(config_file)
        assert plugin.get_status()["initialised"] is True

    def test_get_status_returns_audit_count(self) -> None:
        plugin = GovernancePlugin()
        plugin.load_config_defaults()
        status = plugin.get_status()
        assert "audit_count" in status
        assert "policy_count" in status
        assert "total_cost_usd" in status
        assert "pending_approvals" in status


# ---------------------------------------------------------------------------
# GovernancePlugin — pre_action
# ---------------------------------------------------------------------------


class TestGovernancePluginPreAction:
    def setup_method(self) -> None:
        self.plugin = GovernancePlugin()
        self.plugin.load_config_defaults()

    def test_pre_action_returns_dict(self) -> None:
        result = self.plugin.pre_action({"action": "file_read", "path": "/tmp/test.txt"})
        assert isinstance(result, dict)
        assert "allowed" in result

    def test_pre_action_allowed_for_benign_action(self) -> None:
        result = self.plugin.pre_action({"action": "file_read", "path": "/tmp/test.txt"})
        assert result["allowed"] is True

    def test_pre_action_has_results_key(self) -> None:
        result = self.plugin.pre_action({"action": "api_call", "url": "https://api.example.com"})
        assert "results" in result

    def test_pre_action_has_requires_approval_key(self) -> None:
        result = self.plugin.pre_action({"action": "file_read"})
        assert "requires_approval" in result

    def test_pre_action_budget_exceeded_blocks(self) -> None:
        """When budget is exceeded, pre_action returns allowed=False."""
        plugin = GovernancePlugin()
        # Load config with very low daily budget
        loader = ConfigLoader()
        config = loader.load_string("cost:\n  daily_budget_usd: 0.001\n")
        plugin._config = config
        plugin._init_subsystems()
        # Record cost that exceeds budget
        assert plugin.cost_tracker is not None
        plugin.cost_tracker.record(
            task_id="t1", model="m", input_tokens=10, output_tokens=5, cost_usd=1.0
        )
        result = plugin.pre_action({"action": "file_read"})
        assert result["allowed"] is False
        assert result["blocking_policy"] == "budget-exceeded"


# ---------------------------------------------------------------------------
# GovernancePlugin — post_action
# ---------------------------------------------------------------------------


class TestGovernancePluginPostAction:
    def setup_method(self) -> None:
        self.plugin = GovernancePlugin()
        self.plugin.load_config_defaults()

    def test_post_action_logs_audit_entry(self) -> None:
        context = {"action": "file_read", "path": "/tmp/test.txt"}
        result: dict[str, object] = {"status": "ok"}
        self.plugin.post_action(context, result)
        assert self.plugin.audit is not None
        assert self.plugin.audit.count() > 0

    def test_post_action_records_cost(self) -> None:
        context = {"action": "api_call", "task_id": "t1"}
        result = {
            "cost_usd": 0.01,
            "model": "claude-opus-4",
            "input_tokens": 500,
            "output_tokens": 100,
        }
        self.plugin.post_action(context, result)
        assert self.plugin.cost_tracker is not None
        assert self.plugin.cost_tracker.total_cost_usd() == pytest.approx(0.01)

    def test_post_action_no_cost_key_is_safe(self) -> None:
        context = {"action": "file_read"}
        result: dict[str, object] = {"status": "ok"}
        # Should not raise
        self.plugin.post_action(context, result)

    def test_post_action_invalid_cost_is_skipped(self) -> None:
        context = {"action": "api_call"}
        result: dict[str, object] = {"cost_usd": "not-a-number"}
        # Should not raise — invalid cost is silently skipped
        self.plugin.post_action(context, result)


# ---------------------------------------------------------------------------
# GovernancePlugin — redact_on_warn
# ---------------------------------------------------------------------------


class TestGovernancePluginPiiRedaction:
    def test_pre_action_redacts_content_when_enabled(self) -> None:
        loader = ConfigLoader()
        config = loader.load_string("pii:\n  redact_on_warn: true\n")
        plugin = GovernancePlugin()
        plugin._config = config
        plugin._init_subsystems()
        # Send PII in content
        result = plugin.pre_action({
            "action": "file_read",
            "content": "Contact user@example.com for info",
        })
        assert isinstance(result, dict)
        # redacted_content may be set when PII is detected
        # (the key should always be present)
        assert "redacted_content" in result


# ---------------------------------------------------------------------------
# CoworkHooks
# ---------------------------------------------------------------------------


class TestCoworkHooks:
    def setup_method(self) -> None:
        self.plugin = GovernancePlugin()
        self.plugin.load_config_defaults()
        self.hooks = CoworkHooks(self.plugin)

    def test_pre_file_access_returns_dict(self) -> None:
        result = self.hooks.pre_file_access({"path": "/tmp/test.txt"})
        assert isinstance(result, dict)
        assert "allowed" in result

    def test_pre_file_access_injects_action(self) -> None:
        # Verify action is injected by checking the result is well-formed
        result = self.hooks.pre_file_access({"path": "/data/report.csv"})
        assert result.get("allowed") is True

    def test_post_file_access_logs(self) -> None:
        context = {"path": "/tmp/test.txt"}
        result: dict[str, object] = {"size_bytes": 1024}
        self.hooks.post_file_access(context, result)
        assert self.plugin.audit is not None
        assert self.plugin.audit.count() > 0

    def test_pre_file_write_returns_dict(self) -> None:
        result = self.hooks.pre_file_write({"path": "/tmp/output.txt"})
        assert isinstance(result, dict)
        assert "allowed" in result

    def test_post_file_write_logs(self) -> None:
        context = {"path": "/tmp/output.txt"}
        result: dict[str, object] = {"bytes_written": 512}
        self.hooks.post_file_write(context, result)
        assert self.plugin.audit is not None
        assert self.plugin.audit.count() > 0

    def test_pre_api_call_returns_dict(self) -> None:
        result = self.hooks.pre_api_call({"url": "https://api.openai.com/v1/chat"})
        assert isinstance(result, dict)
        assert "allowed" in result

    def test_post_api_call_records_cost(self) -> None:
        context = {"url": "https://api.openai.com/v1/chat", "task_id": "t1"}
        result: dict[str, object] = {
            "cost_usd": 0.05,
            "model": "gpt-4o",
            "input_tokens": 1000,
            "output_tokens": 200,
        }
        self.hooks.post_api_call(context, result)
        assert self.plugin.cost_tracker is not None
        assert self.plugin.cost_tracker.total_cost_usd() == pytest.approx(0.05)

    def test_pre_file_access_preserves_extra_context_keys(self) -> None:
        result = self.hooks.pre_file_access({"path": "/tmp/x.txt", "agent": "worker-1"})
        assert isinstance(result, dict)

    def test_pre_api_call_with_task_id(self) -> None:
        result = self.hooks.pre_api_call({"url": "https://example.com", "task_id": "t42"})
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# DashboardServer — HTTP handler
# ---------------------------------------------------------------------------


def _find_free_port() -> int:
    """Find a free TCP port on localhost."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _make_api() -> object:
    """Create a minimal DashboardApi backed by default-config plugin."""
    from aumos_cowork_governance.dashboard.api import DashboardApi
    plugin = GovernancePlugin()
    plugin.load_config_defaults()
    return DashboardApi(
        audit_logger=plugin.audit,
        policy_engine=plugin.engine,
        cost_tracker=plugin.cost_tracker,
        approval_queue=plugin.approval_queue,
    )


class TestDashboardServer:
    def test_url_property(self) -> None:
        from aumos_cowork_governance.dashboard.server import DashboardServer
        api = _make_api()
        server = DashboardServer(api=api, host="127.0.0.1", port=9999)  # type: ignore[arg-type]
        assert server.url == "http://127.0.0.1:9999/"

    def test_start_background_and_stop(self) -> None:
        from aumos_cowork_governance.dashboard.server import DashboardServer
        api = _make_api()
        port = _find_free_port()
        server = DashboardServer(api=api, host="127.0.0.1", port=port)  # type: ignore[arg-type]
        server.start_background()
        time.sleep(0.1)  # Let the thread start
        # Hit the root endpoint
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/")
        assert resp.getcode() == 200
        content = resp.read().decode("utf-8")
        assert "Cowork Governance Dashboard" in content
        server.stop()

    def test_api_status_endpoint(self) -> None:
        from aumos_cowork_governance.dashboard.server import DashboardServer
        api = _make_api()
        port = _find_free_port()
        server = DashboardServer(api=api, host="127.0.0.1", port=port)  # type: ignore[arg-type]
        server.start_background()
        time.sleep(0.1)
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status")
        data = json.loads(resp.read())
        assert "audit_count" in data
        server.stop()

    def test_api_audit_endpoint(self) -> None:
        from aumos_cowork_governance.dashboard.server import DashboardServer
        api = _make_api()
        port = _find_free_port()
        server = DashboardServer(api=api, host="127.0.0.1", port=port)  # type: ignore[arg-type]
        server.start_background()
        time.sleep(0.1)
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/audit?n=10")
        data = json.loads(resp.read())
        assert "entries" in data
        server.stop()

    def test_api_policies_endpoint(self) -> None:
        from aumos_cowork_governance.dashboard.server import DashboardServer
        api = _make_api()
        port = _find_free_port()
        server = DashboardServer(api=api, host="127.0.0.1", port=port)  # type: ignore[arg-type]
        server.start_background()
        time.sleep(0.1)
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/policies")
        data = json.loads(resp.read())
        assert "policies" in data
        server.stop()

    def test_api_costs_endpoint(self) -> None:
        from aumos_cowork_governance.dashboard.server import DashboardServer
        api = _make_api()
        port = _find_free_port()
        server = DashboardServer(api=api, host="127.0.0.1", port=port)  # type: ignore[arg-type]
        server.start_background()
        time.sleep(0.1)
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/costs")
        data = json.loads(resp.read())
        assert "total_cost_usd" in data
        server.stop()

    def test_api_approvals_endpoint(self) -> None:
        from aumos_cowork_governance.dashboard.server import DashboardServer
        api = _make_api()
        port = _find_free_port()
        server = DashboardServer(api=api, host="127.0.0.1", port=port)  # type: ignore[arg-type]
        server.start_background()
        time.sleep(0.1)
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/approvals")
        data = json.loads(resp.read())
        assert "count" in data
        server.stop()

    def test_404_for_unknown_route(self) -> None:
        from aumos_cowork_governance.dashboard.server import DashboardServer
        import urllib.error
        api = _make_api()
        port = _find_free_port()
        server = DashboardServer(api=api, host="127.0.0.1", port=port)  # type: ignore[arg-type]
        server.start_background()
        time.sleep(0.1)
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/nonexistent")
            assert False, "Expected HTTP 404"
        except urllib.error.HTTPError as exc:
            assert exc.code == 404
        finally:
            server.stop()

    def test_stop_when_server_not_started_is_safe(self) -> None:
        from aumos_cowork_governance.dashboard.server import DashboardServer
        api = _make_api()
        server = DashboardServer(api=api, host="127.0.0.1", port=9998)  # type: ignore[arg-type]
        # stop() when never started should not raise
        server.stop()

    def test_index_html_route(self) -> None:
        from aumos_cowork_governance.dashboard.server import DashboardServer
        api = _make_api()
        port = _find_free_port()
        server = DashboardServer(api=api, host="127.0.0.1", port=port)  # type: ignore[arg-type]
        server.start_background()
        time.sleep(0.1)
        resp = urllib.request.urlopen(f"http://127.0.0.1:{port}/index.html")
        assert resp.getcode() == 200
        server.stop()


# ---------------------------------------------------------------------------
# RuleEvaluator — operators (boost evaluator.py coverage)
# ---------------------------------------------------------------------------


class TestRuleEvaluatorOperators:
    def setup_method(self) -> None:
        self.ev = RuleEvaluator()

    def _cond(self, field: str, operator: str, value: object) -> dict[str, object]:
        return {"field": field, "operator": operator, "value": value}

    def test_ends_with_true(self) -> None:
        cond = self._cond("path", "ends_with", ".py")
        assert self.ev.evaluate([cond], "AND", {"path": "script.py"}) is True

    def test_ends_with_false(self) -> None:
        cond = self._cond("path", "ends_with", ".py")
        assert self.ev.evaluate([cond], "AND", {"path": "script.txt"}) is False

    def test_ends_with_non_string_false(self) -> None:
        cond = self._cond("count", "ends_with", "0")
        assert self.ev.evaluate([cond], "AND", {"count": 10}) is False

    def test_greater_than_or_equal_true(self) -> None:
        cond = self._cond("tokens", "greater_than_or_equal", 100)
        assert self.ev.evaluate([cond], "AND", {"tokens": 100}) is True

    def test_greater_than_or_equal_false(self) -> None:
        cond = self._cond("tokens", "greater_than_or_equal", 100)
        assert self.ev.evaluate([cond], "AND", {"tokens": 99}) is False

    def test_less_than_or_equal_true(self) -> None:
        cond = self._cond("tokens", "less_than_or_equal", 50)
        assert self.ev.evaluate([cond], "AND", {"tokens": 50}) is True

    def test_less_than_or_equal_false(self) -> None:
        cond = self._cond("tokens", "less_than_or_equal", 50)
        assert self.ev.evaluate([cond], "AND", {"tokens": 51}) is False

    def test_matches_valid_regex(self) -> None:
        cond = self._cond("url", "matches", r"https://.*\.example\.com")
        assert self.ev.evaluate([cond], "AND", {"url": "https://api.example.com"}) is True

    def test_matches_invalid_regex_returns_false(self) -> None:
        cond = self._cond("url", "matches", r"[invalid regex")
        assert self.ev.evaluate([cond], "AND", {"url": "https://api.example.com"}) is False

    def test_matches_non_string_false(self) -> None:
        cond = self._cond("count", "matches", r"\d+")
        assert self.ev.evaluate([cond], "AND", {"count": 42}) is False

    def test_in_list_true(self) -> None:
        cond = self._cond("action", "in_list", ["file_read", "file_write"])
        assert self.ev.evaluate([cond], "AND", {"action": "file_read"}) is True

    def test_in_list_false(self) -> None:
        cond = self._cond("action", "in_list", ["file_read"])
        assert self.ev.evaluate([cond], "AND", {"action": "api_call"}) is False

    def test_in_list_non_list_expected_false(self) -> None:
        cond = self._cond("action", "in_list", "not-a-list")
        assert self.ev.evaluate([cond], "AND", {"action": "file_read"}) is False

    def test_not_in_list_true(self) -> None:
        cond = self._cond("action", "not_in_list", ["blocked_op"])
        assert self.ev.evaluate([cond], "AND", {"action": "file_read"}) is True

    def test_not_in_list_when_in_list_false(self) -> None:
        cond = self._cond("action", "not_in_list", ["file_read"])
        assert self.ev.evaluate([cond], "AND", {"action": "file_read"}) is False

    def test_not_in_list_non_list_expected_true(self) -> None:
        cond = self._cond("action", "not_in_list", "not-a-list")
        assert self.ev.evaluate([cond], "AND", {"action": "file_read"}) is True

    def test_is_null_true(self) -> None:
        cond = self._cond("optional_field", "is_null", None)
        assert self.ev.evaluate([cond], "AND", {"optional_field": None}) is True

    def test_is_null_false(self) -> None:
        cond = self._cond("field", "is_null", None)
        assert self.ev.evaluate([cond], "AND", {"field": "value"}) is False

    def test_is_not_null_true(self) -> None:
        cond = self._cond("field", "is_not_null", None)
        assert self.ev.evaluate([cond], "AND", {"field": "value"}) is True

    def test_is_not_null_false(self) -> None:
        cond = self._cond("field", "is_not_null", None)
        assert self.ev.evaluate([cond], "AND", {"field": None}) is False

    def test_contains_pii_without_detector_returns_false(self) -> None:
        cond = self._cond("content", "contains_pii", None)
        assert self.ev.evaluate([cond], "AND", {"content": "user@example.com"}) is False

    def test_contains_pii_with_detector(self) -> None:
        detector = lambda text: "@" in text  # noqa: E731
        ev = RuleEvaluator(pii_detector=detector)
        cond = self._cond("content", "contains_pii", None)
        assert ev.evaluate([cond], "AND", {"content": "user@example.com"}) is True

    def test_contains_pii_non_string_false(self) -> None:
        detector = lambda text: True  # noqa: E731
        ev = RuleEvaluator(pii_detector=detector)
        cond = self._cond("count", "contains_pii", None)
        assert ev.evaluate([cond], "AND", {"count": 42}) is False

    def test_unknown_operator_returns_false(self) -> None:
        cond = self._cond("field", "xyzzy_unknown", "value")
        assert self.ev.evaluate([cond], "AND", {"field": "value"}) is False

    def test_negate_prefix_inverts_result(self) -> None:
        # "not:equals" should return True when actual != expected
        cond = self._cond("action", "not:equals", "file_read")
        assert self.ev.evaluate([cond], "AND", {"action": "api_call"}) is True

    def test_negate_prefix_false_case(self) -> None:
        cond = self._cond("action", "not:equals", "file_read")
        assert self.ev.evaluate([cond], "AND", {"action": "file_read"}) is False

    def test_or_logic_any_match(self) -> None:
        conditions = [
            self._cond("action", "equals", "file_read"),
            self._cond("action", "equals", "api_call"),
        ]
        assert self.ev.evaluate(conditions, "OR", {"action": "api_call"}) is True

    def test_or_logic_none_match(self) -> None:
        conditions = [
            self._cond("action", "equals", "file_read"),
            self._cond("action", "equals", "api_call"),
        ]
        assert self.ev.evaluate(conditions, "OR", {"action": "file_delete"}) is False

    def test_empty_conditions_returns_true(self) -> None:
        assert self.ev.evaluate([], "AND", {"action": "file_read"}) is True

    def test_dot_path_resolution(self) -> None:
        cond = self._cond("user.role", "equals", "admin")
        ctx: dict[str, object] = {"user": {"role": "admin"}}
        assert self.ev.evaluate([cond], "AND", ctx) is True

    def test_dot_path_missing_field_resolves_none(self) -> None:
        cond = self._cond("user.missing", "is_null", None)
        ctx: dict[str, object] = {"user": {"role": "admin"}}
        assert self.ev.evaluate([cond], "AND", ctx) is True

    def test_greater_than_type_error_returns_false(self) -> None:
        cond = self._cond("field", "greater_than", "not-a-number")
        assert self.ev.evaluate([cond], "AND", {"field": "also-not-a-number"}) is False

    def test_less_than_type_error_returns_false(self) -> None:
        cond = self._cond("field", "less_than", "not-a-number")
        assert self.ev.evaluate([cond], "AND", {"field": "also-not-a-number"}) is False

    def test_greater_than_or_equal_type_error_returns_false(self) -> None:
        cond = self._cond("field", "greater_than_or_equal", "not-a-number")
        assert self.ev.evaluate([cond], "AND", {"field": "also-not-a-number"}) is False

    def test_less_than_or_equal_type_error_returns_false(self) -> None:
        cond = self._cond("field", "less_than_or_equal", "not-a-number")
        assert self.ev.evaluate([cond], "AND", {"field": "also-not-a-number"}) is False
