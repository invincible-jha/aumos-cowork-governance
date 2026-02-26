"""Unit tests for policies/parser.py — PolicyParser."""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from aumos_cowork_governance.policies.parser import ParsedConfig, ParsedPolicy, PolicyParser


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def parser() -> PolicyParser:
    return PolicyParser()


MINIMAL_YAML = """\
policies:
  - name: allow-public
    action: allow
    message: "Public files are permitted."
    conditions:
      - field: path
        operator: starts_with
        value: /public
"""

FULL_YAML = """\
policies:
  - name: block-etc
    action: block
    message: "No access to /etc"
    condition_logic: AND
    conditions:
      - field: path
        operator: starts_with
        value: /etc
    notify:
      - security@example.com
    enabled: true

  - name: warn-tmp
    action: warn
    message: "Suspicious /tmp access"
    condition_logic: OR
    conditions:
      - field: path
        operator: starts_with
        value: /tmp
    enabled: true

settings:
  audit_log_path: /var/log/cowork/audit.jsonl
  cost_budget_daily_usd: 10.0
"""

INVALID_ACTION_YAML = """\
policies:
  - name: bad-action
    action: explode
    conditions: []
"""


# ---------------------------------------------------------------------------
# parse_string — minimal config
# ---------------------------------------------------------------------------


class TestPolicyParserParseString:
    def test_parse_minimal_returns_parsed_config(self, parser: PolicyParser) -> None:
        config = parser.parse_string(MINIMAL_YAML)
        assert isinstance(config, ParsedConfig)
        assert len(config.policies) == 1

    def test_parse_minimal_policy_fields(self, parser: PolicyParser) -> None:
        config = parser.parse_string(MINIMAL_YAML)
        policy = config.policies[0]
        assert policy.name == "allow-public"
        assert policy.action == "allow"
        assert policy.message == "Public files are permitted."

    def test_parse_minimal_condition(self, parser: PolicyParser) -> None:
        config = parser.parse_string(MINIMAL_YAML)
        condition = config.policies[0].conditions[0]
        assert condition["field"] == "path"
        assert condition["operator"] == "starts_with"
        assert condition["value"] == "/public"

    def test_parse_full_returns_two_policies(self, parser: PolicyParser) -> None:
        config = parser.parse_string(FULL_YAML)
        assert len(config.policies) == 2

    def test_parse_full_settings(self, parser: PolicyParser) -> None:
        config = parser.parse_string(FULL_YAML)
        assert config.settings["audit_log_path"] == "/var/log/cowork/audit.jsonl"
        assert config.settings["cost_budget_daily_usd"] == 10.0

    def test_parse_full_notify_list(self, parser: PolicyParser) -> None:
        config = parser.parse_string(FULL_YAML)
        block_policy = config.policies[0]
        assert "security@example.com" in block_policy.notify

    def test_parse_full_condition_logic_and(self, parser: PolicyParser) -> None:
        config = parser.parse_string(FULL_YAML)
        assert config.policies[0].condition_logic == "AND"

    def test_parse_full_condition_logic_or(self, parser: PolicyParser) -> None:
        config = parser.parse_string(FULL_YAML)
        assert config.policies[1].condition_logic == "OR"

    def test_parse_empty_yaml_returns_empty_policies(self, parser: PolicyParser) -> None:
        config = parser.parse_string("")
        assert config.policies == []
        assert config.settings == {}

    def test_invalid_action_defaults_to_log(self, parser: PolicyParser) -> None:
        config = parser.parse_string(INVALID_ACTION_YAML)
        assert config.policies[0].action == "log"

    def test_parse_enabled_defaults_true(self, parser: PolicyParser) -> None:
        config = parser.parse_string(MINIMAL_YAML)
        assert config.policies[0].enabled is True

    def test_parse_raw_is_preserved(self, parser: PolicyParser) -> None:
        config = parser.parse_string(FULL_YAML)
        assert "policies" in config.raw


# ---------------------------------------------------------------------------
# parse — file path
# ---------------------------------------------------------------------------


class TestPolicyParserParseFile:
    def test_parse_from_file(self, parser: PolicyParser, tmp_path: Path) -> None:
        config_file = tmp_path / "gov.yaml"
        config_file.write_text(MINIMAL_YAML, encoding="utf-8")
        config = parser.parse(config_file)
        assert len(config.policies) == 1

    def test_parse_missing_file_raises(self, parser: PolicyParser, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            parser.parse(tmp_path / "missing.yaml")

    def test_parse_accepts_string_path(self, parser: PolicyParser, tmp_path: Path) -> None:
        config_file = tmp_path / "gov.yaml"
        config_file.write_text(MINIMAL_YAML, encoding="utf-8")
        config = parser.parse(str(config_file))
        assert len(config.policies) == 1


# ---------------------------------------------------------------------------
# Valid actions and operators
# ---------------------------------------------------------------------------


class TestPolicyParserValidSets:
    def test_valid_actions_contains_all_five(self, parser: PolicyParser) -> None:
        assert PolicyParser.VALID_ACTIONS == frozenset(
            {"allow", "block", "warn", "log", "approve"}
        )

    def test_valid_operators_contains_pii(self, parser: PolicyParser) -> None:
        assert "contains_pii" in PolicyParser.VALID_OPERATORS

    def test_valid_operators_contains_matches(self, parser: PolicyParser) -> None:
        assert "matches" in PolicyParser.VALID_OPERATORS


# ---------------------------------------------------------------------------
# ParsedPolicy dataclass
# ---------------------------------------------------------------------------


class TestParsedPolicy:
    def test_parsed_policy_is_dataclass(self, parser: PolicyParser) -> None:
        config = parser.parse_string(FULL_YAML)
        assert isinstance(config.policies[0], ParsedPolicy)

    def test_parsed_policy_enabled_field(self, parser: PolicyParser) -> None:
        yaml_text = """\
policies:
  - name: disabled-policy
    action: log
    enabled: false
    conditions: []
"""
        config = parser.parse_string(yaml_text)
        assert config.policies[0].enabled is False
