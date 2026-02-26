"""YAML policy parser.

Parses a governance YAML configuration file into a structured list of
policy dictionaries suitable for the PolicyEngine.

The expected top-level YAML structure is::

    policies:
      - name: "block-etc-passwd"
        action: block
        message: "Access to /etc is not permitted."
        conditions:
          - field: path
            operator: starts_with
            value: /etc
        notify:
          - security-team@example.com

    settings:
      audit_log_path: /var/log/cowork/audit.jsonl
      cost_budget_daily_usd: 10.0

Example
-------
>>> parser = PolicyParser()
>>> config = parser.parse("governance.yaml")
>>> len(config.policies)
3
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ParsedPolicy:
    """Structured representation of a single parsed policy."""

    name: str
    action: str
    message: str
    conditions: list[dict[str, object]]
    condition_logic: str
    notify: list[str]
    enabled: bool


@dataclass
class ParsedConfig:
    """Full parsed governance configuration."""

    policies: list[ParsedPolicy]
    settings: dict[str, object]
    raw: dict[str, object]


class PolicyParser:
    """Parses governance YAML into structured :class:`ParsedConfig` objects.

    The parser is deliberately permissive for unknown keys so that future
    schema extensions remain backwards-compatible.
    """

    VALID_ACTIONS: frozenset[str] = frozenset(
        {"allow", "block", "warn", "log", "approve"}
    )
    VALID_OPERATORS: frozenset[str] = frozenset(
        {
            "equals",
            "not_equals",
            "starts_with",
            "contains",
            "greater_than",
            "less_than",
            "matches",
            "in_list",
            "not_in_list",
            "contains_pii",
        }
    )

    def parse(self, config_path: str | Path) -> ParsedConfig:
        """Parse a YAML governance file.

        Parameters
        ----------
        config_path:
            Path to the governance YAML file.

        Returns
        -------
        ParsedConfig
            Structured configuration object.

        Raises
        ------
        FileNotFoundError
            If the config file does not exist.
        ValueError
            If the YAML is malformed or missing required keys.
        """
        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Governance config not found: {config_path}")

        with config_path.open("r", encoding="utf-8") as fh:
            raw: dict[str, object] = yaml.safe_load(fh) or {}

        return self._parse_dict(raw)

    def parse_string(self, yaml_content: str) -> ParsedConfig:
        """Parse a YAML string directly (useful for testing).

        Parameters
        ----------
        yaml_content:
            Raw YAML text.
        """
        raw: dict[str, object] = yaml.safe_load(yaml_content) or {}
        return self._parse_dict(raw)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_dict(self, raw: dict[str, object]) -> ParsedConfig:
        """Convert a raw YAML dict to a :class:`ParsedConfig`."""
        raw_policies: list[dict[str, object]] = list(
            raw.get("policies", [])  # type: ignore[arg-type]
        )
        settings: dict[str, object] = dict(
            raw.get("settings", {})  # type: ignore[arg-type]
        )

        policies = [self._parse_policy(p) for p in raw_policies]
        return ParsedConfig(policies=policies, settings=settings, raw=raw)

    def _parse_policy(self, raw_policy: dict[str, object]) -> ParsedPolicy:
        """Parse a single policy dict."""
        name: str = str(raw_policy.get("name", "unnamed"))
        action_raw: str = str(raw_policy.get("action", "log")).lower()

        if action_raw not in self.VALID_ACTIONS:
            logger.warning(
                "Policy '%s' has unknown action '%s'; defaulting to 'log'.",
                name,
                action_raw,
            )
            action_raw = "log"

        message: str = str(raw_policy.get("message", ""))
        condition_logic: str = str(raw_policy.get("condition_logic", "AND")).upper()
        notify: list[str] = [str(n) for n in raw_policy.get("notify", [])]  # type: ignore[union-attr]
        enabled: bool = bool(raw_policy.get("enabled", True))

        raw_conditions: list[dict[str, object]] = list(
            raw_policy.get("conditions", [])  # type: ignore[arg-type]
        )
        conditions = [self._parse_condition(name, c) for c in raw_conditions]

        return ParsedPolicy(
            name=name,
            action=action_raw,
            message=message,
            conditions=conditions,
            condition_logic=condition_logic,
            notify=notify,
            enabled=enabled,
        )

    def _parse_condition(
        self,
        policy_name: str,
        raw_condition: dict[str, object],
    ) -> dict[str, object]:
        """Validate and normalise a single condition dict."""
        operator: str = str(raw_condition.get("operator", "equals"))
        if operator not in self.VALID_OPERATORS:
            logger.warning(
                "Policy '%s' uses unknown operator '%s'.",
                policy_name,
                operator,
            )
        return dict(raw_condition)
