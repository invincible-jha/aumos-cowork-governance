"""Governance configuration loader with Pydantic v2 validation.

Loads and validates a ``governance.yaml`` file into a typed
:class:`GovernanceConfig` object.  Unknown keys are allowed to support
future schema additions without breakage.

Example
-------
>>> loader = ConfigLoader()
>>> config = loader.load(Path("governance.yaml"))
>>> config.audit.log_path
PosixPath('/var/log/cowork/audit.jsonl')
"""
from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator


class AuditConfig(BaseModel):
    """Configuration for the audit trail subsystem."""

    model_config = {"extra": "allow"}

    log_path: Path = Field(default=Path("./governance_audit.jsonl"))
    rotation_enabled: bool = Field(default=True)
    retention_days: int = Field(default=90, ge=1)


class CostConfig(BaseModel):
    """Configuration for the cost tracking subsystem."""

    model_config = {"extra": "allow"}

    daily_budget_usd: float | None = Field(default=None, ge=0)
    weekly_budget_usd: float | None = Field(default=None, ge=0)
    monthly_budget_usd: float | None = Field(default=None, ge=0)
    alert_thresholds_pct: list[float] = Field(default_factory=lambda: [50.0, 80.0, 100.0])
    webhook_url: str | None = Field(default=None)


class PiiConfig(BaseModel):
    """Configuration for PII detection."""

    model_config = {"extra": "allow"}

    jurisdictions: list[str] = Field(default_factory=lambda: ["common", "us"])
    redact_on_warn: bool = Field(default=False)

    @field_validator("jurisdictions")
    @classmethod
    def validate_jurisdictions(cls, values: list[str]) -> list[str]:
        valid = {"common", "us", "eu", "india"}
        for v in values:
            if v not in valid:
                raise ValueError(f"Unknown jurisdiction '{v}'. Valid: {valid}")
        return values


class ApprovalConfig(BaseModel):
    """Configuration for the human approval subsystem."""

    model_config = {"extra": "allow"}

    timeout_seconds: float = Field(default=300.0, ge=1)
    webhook_url: str | None = Field(default=None)
    webhook_format: Literal["slack", "teams", "generic"] = Field(default="generic")


class DashboardConfig(BaseModel):
    """Configuration for the local dashboard."""

    model_config = {"extra": "allow"}

    enabled: bool = Field(default=False)
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8080, ge=1024, le=65535)


class GovernanceConfig(BaseModel):
    """Top-level governance configuration schema.

    Loaded from ``governance.yaml``.  All sections are optional and
    fall back to sensible defaults.
    """

    model_config = {"extra": "allow"}

    version: str = Field(default="1")
    preset: str | None = Field(default=None)
    policy_files: list[Path] = Field(default_factory=list)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    cost: CostConfig = Field(default_factory=CostConfig)
    pii: PiiConfig = Field(default_factory=PiiConfig)
    approval: ApprovalConfig = Field(default_factory=ApprovalConfig)
    dashboard: DashboardConfig = Field(default_factory=DashboardConfig)
    policies: list[dict[str, object]] = Field(default_factory=list)
    settings: dict[str, object] = Field(default_factory=dict)


class ConfigLoader:
    """Loads and validates governance YAML configuration.

    Example
    -------
    >>> loader = ConfigLoader()
    >>> config = loader.load(Path("governance.yaml"))
    """

    def load(self, config_path: Path) -> GovernanceConfig:
        """Load and validate a governance YAML file.

        Parameters
        ----------
        config_path:
            Path to the ``governance.yaml`` file.

        Returns
        -------
        GovernanceConfig
            Validated configuration object.

        Raises
        ------
        FileNotFoundError:
            When the config file does not exist.
        ValueError:
            When the YAML content fails Pydantic validation.
        """
        if not config_path.exists():
            raise FileNotFoundError(f"Governance config not found: {config_path}")

        with config_path.open("r", encoding="utf-8") as fh:
            raw: dict[str, object] = yaml.safe_load(fh) or {}

        return GovernanceConfig.model_validate(raw)

    def load_string(self, yaml_content: str) -> GovernanceConfig:
        """Load and validate a YAML string directly.

        Parameters
        ----------
        yaml_content:
            Raw YAML text.

        Returns
        -------
        GovernanceConfig
            Validated configuration object.
        """
        raw: dict[str, object] = yaml.safe_load(yaml_content) or {}
        return GovernanceConfig.model_validate(raw)

    def defaults(self) -> GovernanceConfig:
        """Return a default configuration with all defaults applied."""
        return GovernanceConfig()
