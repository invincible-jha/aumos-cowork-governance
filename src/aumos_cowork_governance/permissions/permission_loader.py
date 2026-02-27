"""YAML-based permission configuration loader for the permission system (E8.1).

PermissionLoader reads YAML permission configs and builds PermissionMatrix
instances. YAML files must follow the schema defined in this module.

Schema
------
::

    version: "1.0"
    default_allow: false
    rules:
      - id: "rule-001"
        action: "file_read"
        allow: true
        reason: "Allow reads within workspace"
        priority: 10
        constraints:
          - type: "region"
            allowed_paths:
              - "/workspace"
          - type: "glob_pattern"
            patterns:
              - "*.csv"
              - "*.json"
      - id: "rule-002"
        action: "file_write"
        allow: false
        reason: "Deny writes to system directories"
        constraints:
          - type: "region"
            allowed_paths:
              - "/etc"
              - "/usr"

Example
-------
::

    loader = PermissionLoader()
    matrix = loader.load("/path/to/permissions.yaml")
    result = matrix.check("file_read", "/workspace/data.csv")
    assert result.allowed is True
"""
from __future__ import annotations

import logging
from pathlib import Path

import yaml

from aumos_cowork_governance.permissions.action_permission import (
    PermissionMatrix,
    PermissionRule,
)

logger = logging.getLogger(__name__)

_SUPPORTED_VERSIONS: frozenset[str] = frozenset(["1.0", "1"])


class PermissionConfigError(ValueError):
    """Raised when a permission YAML config is malformed or invalid.

    Attributes
    ----------
    config_path:
        The path to the config file that caused the error, if known.
    """

    def __init__(self, message: str, config_path: str | None = None) -> None:
        self.config_path = config_path
        prefix = f"[{config_path}] " if config_path else ""
        super().__init__(f"{prefix}{message}")


class PermissionLoader:
    """Loads PermissionMatrix configurations from YAML files or dicts.

    Parameters
    ----------
    strict:
        When ``True``, unknown top-level keys in the YAML file are treated
        as an error. Default ``False`` (unknown keys are silently ignored).

    Examples
    --------
    ::

        loader = PermissionLoader()
        matrix = loader.load_from_dict({
            "version": "1.0",
            "default_allow": False,
            "rules": [
                {
                    "id": "r1",
                    "action": "file_read",
                    "allow": True,
                    "reason": "Allow workspace reads",
                    "constraints": [
                        {"type": "region", "allowed_paths": ["/workspace"]},
                    ],
                }
            ],
        })
        result = matrix.check("file_read", "/workspace/data.csv")
        assert result.allowed
    """

    _KNOWN_TOP_KEYS: frozenset[str] = frozenset(
        ["version", "default_allow", "rules", "metadata", "description"]
    )

    def __init__(self, strict: bool = False) -> None:
        self._strict = strict

    def load(self, config_path: str | Path) -> PermissionMatrix:
        """Load a PermissionMatrix from a YAML file on disk.

        Parameters
        ----------
        config_path:
            Path to the YAML permission configuration file.

        Returns
        -------
        PermissionMatrix

        Raises
        ------
        PermissionConfigError
            If the file cannot be read, parsed, or is structurally invalid.
        FileNotFoundError
            If the config file does not exist.
        """
        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(
                f"Permission config not found: {config_path}"
            )

        try:
            with config_path.open("r", encoding="utf-8") as fh:
                raw: dict[str, object] = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise PermissionConfigError(
                f"Failed to parse YAML: {exc}", str(config_path)
            ) from exc

        return self._build_matrix(raw, config_path=str(config_path))

    def load_from_dict(
        self,
        config: dict[str, object],
        config_path: str | None = None,
    ) -> PermissionMatrix:
        """Load a PermissionMatrix from an already-parsed config dictionary.

        Parameters
        ----------
        config:
            Dictionary conforming to the permission config schema.
        config_path:
            Optional source identifier used in error messages.

        Returns
        -------
        PermissionMatrix

        Raises
        ------
        PermissionConfigError
            If the config is structurally invalid.
        """
        return self._build_matrix(config, config_path=config_path)

    def load_from_yaml_string(
        self,
        yaml_string: str,
        config_path: str | None = None,
    ) -> PermissionMatrix:
        """Load a PermissionMatrix from a YAML string.

        Parameters
        ----------
        yaml_string:
            YAML content as a string.
        config_path:
            Optional source identifier for error messages.

        Returns
        -------
        PermissionMatrix

        Raises
        ------
        PermissionConfigError
            If parsing fails or the config is invalid.
        """
        try:
            raw: dict[str, object] = yaml.safe_load(yaml_string) or {}
        except yaml.YAMLError as exc:
            raise PermissionConfigError(
                f"Failed to parse YAML string: {exc}", config_path
            ) from exc
        return self._build_matrix(raw, config_path=config_path)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_matrix(
        self,
        raw: dict[str, object],
        config_path: str | None = None,
    ) -> PermissionMatrix:
        """Validate and build a PermissionMatrix from a raw config dict."""
        self._validate_structure(raw, config_path)

        version = str(raw.get("version", "1.0"))
        if version not in _SUPPORTED_VERSIONS:
            raise PermissionConfigError(
                f"Unsupported config version {version!r}. "
                f"Supported: {sorted(_SUPPORTED_VERSIONS)}.",
                config_path,
            )

        default_allow: bool = bool(raw.get("default_allow", False))
        raw_rules: list[dict[str, object]] = list(raw.get("rules", []))  # type: ignore[arg-type]

        rules: list[PermissionRule] = []
        for index, raw_rule in enumerate(raw_rules):
            try:
                rule = PermissionRule.from_dict(raw_rule)
                rules.append(rule)
            except (ValueError, KeyError, TypeError) as exc:
                raise PermissionConfigError(
                    f"Error in rule at index {index}: {exc}",
                    config_path,
                ) from exc

        logger.info(
            "Loaded %d permission rules from %s (default_allow=%s)",
            len(rules),
            config_path or "<dict>",
            default_allow,
        )
        return PermissionMatrix(rules=rules, default_allow=default_allow)

    def _validate_structure(
        self,
        raw: dict[str, object],
        config_path: str | None,
    ) -> None:
        """Validate top-level structure of the config dict."""
        if not isinstance(raw, dict):
            raise PermissionConfigError(
                "Permission config must be a YAML mapping (dict).", config_path
            )

        if "rules" not in raw:
            raise PermissionConfigError(
                "Permission config must contain a 'rules' list.", config_path
            )

        if not isinstance(raw["rules"], list):
            raise PermissionConfigError(
                "Permission config 'rules' must be a list.", config_path
            )

        if self._strict:
            unknown_keys = set(raw.keys()) - self._KNOWN_TOP_KEYS
            if unknown_keys:
                raise PermissionConfigError(
                    f"Unknown top-level keys: {sorted(unknown_keys)}. "
                    f"Known keys: {sorted(self._KNOWN_TOP_KEYS)}.",
                    config_path,
                )
