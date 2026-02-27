"""Tests for PermissionLoader (E8.1)."""
from __future__ import annotations

import pathlib

import pytest

from aumos_cowork_governance.permissions.action_permission import PermissionMatrix
from aumos_cowork_governance.permissions.permission_loader import (
    PermissionConfigError,
    PermissionLoader,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_VALID_CONFIG: dict[str, object] = {
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
        },
        {
            "id": "r2",
            "action": "file_write",
            "allow": False,
            "reason": "Deny writes outside workspace",
            "constraints": [
                {"type": "region", "allowed_paths": ["/etc", "/usr"]},
            ],
        },
    ],
}


@pytest.fixture()
def loader() -> PermissionLoader:
    return PermissionLoader()


@pytest.fixture()
def strict_loader() -> PermissionLoader:
    return PermissionLoader(strict=True)


# ---------------------------------------------------------------------------
# load_from_dict
# ---------------------------------------------------------------------------

class TestPermissionLoaderFromDict:
    def test_returns_permission_matrix(self, loader: PermissionLoader) -> None:
        matrix = loader.load_from_dict(_VALID_CONFIG)
        assert isinstance(matrix, PermissionMatrix)

    def test_rule_count_correct(self, loader: PermissionLoader) -> None:
        matrix = loader.load_from_dict(_VALID_CONFIG)
        assert matrix.rule_count == 2

    def test_default_allow_applied(self, loader: PermissionLoader) -> None:
        matrix = loader.load_from_dict(_VALID_CONFIG)
        assert matrix.default_allow is False

    def test_check_allowed_path(self, loader: PermissionLoader) -> None:
        matrix = loader.load_from_dict(_VALID_CONFIG)
        result = matrix.check("file_read", "/workspace/data.csv")
        assert result.allowed is True

    def test_check_denied_path(self, loader: PermissionLoader) -> None:
        matrix = loader.load_from_dict(_VALID_CONFIG)
        result = matrix.check("file_read", "/home/user/secret.txt")
        assert result.allowed is False

    def test_missing_rules_key_raises(self, loader: PermissionLoader) -> None:
        with pytest.raises(PermissionConfigError, match="rules"):
            loader.load_from_dict({"version": "1.0", "default_allow": False})

    def test_non_dict_config_raises(self, loader: PermissionLoader) -> None:
        with pytest.raises(PermissionConfigError):
            loader.load_from_dict([{"action": "file_read"}])  # type: ignore[arg-type]

    def test_empty_rules_list_valid(self, loader: PermissionLoader) -> None:
        matrix = loader.load_from_dict({"rules": []})
        assert matrix.rule_count == 0

    def test_default_allow_true(self, loader: PermissionLoader) -> None:
        config = {"rules": [], "default_allow": True}
        matrix = loader.load_from_dict(config)
        assert matrix.default_allow is True

    def test_unsupported_version_raises(self, loader: PermissionLoader) -> None:
        config = {**_VALID_CONFIG, "version": "99.0"}
        with pytest.raises(PermissionConfigError, match="version"):
            loader.load_from_dict(config)

    def test_invalid_rule_raises(self, loader: PermissionLoader) -> None:
        config = {
            "rules": [
                {"allow": True, "reason": "no action"},
            ]
        }
        with pytest.raises(PermissionConfigError):
            loader.load_from_dict(config)


class TestPermissionLoaderStrict:
    def test_strict_mode_rejects_unknown_keys(
        self, strict_loader: PermissionLoader
    ) -> None:
        config = {**_VALID_CONFIG, "unknown_key": "some_value"}
        with pytest.raises(PermissionConfigError, match="unknown_key"):
            strict_loader.load_from_dict(config)

    def test_strict_mode_accepts_known_keys(
        self, strict_loader: PermissionLoader
    ) -> None:
        matrix = strict_loader.load_from_dict(_VALID_CONFIG)
        assert isinstance(matrix, PermissionMatrix)

    def test_non_strict_ignores_unknown_keys(
        self, loader: PermissionLoader
    ) -> None:
        config = {**_VALID_CONFIG, "extra_field": "ignored"}
        matrix = loader.load_from_dict(config)
        assert isinstance(matrix, PermissionMatrix)


# ---------------------------------------------------------------------------
# load_from_yaml_string
# ---------------------------------------------------------------------------

class TestPermissionLoaderFromYamlString:
    def test_valid_yaml_string(self, loader: PermissionLoader) -> None:
        yaml_str = """
version: "1.0"
default_allow: false
rules:
  - id: r1
    action: file_read
    allow: true
    reason: Allow workspace reads
    constraints:
      - type: region
        allowed_paths:
          - /workspace
"""
        matrix = loader.load_from_yaml_string(yaml_str)
        assert isinstance(matrix, PermissionMatrix)
        assert matrix.rule_count == 1

    def test_invalid_yaml_raises(self, loader: PermissionLoader) -> None:
        with pytest.raises(PermissionConfigError, match="YAML"):
            loader.load_from_yaml_string("{{invalid: yaml: content:")

    def test_yaml_string_check_works(self, loader: PermissionLoader) -> None:
        yaml_str = """
rules:
  - id: r1
    action: file_read
    allow: true
    reason: test
"""
        matrix = loader.load_from_yaml_string(yaml_str)
        result = matrix.check("file_read", "/workspace/data.csv")
        # No constraint — matches unconditionally
        assert result.allowed is True


# ---------------------------------------------------------------------------
# load (file-based)
# ---------------------------------------------------------------------------

class TestPermissionLoaderFromFile:
    def test_missing_file_raises_file_not_found(
        self, loader: PermissionLoader
    ) -> None:
        missing_path = "/nonexistent/path/permissions.yaml"
        with pytest.raises(FileNotFoundError):
            loader.load(missing_path)

    def test_loads_valid_yaml_file(
        self, loader: PermissionLoader, tmp_path: pathlib.Path
    ) -> None:
        import yaml

        config_file = tmp_path / "permissions.yaml"
        config_file.write_text(
            yaml.dump(
                {
                    "version": "1.0",
                    "default_allow": False,
                    "rules": [
                        {
                            "id": "r1",
                            "action": "file_read",
                            "allow": True,
                            "reason": "Allow workspace",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        matrix = loader.load(str(config_file))
        assert isinstance(matrix, PermissionMatrix)
        assert matrix.rule_count == 1
