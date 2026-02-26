"""Tests for the plugin registry in aumos-cowork-governance."""
from __future__ import annotations

from abc import ABC, abstractmethod
from unittest.mock import MagicMock, patch

import pytest

from aumos_cowork_governance.plugins.registry import (
    PluginAlreadyRegisteredError,
    PluginNotFoundError,
    PluginRegistry,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


class BaseProcessor(ABC):
    @abstractmethod
    def process(self, data: str) -> str: ...


class ConcreteA(BaseProcessor):
    def process(self, data: str) -> str:
        return data.upper()


class ConcreteB(BaseProcessor):
    def process(self, data: str) -> str:
        return data.lower()


class NotASubclass:
    def process(self, data: str) -> str:
        return data


@pytest.fixture()
def registry() -> PluginRegistry[BaseProcessor]:
    return PluginRegistry(BaseProcessor, "test-registry")


# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------


class TestPluginErrors:
    def test_not_found_error_has_name(self) -> None:
        err = PluginNotFoundError("my-plugin", "my-registry")
        assert err.plugin_name == "my-plugin"
        assert err.registry_name == "my-registry"
        assert issubclass(PluginNotFoundError, KeyError)

    def test_already_registered_error_has_name(self) -> None:
        err = PluginAlreadyRegisteredError("dup", "reg")
        assert err.plugin_name == "dup"
        assert issubclass(PluginAlreadyRegisteredError, ValueError)


# ---------------------------------------------------------------------------
# register decorator
# ---------------------------------------------------------------------------


class TestRegisterDecorator:
    def test_register_and_get(self, registry: PluginRegistry[BaseProcessor]) -> None:
        registry.register("proc-a")(ConcreteA)
        assert registry.get("proc-a") is ConcreteA

    def test_register_returns_class_unchanged(self, registry: PluginRegistry[BaseProcessor]) -> None:
        result = registry.register("proc-a")(ConcreteA)
        assert result is ConcreteA

    def test_register_duplicate_raises(self, registry: PluginRegistry[BaseProcessor]) -> None:
        registry.register("proc-a")(ConcreteA)
        with pytest.raises(PluginAlreadyRegisteredError):
            registry.register("proc-a")(ConcreteB)

    def test_register_non_subclass_raises_type_error(self, registry: PluginRegistry[BaseProcessor]) -> None:
        with pytest.raises(TypeError):
            registry.register("bad")(NotASubclass)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# register_class
# ---------------------------------------------------------------------------


class TestRegisterClass:
    def test_register_class_directly(self, registry: PluginRegistry[BaseProcessor]) -> None:
        registry.register_class("proc-b", ConcreteB)
        assert registry.get("proc-b") is ConcreteB

    def test_register_class_duplicate_raises(self, registry: PluginRegistry[BaseProcessor]) -> None:
        registry.register_class("proc-a", ConcreteA)
        with pytest.raises(PluginAlreadyRegisteredError):
            registry.register_class("proc-a", ConcreteB)

    def test_register_class_non_subclass_raises(self, registry: PluginRegistry[BaseProcessor]) -> None:
        with pytest.raises(TypeError):
            registry.register_class("bad", NotASubclass)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# deregister
# ---------------------------------------------------------------------------


class TestDeregister:
    def test_deregister_existing(self, registry: PluginRegistry[BaseProcessor]) -> None:
        registry.register_class("proc-a", ConcreteA)
        registry.deregister("proc-a")
        assert "proc-a" not in registry

    def test_deregister_nonexistent_raises(self, registry: PluginRegistry[BaseProcessor]) -> None:
        with pytest.raises(PluginNotFoundError):
            registry.deregister("ghost")


# ---------------------------------------------------------------------------
# get
# ---------------------------------------------------------------------------


class TestGet:
    def test_get_nonexistent_raises(self, registry: PluginRegistry[BaseProcessor]) -> None:
        with pytest.raises(PluginNotFoundError):
            registry.get("missing")

    def test_get_after_register(self, registry: PluginRegistry[BaseProcessor]) -> None:
        registry.register_class("proc-a", ConcreteA)
        assert registry.get("proc-a") is ConcreteA


# ---------------------------------------------------------------------------
# list_plugins
# ---------------------------------------------------------------------------


class TestListPlugins:
    def test_empty_registry(self, registry: PluginRegistry[BaseProcessor]) -> None:
        assert registry.list_plugins() == []

    def test_sorted_alphabetically(self, registry: PluginRegistry[BaseProcessor]) -> None:
        registry.register_class("z-plugin", ConcreteA)
        registry.register_class("a-plugin", ConcreteB)
        assert registry.list_plugins() == ["a-plugin", "z-plugin"]


# ---------------------------------------------------------------------------
# Dunder methods
# ---------------------------------------------------------------------------


class TestDunderMethods:
    def test_contains_true(self, registry: PluginRegistry[BaseProcessor]) -> None:
        registry.register_class("proc", ConcreteA)
        assert "proc" in registry

    def test_contains_false(self, registry: PluginRegistry[BaseProcessor]) -> None:
        assert "missing" not in registry

    def test_len(self, registry: PluginRegistry[BaseProcessor]) -> None:
        assert len(registry) == 0
        registry.register_class("proc-a", ConcreteA)
        assert len(registry) == 1
        registry.register_class("proc-b", ConcreteB)
        assert len(registry) == 2

    def test_repr(self, registry: PluginRegistry[BaseProcessor]) -> None:
        r = repr(registry)
        assert "test-registry" in r
        assert "BaseProcessor" in r


# ---------------------------------------------------------------------------
# load_entrypoints
# ---------------------------------------------------------------------------


class TestLoadEntrypoints:
    def test_load_entrypoints_no_plugins_does_nothing(self, registry: PluginRegistry[BaseProcessor]) -> None:
        with patch("importlib.metadata.entry_points", return_value=[]):
            registry.load_entrypoints("test.group")
        assert len(registry) == 0

    def test_load_entrypoints_loads_valid_plugin(self, registry: PluginRegistry[BaseProcessor]) -> None:
        mock_ep = MagicMock()
        mock_ep.name = "ep-proc"
        mock_ep.load.return_value = ConcreteA
        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry.load_entrypoints("test.group")
        assert "ep-proc" in registry
        assert registry.get("ep-proc") is ConcreteA

    def test_load_entrypoints_skips_already_registered(self, registry: PluginRegistry[BaseProcessor]) -> None:
        registry.register_class("ep-proc", ConcreteA)
        mock_ep = MagicMock()
        mock_ep.name = "ep-proc"
        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry.load_entrypoints("test.group")
        mock_ep.load.assert_not_called()

    def test_load_entrypoints_handles_load_failure(self, registry: PluginRegistry[BaseProcessor]) -> None:
        mock_ep = MagicMock()
        mock_ep.name = "failing-ep"
        mock_ep.load.side_effect = ImportError("module not found")
        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry.load_entrypoints("test.group")
        assert "failing-ep" not in registry

    def test_load_entrypoints_handles_type_error_on_register(self, registry: PluginRegistry[BaseProcessor]) -> None:
        mock_ep = MagicMock()
        mock_ep.name = "bad-type"
        mock_ep.load.return_value = NotASubclass
        with patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            registry.load_entrypoints("test.group")
        assert "bad-type" not in registry
