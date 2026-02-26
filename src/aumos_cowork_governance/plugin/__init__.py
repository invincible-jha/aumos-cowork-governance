"""Plugin core package for aumos-cowork-governance.

Exports the GovernancePlugin entry point, lifecycle hooks, and
configuration loader.
"""
from __future__ import annotations

from aumos_cowork_governance.plugin.config_loader import ConfigLoader, GovernanceConfig
from aumos_cowork_governance.plugin.governance_plugin import GovernancePlugin
from aumos_cowork_governance.plugin.hooks import CoworkHooks

__all__ = [
    "ConfigLoader",
    "CoworkHooks",
    "GovernanceConfig",
    "GovernancePlugin",
]
