"""Plugin subsystem for aumos-cowork-governance.

The registry module provides the decorator-based registration surface.
Third-party implementations register via this system using
``importlib.metadata`` entry-points under the "aumos_cowork_governance.plugins"
group.

Example
-------
Declare a plugin in pyproject.toml:

.. code-block:: toml

    [aumos_cowork_governance.plugins]
    my_plugin = "my_package.plugins.my_plugin:MyPlugin"
"""
from __future__ import annotations

from aumos_cowork_governance.plugins.registry import PluginRegistry

__all__ = ["PluginRegistry"]
