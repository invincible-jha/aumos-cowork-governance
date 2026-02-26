"""Local governance dashboard package.

Provides a lightweight HTTP server (no external web framework) that serves
a browser-based governance dashboard and a JSON REST API, as well as a
Rich-based terminal renderer for inline CLI dashboard output.
"""
from __future__ import annotations

from aumos_cowork_governance.dashboard.api import DashboardApi
from aumos_cowork_governance.dashboard.renderer import DashboardData, DashboardRenderer
from aumos_cowork_governance.dashboard.server import DashboardServer

__all__ = [
    "DashboardApi",
    "DashboardData",
    "DashboardRenderer",
    "DashboardServer",
]
