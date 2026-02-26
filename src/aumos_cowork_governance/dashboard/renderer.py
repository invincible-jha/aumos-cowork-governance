"""Terminal dashboard renderer using Rich for formatted governance summaries.

DashboardRenderer produces human-readable output in three formats:
- Rich-formatted terminal panels and tables (for CLI use)
- Plain tabular text (for log-friendly output)
- JSON (for programmatic consumption)

Example
-------
>>> from aumos_cowork_governance.dashboard.renderer import DashboardRenderer, DashboardData
>>> data = DashboardData(
...     total_evaluations=150,
...     pass_count=140,
...     fail_count=10,
...     pending_approvals=3,
...     total_cost_usd=4.27,
...     active_agents=5,
...     top_violations=[("DH-001", 6), ("CON-001", 4)],
...     recent_events=[{"event": "policy_block", "policy": "no-pii"}],
... )
>>> renderer = DashboardRenderer()
>>> print(renderer.render_json(data))
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
import io


@dataclass
class DashboardData:
    """Aggregated governance metrics for dashboard rendering.

    Attributes
    ----------
    total_evaluations:
        Total number of policy evaluations performed in this session.
    pass_count:
        Number of evaluations that resulted in ALLOW (no block).
    fail_count:
        Number of evaluations that were BLOCKED by a policy.
    pending_approvals:
        Current count of pending human-approval requests.
    total_cost_usd:
        Accumulated API cost in USD across all recorded operations.
    active_agents:
        Number of distinct agent identifiers seen in cost records.
    top_violations:
        Ordered list of ``(rule_id, count)`` pairs for the most frequently
        triggered violations, highest count first.
    recent_events:
        Most-recent audit events as flat string-keyed dicts (e.g. from the
        audit logger), latest first.
    """

    total_evaluations: int
    pass_count: int
    fail_count: int
    pending_approvals: int
    total_cost_usd: float
    active_agents: int
    top_violations: list[tuple[str, int]]
    recent_events: list[dict[str, str]]


class DashboardRenderer:
    """Renders governance DashboardData in multiple output formats.

    Methods
    -------
    render_summary(data):
        Returns a Rich-formatted string with panels and tables suitable
        for terminal output via ``print()`` or ``rich.print()``.
    render_table(data):
        Returns plain multi-line tabular text for log-friendly environments.
    render_json(data):
        Returns a compact JSON string representation of the dashboard data.
    """

    # ------------------------------------------------------------------
    # Rich rendering
    # ------------------------------------------------------------------

    def render_summary(self, data: DashboardData) -> str:
        """Render a Rich-formatted governance dashboard summary.

        Parameters
        ----------
        data:
            The aggregated governance metrics to display.

        Returns
        -------
        str
            A string containing Rich markup, suitable for printing to a
            terminal that supports ANSI colour codes.
        """
        output_buffer = io.StringIO()
        console = Console(file=output_buffer, highlight=False)

        # --- Health overview panel ---
        pass_pct = (
            round(data.pass_count / data.total_evaluations * 100, 1)
            if data.total_evaluations > 0
            else 0.0
        )
        health_color = "green" if data.fail_count == 0 else ("yellow" if data.fail_count < 5 else "red")

        overview_table = Table.grid(padding=(0, 2))
        overview_table.add_column(style="bold")
        overview_table.add_column()
        overview_table.add_row("Total Evaluations", str(data.total_evaluations))
        overview_table.add_row(
            "Pass / Fail",
            f"[green]{data.pass_count}[/green] / [{health_color}]{data.fail_count}[/{health_color}]"
            f"  ({pass_pct}% pass rate)",
        )
        overview_table.add_row("Pending Approvals", str(data.pending_approvals))
        overview_table.add_row("Active Agents", str(data.active_agents))
        overview_table.add_row("Total Cost (USD)", f"${data.total_cost_usd:.4f}")

        console.print(Panel(overview_table, title="[bold cyan]Governance Overview[/bold cyan]", border_style="cyan"))

        # --- Top violations table ---
        if data.top_violations:
            violations_table = Table(
                "Rule ID",
                "Violation Count",
                title="Top Violations",
                show_header=True,
                header_style="bold magenta",
            )
            for rule_id, count in data.top_violations:
                violations_table.add_row(rule_id, str(count))
            console.print(violations_table)
        else:
            console.print(Panel("[green]No violations recorded.[/green]", title="Top Violations"))

        # --- Recent events table ---
        if data.recent_events:
            events_table = Table(
                "Event",
                "Details",
                title="Recent Events",
                show_header=True,
                header_style="bold yellow",
                expand=True,
            )
            for event_dict in data.recent_events[:10]:
                event_type = event_dict.get("event", "unknown")
                details = ", ".join(
                    f"{k}={v}" for k, v in event_dict.items() if k != "event"
                )
                events_table.add_row(event_type, details)
            console.print(events_table)
        else:
            console.print(Panel("[dim]No recent events.[/dim]", title="Recent Events"))

        return output_buffer.getvalue()

    # ------------------------------------------------------------------
    # Plain tabular rendering
    # ------------------------------------------------------------------

    def render_table(self, data: DashboardData) -> str:
        """Render a plain-text tabular governance dashboard summary.

        Suitable for environments that do not support ANSI colour codes,
        such as CI log output or file redirection.

        Parameters
        ----------
        data:
            The aggregated governance metrics to display.

        Returns
        -------
        str
            Multi-line plain-text table.
        """
        pass_pct = (
            round(data.pass_count / data.total_evaluations * 100, 1)
            if data.total_evaluations > 0
            else 0.0
        )
        sep = "-" * 50
        lines: list[str] = [
            sep,
            " GOVERNANCE DASHBOARD",
            sep,
            f"  Total Evaluations : {data.total_evaluations}",
            f"  Pass Count        : {data.pass_count} ({pass_pct}%)",
            f"  Fail Count        : {data.fail_count}",
            f"  Pending Approvals : {data.pending_approvals}",
            f"  Active Agents     : {data.active_agents}",
            f"  Total Cost (USD)  : ${data.total_cost_usd:.4f}",
            sep,
        ]

        if data.top_violations:
            lines.append(" TOP VIOLATIONS")
            lines.append(sep)
            for rule_id, count in data.top_violations:
                lines.append(f"  {rule_id:<20} {count} occurrences")
            lines.append(sep)
        else:
            lines.append("  No violations recorded.")
            lines.append(sep)

        if data.recent_events:
            lines.append(" RECENT EVENTS (last 10)")
            lines.append(sep)
            for event_dict in data.recent_events[:10]:
                event_type = event_dict.get("event", "unknown")
                details = " | ".join(
                    f"{k}={v}" for k, v in event_dict.items() if k != "event"
                )
                lines.append(f"  [{event_type}] {details}")
            lines.append(sep)
        else:
            lines.append("  No recent events.")
            lines.append(sep)

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # JSON rendering
    # ------------------------------------------------------------------

    def render_json(self, data: DashboardData) -> str:
        """Render the dashboard data as a compact JSON string.

        Parameters
        ----------
        data:
            The aggregated governance metrics to serialise.

        Returns
        -------
        str
            JSON-encoded string with all dashboard fields.
        """
        payload: dict[str, object] = {
            "total_evaluations": data.total_evaluations,
            "pass_count": data.pass_count,
            "fail_count": data.fail_count,
            "pending_approvals": data.pending_approvals,
            "total_cost_usd": data.total_cost_usd,
            "active_agents": data.active_agents,
            "top_violations": [
                {"rule_id": rule_id, "count": count}
                for rule_id, count in data.top_violations
            ],
            "recent_events": list(data.recent_events),
        }
        return json.dumps(payload, indent=2)
