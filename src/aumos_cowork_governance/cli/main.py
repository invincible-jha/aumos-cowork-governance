"""CLI entry point for aumos-cowork-governance.

Invoked as::

    cowork-gov [OPTIONS] COMMAND [ARGS]...

or during development::

    python -m aumos_cowork_governance.cli.main

Commands
--------
- init             Initialise a project with a governance policy pack
- check            Evaluate an action JSON against loaded policies
- audit show       Display recent audit entries
- audit export     Export audit data to CSV or JSON
- cost status      Show current cost tracking status
- cost report      Generate a cost usage report
- compliance check Run a compliance checklist
- dashboard        Start the local governance dashboard
- version          Show version information
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()
err_console = Console(stderr=True)

_DEFAULT_CONFIG = Path("governance.yaml")

# ---------------------------------------------------------------------------
# Preset policy pack file lists
# ---------------------------------------------------------------------------
_PRESETS: dict[str, list[str]] = {
    "startup": ["pii_protection", "file_access_control", "cost_limits"],
    "enterprise": [
        "pii_protection",
        "file_access_control",
        "cost_limits",
        "data_classification",
        "soc2_basic",
    ],
    "healthcare": [
        "pii_protection",
        "file_access_control",
        "cost_limits",
        "data_classification",
        "hipaa_basic",
    ],
    "finance": [
        "pii_protection",
        "file_access_control",
        "cost_limits",
        "data_classification",
        "soc2_basic",
        "gdpr_basic",
    ],
}


# ---------------------------------------------------------------------------
# Root command group
# ---------------------------------------------------------------------------


@click.group()
@click.version_option(package_name="aumos-cowork-governance")
def cli() -> None:
    """Cowork Governance CLI — policy, audit, cost, and compliance tools."""


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


@cli.command(name="version")
def version_command() -> None:
    """Show detailed version information."""
    from aumos_cowork_governance import __version__

    console.print(
        Panel(
            f"[bold]aumos-cowork-governance[/bold]  v[cyan]{__version__}[/cyan]\n"
            "Python governance plugin for Cowork agent environments.",
            title="Version",
            border_style="blue",
        )
    )


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


@cli.command(name="init")
@click.option(
    "--preset",
    type=click.Choice(["startup", "enterprise", "healthcare", "finance"]),
    default="startup",
    show_default=True,
    help="Policy pack preset to initialise with.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="governance.yaml",
    show_default=True,
    help="Output governance config file path.",
)
def init_command(preset: str, output: str) -> None:
    """Initialise a project with a governance policy pack."""
    import importlib.resources

    output_path = Path(output)
    template_names = _PRESETS.get(preset, _PRESETS["startup"])

    # Build inline policy list from template files.
    import yaml
    import importlib.resources as pkg

    all_policies: list[dict[str, object]] = []
    templates_pkg = "aumos_cowork_governance.policies.templates"
    for template_name in template_names:
        try:
            ref = pkg.files(templates_pkg).joinpath(f"{template_name}.yaml")
            raw_text = ref.read_text(encoding="utf-8")
            template_data: dict[str, object] = yaml.safe_load(raw_text) or {}
            policies = template_data.get("policies", [])
            all_policies.extend(policies)  # type: ignore[arg-type]
        except Exception as exc:
            err_console.print(f"[yellow]Warning:[/yellow] Could not load template '{template_name}': {exc}")

    config: dict[str, object] = {
        "version": "1",
        "preset": preset,
        "policies": all_policies,
        "audit": {
            "log_path": "./governance_audit.jsonl",
            "rotation_enabled": True,
            "retention_days": 90,
        },
        "cost": {
            "daily_budget_usd": 50.0,
            "weekly_budget_usd": 200.0,
            "monthly_budget_usd": 500.0,
            "alert_thresholds_pct": [50, 80, 100],
        },
        "pii": {
            "jurisdictions": ["common", "us"],
            "redact_on_warn": False,
        },
        "approval": {
            "timeout_seconds": 300,
            "webhook_format": "generic",
        },
        "dashboard": {
            "enabled": False,
            "host": "127.0.0.1",
            "port": 8080,
        },
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        yaml.dump(config, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)

    console.print(f"[green]Initialised[/green] governance config: [bold]{output_path}[/bold]")
    console.print(f"  Preset: [cyan]{preset}[/cyan]")
    console.print(f"  Policies loaded: [cyan]{len(all_policies)}[/cyan]")


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


@cli.command(name="check")
@click.option(
    "--action",
    "-a",
    "action_json",
    required=True,
    help='Action context as JSON string, e.g. \'{"action": "file_read", "path": "/data/x.csv"}\'.',
)
@click.option(
    "--config",
    "-c",
    "config_path",
    default=str(_DEFAULT_CONFIG),
    show_default=True,
    type=click.Path(exists=True),
    help="Path to governance.yaml.",
)
def check_command(action_json: str, config_path: str) -> None:
    """Evaluate an action context JSON against governance policies."""
    try:
        action_context: dict[str, object] = json.loads(action_json)
    except json.JSONDecodeError as exc:
        err_console.print(f"[red]Invalid JSON:[/red] {exc}")
        sys.exit(1)

    from aumos_cowork_governance.plugin.governance_plugin import GovernancePlugin

    plugin = GovernancePlugin()
    plugin.load_config(Path(config_path))
    outcome = plugin.pre_action(action_context)

    allowed = outcome.get("allowed", False)
    requires_approval = outcome.get("requires_approval", False)
    blocking_policy = outcome.get("blocking_policy")

    if allowed and not requires_approval:
        status_str = "[green]ALLOWED[/green]"
    elif requires_approval:
        status_str = "[yellow]REQUIRES APPROVAL[/yellow]"
    else:
        status_str = "[red]BLOCKED[/red]"

    console.print(Panel(status_str, title="Policy Check Result", border_style="blue"))

    if blocking_policy:
        console.print(f"  Blocking policy: [bold red]{blocking_policy}[/bold red]")
    if outcome.get("message"):
        console.print(f"  Message: {outcome['message']}")

    results: list[dict[str, object]] = list(outcome.get("results", []))  # type: ignore[arg-type]
    matched = [r for r in results if r.get("matched")]
    if matched:
        table = Table(title="Matched Policies", box=box.SIMPLE)
        table.add_column("Policy", style="cyan")
        table.add_column("Action", style="magenta")
        table.add_column("Message")
        for r in matched:
            table.add_row(str(r.get("policy", "")), str(r.get("action", "")), str(r.get("message", "")))
        console.print(table)

    sys.exit(0 if allowed else 1)


# ---------------------------------------------------------------------------
# audit group
# ---------------------------------------------------------------------------


@cli.group(name="audit")
def audit_group() -> None:
    """Audit trail commands."""


@audit_group.command(name="show")
@click.option("--last", "-n", default=20, show_default=True, type=int, help="Number of recent entries to show.")
@click.option(
    "--config",
    "-c",
    "config_path",
    default=str(_DEFAULT_CONFIG),
    type=click.Path(),
    help="Path to governance.yaml.",
)
def audit_show_command(last: int, config_path: str) -> None:
    """Show recent audit log entries."""
    from aumos_cowork_governance.plugin.config_loader import ConfigLoader

    loader = ConfigLoader()
    cfg_path = Path(config_path)
    if cfg_path.exists():
        config = loader.load(cfg_path)
    else:
        config = loader.defaults()

    from aumos_cowork_governance.audit.logger import AuditLogger

    audit = AuditLogger(log_path=config.audit.log_path)
    records = audit.last_n(last)

    if not records:
        console.print("[yellow]No audit entries found.[/yellow]")
        return

    table = Table(title=f"Last {last} Audit Events", box=box.SIMPLE)
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("Event", style="cyan")
    table.add_column("Policy", style="magenta")
    table.add_column("Message")

    for record in records:
        ts = str(record.get("timestamp", ""))[:19].replace("T", " ")
        event = str(record.get("event", ""))
        policy = str(record.get("policy", ""))
        message = str(record.get("message", ""))
        table.add_row(ts, event, policy, message)

    console.print(table)
    console.print(f"  Total audit records: [cyan]{audit.count()}[/cyan]")


@audit_group.command(name="export")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["csv", "json"]),
    default="csv",
    show_default=True,
    help="Export format.",
)
@click.option("--output", "-o", "output_file", required=True, type=click.Path(), help="Output file path.")
@click.option(
    "--config",
    "-c",
    "config_path",
    default=str(_DEFAULT_CONFIG),
    type=click.Path(),
    help="Path to governance.yaml.",
)
def audit_export_command(output_format: str, output_file: str, config_path: str) -> None:
    """Export audit data to CSV or JSON."""
    from aumos_cowork_governance.audit.exporter import AuditExporter
    from aumos_cowork_governance.audit.logger import AuditLogger
    from aumos_cowork_governance.plugin.config_loader import ConfigLoader

    loader = ConfigLoader()
    cfg_path = Path(config_path)
    config = loader.load(cfg_path) if cfg_path.exists() else loader.defaults()

    audit = AuditLogger(log_path=config.audit.log_path)
    exporter = AuditExporter(audit)
    out_path = Path(output_file)

    if output_format == "csv":
        count = exporter.to_csv(out_path)
    else:
        count = exporter.to_json(out_path)

    console.print(f"[green]Exported[/green] {count} records to [bold]{out_path}[/bold] ({output_format.upper()}).")


# ---------------------------------------------------------------------------
# cost group
# ---------------------------------------------------------------------------


@cli.group(name="cost")
def cost_group() -> None:
    """Cost tracking commands."""


@cost_group.command(name="status")
@click.option(
    "--config",
    "-c",
    "config_path",
    default=str(_DEFAULT_CONFIG),
    type=click.Path(),
    help="Path to governance.yaml.",
)
def cost_status_command(config_path: str) -> None:
    """Show current cost tracking status."""
    from aumos_cowork_governance.audit.logger import AuditLogger
    from aumos_cowork_governance.cost.tracker import CostTracker
    from aumos_cowork_governance.plugin.config_loader import ConfigLoader

    loader = ConfigLoader()
    cfg_path = Path(config_path)
    config = loader.load(cfg_path) if cfg_path.exists() else loader.defaults()

    # Reconstruct cost from audit log (cost records in post_action).
    audit = AuditLogger(log_path=config.audit.log_path)
    tracker = CostTracker()
    for record in audit.read_all():
        if record.get("event") == "action_completed":
            result_summary = record.get("result_summary", {})
            if isinstance(result_summary, dict):
                cost_usd = result_summary.get("cost_usd")
                if cost_usd is not None:
                    try:
                        tracker.record(
                            task_id=str(record.get("session_id", "unknown")),
                            model=str(result_summary.get("model", "unknown")),
                            input_tokens=int(result_summary.get("input_tokens", 0)),  # type: ignore[arg-type]
                            output_tokens=int(result_summary.get("output_tokens", 0)),  # type: ignore[arg-type]
                            cost_usd=float(cost_usd),  # type: ignore[arg-type]
                        )
                    except (TypeError, ValueError):
                        pass

    total = tracker.total_cost_usd()
    tokens = tracker.total_tokens()
    calls = len(tracker.all_records())

    table = Table(title="Cost Status", box=box.SIMPLE)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")
    table.add_row("Total Cost (USD)", f"${total:.4f}")
    table.add_row("Total Tokens", f"{tokens:,}")
    table.add_row("API Calls", str(calls))

    if config.cost.daily_budget_usd:
        pct = min(100.0, total / config.cost.daily_budget_usd * 100.0)
        colour = "red" if pct >= 100 else ("yellow" if pct >= 80 else "green")
        table.add_row(
            "Daily Budget",
            f"[{colour}]${total:.4f} / ${config.cost.daily_budget_usd:.2f} ({pct:.1f}%)[/{colour}]",
        )

    console.print(table)


@cost_group.command(name="report")
@click.option(
    "--period",
    "-p",
    type=click.Choice(["daily", "weekly", "monthly"]),
    default="daily",
    show_default=True,
    help="Reporting period.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    default=None,
    type=click.Path(),
    help="Output CSV file path (prints to console if omitted).",
)
@click.option(
    "--config",
    "-c",
    "config_path",
    default=str(_DEFAULT_CONFIG),
    type=click.Path(),
    help="Path to governance.yaml.",
)
def cost_report_command(period: str, output_file: str | None, config_path: str) -> None:
    """Generate a cost usage report."""
    from aumos_cowork_governance.cost.reporter import CostReporter
    from aumos_cowork_governance.cost.tracker import CostTracker
    from aumos_cowork_governance.plugin.config_loader import ConfigLoader

    loader = ConfigLoader()
    cfg_path = Path(config_path)
    config = loader.load(cfg_path) if cfg_path.exists() else loader.defaults()

    tracker = CostTracker()
    reporter = CostReporter(tracker)
    summary = reporter.summary(period=period)

    console.print(Panel(f"[bold]{period.upper()} Cost Report[/bold]", border_style="blue"))
    console.print(f"  Total cost:   [cyan]${float(summary['total_cost_usd']):.4f} USD[/cyan]")
    console.print(f"  Total tokens: [cyan]{int(summary['total_tokens']):,}[/cyan]")
    console.print(f"  API calls:    [cyan]{int(summary['call_count'])}[/cyan]")

    if output_file:
        out_path = Path(output_file)
        count = reporter.to_csv(out_path, period=period)
        console.print(f"  [green]Exported[/green] {count} records to {out_path}.")


# ---------------------------------------------------------------------------
# compliance group
# ---------------------------------------------------------------------------


@cli.group(name="compliance")
def compliance_group() -> None:
    """Compliance checklist commands."""


@compliance_group.command(name="check")
@click.option(
    "--framework",
    "-f",
    type=click.Choice(["soc2", "gdpr", "hipaa"]),
    default="soc2",
    show_default=True,
    help="Compliance framework to check against.",
)
@click.option(
    "--config",
    "-c",
    "config_path",
    default=str(_DEFAULT_CONFIG),
    type=click.Path(),
    help="Path to governance.yaml.",
)
def compliance_check_command(framework: str, config_path: str) -> None:
    """Run a compliance checklist for the specified framework."""
    from aumos_cowork_governance.audit.logger import AuditLogger
    from aumos_cowork_governance.audit.search import AuditSearch
    from aumos_cowork_governance.plugin.config_loader import ConfigLoader

    loader = ConfigLoader()
    cfg_path = Path(config_path)
    config = loader.load(cfg_path) if cfg_path.exists() else loader.defaults()

    audit = AuditLogger(log_path=config.audit.log_path)
    search = AuditSearch(audit)

    checklists: dict[str, list[tuple[str, str]]] = {
        "soc2": [
            ("Audit logging enabled", "audit_log"),
            ("Policy engine active", "policy_check"),
            ("Budget controls configured", "cost_budget"),
            ("Change approval gates", "approval_gate"),
            ("PII detection active", "pii_scan"),
        ],
        "gdpr": [
            ("PII detection active", "pii_scan"),
            ("Data subject access controls", "access_control"),
            ("Audit trail for data access", "audit_log"),
            ("Data retention policy configured", "retention_policy"),
            ("Cross-border transfer controls", "transfer_control"),
        ],
        "hipaa": [
            ("PHI access controls", "phi_access"),
            ("Audit trail for PHI access", "audit_log"),
            ("Encryption at rest configured", "encryption"),
            ("Minimum necessary access", "access_control"),
            ("Business Associate Agreement tracking", "baa_tracking"),
        ],
    }

    items = checklists.get(framework, [])
    audit_count = audit.count()
    policy_blocks = search.by_event("policy_block")
    policy_warns = search.by_event("policy_warn")

    table = Table(title=f"{framework.upper()} Compliance Checklist", box=box.SIMPLE)
    table.add_column("Item", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Notes")

    for item_label, item_key in items:
        if item_key == "audit_log":
            ok = audit_count > 0
            status = "[green]PASS[/green]" if ok else "[red]FAIL[/red]"
            notes = f"{audit_count} audit records"
        elif item_key in ("policy_check", "phi_access", "access_control"):
            ok = cfg_path.exists()
            status = "[green]PASS[/green]" if ok else "[yellow]WARN[/yellow]"
            notes = "Policy file loaded" if ok else "No governance.yaml found"
        elif item_key == "cost_budget":
            ok = (
                config.cost.daily_budget_usd is not None
                or config.cost.monthly_budget_usd is not None
            )
            status = "[green]PASS[/green]" if ok else "[yellow]WARN[/yellow]"
            notes = "Budget limits configured" if ok else "No budget limits set"
        elif item_key == "approval_gate":
            ok = True  # Approval gate is always available in plugin.
            status = "[green]PASS[/green]"
            notes = "Approval gate available"
        elif item_key == "pii_scan":
            ok = "common" in config.pii.jurisdictions or "us" in config.pii.jurisdictions
            status = "[green]PASS[/green]" if ok else "[yellow]WARN[/yellow]"
            notes = f"Jurisdictions: {', '.join(config.pii.jurisdictions)}"
        else:
            status = "[yellow]MANUAL[/yellow]"
            notes = "Manual verification required"

        table.add_row(item_label, status, notes)

    console.print(table)
    console.print(f"\n  Policy blocks: [red]{len(policy_blocks)}[/red]")
    console.print(f"  Policy warnings: [yellow]{len(policy_warns)}[/yellow]")


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


@cli.command(name="dashboard")
@click.option("--port", "-p", default=8080, show_default=True, type=int, help="Port to listen on.")
@click.option("--host", "-h", "host", default="127.0.0.1", show_default=True, help="Bind address.")
@click.option(
    "--config",
    "-c",
    "config_path",
    default=str(_DEFAULT_CONFIG),
    type=click.Path(),
    help="Path to governance.yaml.",
)
def dashboard_command(port: int, host: str, config_path: str) -> None:
    """Start the local governance dashboard."""
    from aumos_cowork_governance.audit.logger import AuditLogger
    from aumos_cowork_governance.dashboard.api import DashboardApi
    from aumos_cowork_governance.dashboard.server import DashboardServer
    from aumos_cowork_governance.plugin.config_loader import ConfigLoader
    from aumos_cowork_governance.policies.engine import PolicyEngine

    loader = ConfigLoader()
    cfg_path = Path(config_path)
    config = loader.load(cfg_path) if cfg_path.exists() else loader.defaults()

    audit = AuditLogger(log_path=config.audit.log_path)
    engine = PolicyEngine()
    if config.policies:
        engine.load_from_dict({"policies": config.policies})

    api = DashboardApi(audit_logger=audit, policy_engine=engine)
    server = DashboardServer(api=api, host=host, port=port)

    console.print(
        Panel(
            f"Starting governance dashboard at [link=http://{host}:{port}/]http://{host}:{port}/[/link]\n"
            "Press Ctrl-C to stop.",
            title="Dashboard",
            border_style="green",
        )
    )
    server.start()


# ---------------------------------------------------------------------------
# constitution group
# ---------------------------------------------------------------------------


@cli.group(name="constitution")
def constitution_group() -> None:
    """Multi-agent constitution commands."""


@constitution_group.command(name="validate")
@click.option(
    "--file",
    "-f",
    "constitution_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to a constitution YAML file.",
)
def constitution_validate_command(constitution_file: str) -> None:
    """Validate a constitution YAML file for internal consistency."""
    from aumos_cowork_governance.constitution.schema import Constitution

    try:
        raw_text = Path(constitution_file).read_text(encoding="utf-8")
        constitution = Constitution.from_yaml(raw_text)
    except Exception as exc:
        err_console.print(f"[red]Parse error:[/red] {exc}")
        sys.exit(1)

    errors = constitution.validate_constitution()

    if not errors:
        console.print(
            Panel(
                f"[green]VALID[/green]  '{constitution.team_name}' v{constitution.version}\n"
                f"  Roles: {len(constitution.roles)}  "
                f"Constraints: {len(constitution.constraints)}  "
                f"Escalation rules: {len(constitution.escalation_rules)}",
                title="Constitution Validation",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"[red]INVALID[/red]  '{constitution.team_name}' — {len(errors)} error(s)",
                title="Constitution Validation",
                border_style="red",
            )
        )
        for error in errors:
            console.print(f"  [red]•[/red] {error}")
        sys.exit(1)


@constitution_group.command(name="check")
@click.option(
    "--file",
    "-f",
    "constitution_file",
    required=True,
    type=click.Path(exists=True),
    help="Path to a constitution YAML file.",
)
@click.option(
    "--role",
    "-r",
    required=True,
    help="Role name to check.",
)
@click.option(
    "--action",
    "-a",
    "action_type",
    required=True,
    type=click.Choice(["tool_call", "budget_spend", "delegation", "data_access", "escalation"]),
    help="Action type to check.",
)
@click.option(
    "--detail",
    "-d",
    "detail_pairs",
    multiple=True,
    help="Detail key=value pairs (e.g. --detail tool_name=read_file).",
)
def constitution_check_command(
    constitution_file: str,
    role: str,
    action_type: str,
    detail_pairs: tuple[str, ...],
) -> None:
    """Check whether a role is permitted to perform an action under a constitution."""
    from datetime import datetime, timezone

    from aumos_cowork_governance.constitution.enforcer import (
        ActionType,
        AgentAction,
        ConstitutionEnforcer,
    )
    from aumos_cowork_governance.constitution.schema import Constitution

    try:
        raw_text = Path(constitution_file).read_text(encoding="utf-8")
        constitution = Constitution.from_yaml(raw_text)
    except Exception as exc:
        err_console.print(f"[red]Parse error:[/red] {exc}")
        sys.exit(1)

    details: dict[str, object] = {}
    for pair in detail_pairs:
        if "=" in pair:
            key, _, value = pair.partition("=")
            details[key.strip()] = value.strip()

    try:
        parsed_action_type = ActionType(action_type)
    except ValueError:
        err_console.print(f"[red]Unknown action type:[/red] {action_type}")
        sys.exit(1)

    action = AgentAction(
        agent_id="cli-check",
        role=role,
        action_type=parsed_action_type,
        details=details,
        timestamp=datetime.now(tz=timezone.utc),
    )

    enforcer = ConstitutionEnforcer(constitution)
    result = enforcer.evaluate(action)

    status_str = "[green]ALLOWED[/green]" if result.allowed else "[red]DENIED[/red]"
    console.print(Panel(status_str, title="Constitution Check", border_style="blue"))
    console.print(f"  Role:   [cyan]{role}[/cyan]")
    console.print(f"  Action: [cyan]{action_type}[/cyan]")

    if result.violations:
        console.print("\n  [red]Violations:[/red]")
        for violation in result.violations:
            console.print(f"    • {violation}")

    if result.warnings:
        console.print("\n  [yellow]Warnings:[/yellow]")
        for warning in result.warnings:
            console.print(f"    • {warning}")

    if result.applied_constraints:
        console.print(f"\n  Applied constraints: {', '.join(result.applied_constraints)}")

    sys.exit(0 if result.allowed else 1)


@constitution_group.command(name="init")
@click.option(
    "--team-name",
    "-t",
    "team_name",
    required=True,
    help="Name of the team for the starter constitution.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    required=True,
    type=click.Path(),
    help="Output YAML file path.",
)
def constitution_init_command(team_name: str, output_file: str) -> None:
    """Generate a starter constitution YAML for a team."""
    from aumos_cowork_governance.constitution.schema import Constitution

    constitution = Constitution.starter(team_name)
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(constitution.to_yaml(), encoding="utf-8")

    console.print(
        Panel(
            f"[green]Created[/green] starter constitution for team '{team_name}'\n"
            f"  File:  [bold]{output_path}[/bold]\n"
            f"  Roles: {', '.join(r.name for r in constitution.roles)}",
            title="Constitution Init",
            border_style="green",
        )
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cli()
