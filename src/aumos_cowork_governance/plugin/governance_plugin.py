"""GovernancePlugin — main entry point for Cowork integration.

The plugin wires together all governance subsystems (policy engine,
audit logger, PII detector, cost tracker, approval queue) and exposes
a simple lifecycle API:

- ``load_config(path)``   — load governance YAML
- ``pre_action(context)``  — evaluate before the agent acts
- ``post_action(context, result)`` — log and check after
- ``get_status()``         — return a governance health summary

Example
-------
>>> plugin = GovernancePlugin()
>>> plugin.load_config(Path("governance.yaml"))
>>> outcome = plugin.pre_action({"action": "file_read", "path": "/data/report.csv"})
>>> outcome["allowed"]
True
"""
from __future__ import annotations

import logging
from pathlib import Path

from aumos_cowork_governance.approval.gate import ApprovalGate
from aumos_cowork_governance.approval.notifier import ApprovalNotifier
from aumos_cowork_governance.approval.queue import ApprovalQueue
from aumos_cowork_governance.approval.timeout import TimeoutHandler
from aumos_cowork_governance.audit.logger import AuditLogger
from aumos_cowork_governance.audit.rotator import LogRotator
from aumos_cowork_governance.cost.alerts import AlertManager
from aumos_cowork_governance.cost.budget import BudgetManager
from aumos_cowork_governance.cost.tracker import CostTracker
from aumos_cowork_governance.dashboard.api import DashboardApi
from aumos_cowork_governance.dashboard.server import DashboardServer
from aumos_cowork_governance.detection.pii_detector import PiiDetector
from aumos_cowork_governance.detection.redactor import PiiRedactor
from aumos_cowork_governance.plugin.config_loader import ConfigLoader, GovernanceConfig
from aumos_cowork_governance.policies.actions import PolicyActionHandler, PolicyBlockedError
from aumos_cowork_governance.policies.engine import EvaluationResult, PolicyEngine

logger = logging.getLogger(__name__)


class GovernancePlugin:
    """Main plugin class for Cowork governance integration.

    Instantiate once per process and call :meth:`load_config` before
    any other method.

    Parameters
    ----------
    config_loader:
        Optional :class:`ConfigLoader` override (for testing).
    """

    def __init__(
        self,
        config_loader: ConfigLoader | None = None,
    ) -> None:
        self._config_loader = config_loader or ConfigLoader()
        self._config: GovernanceConfig | None = None

        # Subsystem instances — initialised in load_config.
        self._audit: AuditLogger | None = None
        self._rotator: LogRotator | None = None
        self._pii_detector: PiiDetector | None = None
        self._redactor: PiiRedactor | None = None
        self._engine: PolicyEngine | None = None
        self._action_handler: PolicyActionHandler | None = None
        self._cost_tracker: CostTracker | None = None
        self._budget_manager: BudgetManager | None = None
        self._alert_manager: AlertManager | None = None
        self._approval_queue: ApprovalQueue | None = None
        self._approval_gate: ApprovalGate | None = None
        self._timeout_handler: TimeoutHandler | None = None
        self._notifier: ApprovalNotifier | None = None
        self._dashboard_server: DashboardServer | None = None

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def load_config(self, path: str | Path) -> None:
        """Load and apply a governance YAML configuration.

        Parameters
        ----------
        path:
            Path to ``governance.yaml``.

        Raises
        ------
        FileNotFoundError:
            When the config file does not exist.
        """
        self._config = self._config_loader.load(Path(path))
        self._init_subsystems()
        logger.info("GovernancePlugin loaded config from %s", path)

    def load_config_defaults(self) -> None:
        """Initialise with all-default configuration (no file required)."""
        self._config = self._config_loader.defaults()
        self._init_subsystems()

    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------

    def pre_action(self, action_context: dict[str, object]) -> dict[str, object]:
        """Evaluate governance policies before an agent action executes.

        This is the primary gate.  Returns a result dict describing whether
        the action is allowed, requires approval, or is blocked.

        Parameters
        ----------
        action_context:
            Dict describing the action (e.g., ``action``, ``path``,
            ``content``, ``url``, ``tokens``, ``cost_usd``).

        Returns
        -------
        dict[str, object]
            Keys: ``allowed``, ``requires_approval``, ``blocking_policy``,
            ``results``, ``redacted_content``.
        """
        self._ensure_initialised()
        assert self._engine is not None
        assert self._action_handler is not None
        assert self._audit is not None

        # Expire stale approval requests before evaluation.
        if self._timeout_handler is not None:
            self._timeout_handler.expire_stale()

        # Optionally redact PII from content before evaluation.
        redacted_content: str | None = None
        if self._config is not None and self._config.pii.redact_on_warn:
            content = action_context.get("content")
            if isinstance(content, str) and self._redactor is not None:
                redacted_content, _ = self._redactor.redact_with_report(content)

        eval_result: EvaluationResult = self._engine.evaluate(action_context)

        # Execute side-effects for all matched policies (stops at BLOCK).
        try:
            self._action_handler.execute_all(eval_result.results, action_context)
        except PolicyBlockedError as exc:
            return {
                "allowed": False,
                "requires_approval": False,
                "blocking_policy": exc.policy_name,
                "message": exc.message,
                "results": [
                    {
                        "policy": r.policy_name,
                        "matched": r.matched,
                        "action": r.action.value,
                        "message": r.message,
                    }
                    for r in eval_result.results
                ],
                "redacted_content": redacted_content,
            }

        # Check budget before allowing.
        if self._budget_manager is not None:
            budget_status = self._budget_manager.check()
            if not budget_status.within_budget:
                exceeded = ", ".join(budget_status.exceeded_periods)
                self._audit.log(
                    {
                        "event": "budget_exceeded",
                        "exceeded_periods": budget_status.exceeded_periods,
                        "action_context": action_context,
                    }
                )
                return {
                    "allowed": False,
                    "requires_approval": False,
                    "blocking_policy": "budget-exceeded",
                    "message": f"Budget exceeded for periods: {exceeded}",
                    "results": [],
                    "redacted_content": redacted_content,
                }

        return {
            "allowed": eval_result.allowed,
            "requires_approval": eval_result.requires_approval,
            "blocking_policy": eval_result.blocking_policy,
            "message": "",
            "results": [
                {
                    "policy": r.policy_name,
                    "matched": r.matched,
                    "action": r.action.value,
                    "message": r.message,
                }
                for r in eval_result.results
            ],
            "redacted_content": redacted_content,
        }

    def post_action(
        self,
        action_context: dict[str, object],
        result: dict[str, object],
    ) -> None:
        """Log and check after an agent action completes.

        Logs the completed action to the audit trail and records any
        API cost data present in the result dict.

        Parameters
        ----------
        action_context:
            The same context passed to :meth:`pre_action`.
        result:
            The action result dict.  May include ``cost_usd``,
            ``input_tokens``, ``output_tokens``, ``model`` keys.
        """
        self._ensure_initialised()
        assert self._audit is not None

        self._audit.log(
            {
                "event": "action_completed",
                "action_context": action_context,
                "result_summary": {
                    k: v
                    for k, v in result.items()
                    if k not in {"content", "raw_output"}
                },
            }
        )

        # Record API cost if present.
        if self._cost_tracker is not None:
            cost_usd = result.get("cost_usd")
            if cost_usd is not None:
                try:
                    self._cost_tracker.record(
                        task_id=str(action_context.get("task_id", "unknown")),
                        model=str(result.get("model", "unknown")),
                        input_tokens=int(result.get("input_tokens", 0)),  # type: ignore[arg-type]
                        output_tokens=int(result.get("output_tokens", 0)),  # type: ignore[arg-type]
                        cost_usd=float(cost_usd),  # type: ignore[arg-type]
                    )
                except (TypeError, ValueError):
                    pass

        # Check budget alerts.
        if self._alert_manager is not None:
            self._alert_manager.check_and_notify()

    def get_status(self) -> dict[str, object]:
        """Return a governance health summary.

        Returns
        -------
        dict[str, object]
            Status dict with ``initialised``, ``audit_count``,
            ``policy_count``, ``pending_approvals``, ``total_cost_usd``.
        """
        if self._audit is None:
            return {"initialised": False}

        audit_count = self._audit.count()
        policy_count = len(self._engine._policies) if self._engine else 0  # type: ignore[attr-defined]
        pending_approvals = (
            self._approval_queue.count_pending() if self._approval_queue else 0
        )
        total_cost = self._cost_tracker.total_cost_usd() if self._cost_tracker else 0.0

        return {
            "initialised": True,
            "audit_count": audit_count,
            "policy_count": policy_count,
            "pending_approvals": pending_approvals,
            "total_cost_usd": total_cost,
        }

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------

    def start_dashboard(
        self,
        host: str | None = None,
        port: int | None = None,
        background: bool = True,
    ) -> str:
        """Start the local governance dashboard.

        Parameters
        ----------
        host:
            Bind address (overrides config).
        port:
            Port (overrides config).
        background:
            When ``True`` (default), run in a background thread.

        Returns
        -------
        str
            Dashboard URL.
        """
        self._ensure_initialised()
        cfg = self._config.dashboard if self._config else None
        effective_host = host or (cfg.host if cfg else "127.0.0.1")
        effective_port = port or (cfg.port if cfg else 8080)

        api = DashboardApi(
            audit_logger=self._audit,
            policy_engine=self._engine,
            cost_tracker=self._cost_tracker,
            approval_queue=self._approval_queue,
        )
        self._dashboard_server = DashboardServer(api=api, host=effective_host, port=effective_port)

        if background:
            self._dashboard_server.start_background()
        else:
            self._dashboard_server.start()

        return self._dashboard_server.url

    def stop_dashboard(self) -> None:
        """Stop the dashboard server."""
        if self._dashboard_server is not None:
            self._dashboard_server.stop()
            self._dashboard_server = None

    # ------------------------------------------------------------------
    # Properties for direct subsystem access
    # ------------------------------------------------------------------

    @property
    def audit(self) -> AuditLogger | None:
        """The audit logger instance."""
        return self._audit

    @property
    def engine(self) -> PolicyEngine | None:
        """The policy engine instance."""
        return self._engine

    @property
    def cost_tracker(self) -> CostTracker | None:
        """The cost tracker instance."""
        return self._cost_tracker

    @property
    def approval_queue(self) -> ApprovalQueue | None:
        """The approval queue instance."""
        return self._approval_queue

    @property
    def pii_detector(self) -> PiiDetector | None:
        """The PII detector instance."""
        return self._pii_detector

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_subsystems(self) -> None:
        """Initialise all governance subsystems from the loaded config."""
        assert self._config is not None

        # Audit trail.
        self._audit = AuditLogger(log_path=self._config.audit.log_path)
        self._rotator = LogRotator(
            log_dir=self._config.audit.log_path.parent,
            retention_days=self._config.audit.retention_days,
        )
        if self._config.audit.rotation_enabled:
            self._rotator.rotate_if_needed()

        # PII detection.
        self._pii_detector = PiiDetector(jurisdictions=self._config.pii.jurisdictions)
        self._redactor = PiiRedactor(detector=self._pii_detector)

        # Policy engine.
        self._engine = PolicyEngine(pii_detector=self._pii_detector.contains_pii)
        if self._config.policies:
            self._engine.load_from_dict({"policies": self._config.policies})
        for policy_file in self._config.policy_files:
            policy_path = Path(policy_file)
            if policy_path.exists():
                self._engine.load(policy_path)

        # Approval subsystem.
        self._approval_queue = ApprovalQueue()
        self._approval_gate = ApprovalGate(
            queue=self._approval_queue,
            timeout_seconds=self._config.approval.timeout_seconds,
        )
        self._timeout_handler = TimeoutHandler(
            queue=self._approval_queue,
            default_timeout_seconds=self._config.approval.timeout_seconds,
        )
        self._notifier = ApprovalNotifier(
            webhook_url=self._config.approval.webhook_url,
            webhook_format=self._config.approval.webhook_format,
        )

        # Cost tracking.
        self._cost_tracker = CostTracker()
        self._budget_manager = BudgetManager(
            tracker=self._cost_tracker,
            daily_usd=self._config.cost.daily_budget_usd,
            weekly_usd=self._config.cost.weekly_budget_usd,
            monthly_usd=self._config.cost.monthly_budget_usd,
        )
        self._alert_manager = AlertManager(
            budget_manager=self._budget_manager,
            thresholds=self._config.cost.alert_thresholds_pct,
            webhook_url=self._config.cost.webhook_url,
        )

        # Policy action handler wired to audit and approval queue.
        self._action_handler = PolicyActionHandler(
            audit_logger=self._audit,
            approval_queue=self._approval_queue,
        )

    def _ensure_initialised(self) -> None:
        """Raise if the plugin has not been initialised via load_config."""
        if self._config is None:
            raise RuntimeError(
                "GovernancePlugin is not initialised. Call load_config() first."
            )
