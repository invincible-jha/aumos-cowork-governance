"""REST API layer for the governance dashboard.

DashboardApi collects data from the runtime components (audit logger,
policy engine, cost tracker, approval queue) and serialises it into
plain Python dicts suitable for JSON serialisation.

The HTTP server calls these methods to build response bodies.

Endpoints
---------
GET /api/audit     — recent audit entries
GET /api/policies  — loaded policy list
GET /api/costs     — cost summary
GET /api/status    — governance health summary
GET /api/approvals — pending approval requests

Example
-------
>>> api = DashboardApi(audit_logger=audit, cost_tracker=tracker)
>>> api.get_status()
{'healthy': True, 'audit_count': 42, ...}
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aumos_cowork_governance.approval.queue import ApprovalQueue
    from aumos_cowork_governance.audit.logger import AuditLogger
    from aumos_cowork_governance.cost.tracker import CostTracker
    from aumos_cowork_governance.policies.engine import PolicyEngine


class DashboardApi:
    """Provides data aggregation for dashboard REST endpoints.

    All component parameters are optional.  When omitted, the
    corresponding endpoint returns an empty or default response.

    Parameters
    ----------
    audit_logger:
        Optional :class:`AuditLogger` instance.
    policy_engine:
        Optional :class:`PolicyEngine` instance.
    cost_tracker:
        Optional :class:`CostTracker` instance.
    approval_queue:
        Optional :class:`ApprovalQueue` instance.
    """

    def __init__(
        self,
        audit_logger: "AuditLogger | None" = None,
        policy_engine: "PolicyEngine | None" = None,
        cost_tracker: "CostTracker | None" = None,
        approval_queue: "ApprovalQueue | None" = None,
    ) -> None:
        self._audit = audit_logger
        self._engine = policy_engine
        self._costs = cost_tracker
        self._approvals = approval_queue

    # ------------------------------------------------------------------
    # Endpoint data methods
    # ------------------------------------------------------------------

    def get_audit(self, last_n: int = 100) -> dict[str, object]:
        """Return recent audit log entries.

        Parameters
        ----------
        last_n:
            Maximum number of recent entries to return.

        Returns
        -------
        dict[str, object]
            ``{"entries": [...], "total": N}``
        """
        if self._audit is None:
            return {"entries": [], "total": 0}
        all_records = self._audit.read_all()
        recent = all_records[-last_n:] if len(all_records) > last_n else all_records
        return {"entries": recent, "total": len(all_records)}

    def get_policies(self) -> dict[str, object]:
        """Return the loaded policy list.

        Returns
        -------
        dict[str, object]
            ``{"policies": [...], "count": N}``
        """
        if self._engine is None:
            return {"policies": [], "count": 0}
        policies = list(self._engine._policies)  # type: ignore[attr-defined]
        return {"policies": policies, "count": len(policies)}

    def get_costs(self) -> dict[str, object]:
        """Return cost tracking summary.

        Returns
        -------
        dict[str, object]
            Summary with totals and per-model breakdown.
        """
        if self._costs is None:
            return {
                "total_cost_usd": 0.0,
                "total_tokens": 0,
                "call_count": 0,
                "by_model": {},
                "by_task": {},
            }
        all_records = self._costs.all_records()
        total_cost = sum(r.cost_usd for r in all_records)
        total_tokens = sum(r.total_tokens for r in all_records)
        by_model: dict[str, float] = {}
        by_task: dict[str, float] = {}
        for record in all_records:
            by_model[record.model] = by_model.get(record.model, 0.0) + record.cost_usd
            by_task[record.task_id] = by_task.get(record.task_id, 0.0) + record.cost_usd

        return {
            "total_cost_usd": round(total_cost, 6),
            "total_tokens": total_tokens,
            "call_count": len(all_records),
            "by_model": by_model,
            "by_task": by_task,
        }

    def get_status(self) -> dict[str, object]:
        """Return a governance health summary.

        Returns
        -------
        dict[str, object]
            Aggregate health status dict.
        """
        now = datetime.now(tz=timezone.utc).isoformat()
        audit_count = self._audit.count() if self._audit else 0
        policy_count = len(self._engine._policies) if self._engine else 0  # type: ignore[attr-defined]
        pending_approvals = self._approvals.count_pending() if self._approvals else 0
        cost_data = self.get_costs()

        return {
            "healthy": True,
            "timestamp": now,
            "audit_count": audit_count,
            "policy_count": policy_count,
            "pending_approvals": pending_approvals,
            "total_cost_usd": cost_data.get("total_cost_usd", 0.0),
        }

    def get_approvals(self) -> dict[str, object]:
        """Return pending approval requests.

        Returns
        -------
        dict[str, object]
            ``{"pending": [...], "count": N}``
        """
        if self._approvals is None:
            return {"pending": [], "count": 0}
        pending = self._approvals.pending()
        serialised: list[dict[str, object]] = []
        for req in pending:
            serialised.append(
                {
                    "request_id": req.request_id,
                    "policy_name": req.policy_name,
                    "message": req.message,
                    "created_at": req.created_at.isoformat(),
                    "notify": req.notify,
                    "action_context": req.action_context,
                }
            )
        return {"pending": serialised, "count": len(serialised)}

    def to_json(self, data: dict[str, object]) -> str:
        """Serialise a data dict to a JSON string.

        Parameters
        ----------
        data:
            The data dict to serialise.

        Returns
        -------
        str
            JSON string.
        """
        return json.dumps(data, default=str)
