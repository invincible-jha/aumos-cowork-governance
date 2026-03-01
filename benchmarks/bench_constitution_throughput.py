"""Benchmark: Constitution enforcement throughput — evaluations per second.

Measures how many ConstitutionEnforcer.evaluate() calls can be completed per
second using a multi-role constitution with tool access and budget constraints.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aumos_cowork_governance.constitution.enforcer import (
    ActionType,
    AgentAction,
    ConstitutionEnforcer,
)
from aumos_cowork_governance.constitution.schema import (
    ConflictStrategy,
    Constitution,
    Permission,
    RoleDefinition,
)

_ITERATIONS: int = 10_000


def _make_constitution() -> Constitution:
    """Build a realistic multi-role constitution for benchmarking."""
    return Constitution(
        team_name="bench-team",
        description="Benchmark constitution",
        conflict_strategy=ConflictStrategy.PRIORITY_BASED,
        roles=[
            RoleDefinition(
                name="orchestrator",
                permissions=[
                    Permission.READ,
                    Permission.WRITE,
                    Permission.DELEGATE,
                    Permission.APPROVE,
                ],
                max_budget_usd=1000.0,
                allowed_tools=["*"],
                denied_tools=["delete_*"],
            ),
            RoleDefinition(
                name="worker",
                permissions=[Permission.READ, Permission.EXECUTE],
                max_budget_usd=50.0,
                allowed_tools=["search", "retrieve", "summarize"],
                denied_tools=[],
            ),
        ],
    )


def bench_constitution_evaluation_throughput() -> dict[str, object]:
    """Benchmark ConstitutionEnforcer.evaluate() throughput.

    Returns
    -------
    dict with keys: operation, iterations, total_seconds, ops_per_second,
    avg_latency_ms, p99_latency_ms, memory_peak_mb.
    """
    constitution = _make_constitution()
    enforcer = ConstitutionEnforcer(constitution)
    action = AgentAction(
        agent_id="agent-bench",
        role="worker",
        action_type=ActionType.TOOL_CALL,
        details={"tool_name": "search"},
        timestamp=datetime.now(tz=timezone.utc),
    )

    start = time.perf_counter()
    for _ in range(_ITERATIONS):
        enforcer.evaluate(action)
    total = time.perf_counter() - start

    result: dict[str, object] = {
        "operation": "constitution_evaluation_throughput",
        "iterations": _ITERATIONS,
        "total_seconds": round(total, 4),
        "ops_per_second": round(_ITERATIONS / total, 1),
        "avg_latency_ms": round(total / _ITERATIONS * 1000, 4),
        "p99_latency_ms": 0.0,
        "memory_peak_mb": 0.0,
    }
    print(
        f"[bench_constitution_throughput] {result['operation']}: "
        f"{result['ops_per_second']:,.0f} ops/sec  "
        f"avg {result['avg_latency_ms']:.4f} ms"
    )
    return result


def run_benchmark() -> dict[str, object]:
    """Entry point returning the benchmark result dict."""
    return bench_constitution_evaluation_throughput()


if __name__ == "__main__":
    result = run_benchmark()
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    output_path = results_dir / "throughput_baseline.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"Results saved to {output_path}")
