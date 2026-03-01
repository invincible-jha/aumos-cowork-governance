"""Benchmark: Memory usage of constitution enforcement operations.

Uses tracemalloc to measure peak memory allocated during ConstitutionEnforcer
construction and repeated evaluation of multiple action types.
"""
from __future__ import annotations

import json
import sys
import tracemalloc
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

_ITERATIONS: int = 500


def bench_enforcement_memory_usage() -> dict[str, object]:
    """Benchmark memory usage during repeated constitution enforcement.

    Returns
    -------
    dict with keys: operation, iterations, peak_memory_kb, current_memory_kb,
    ops_per_second, avg_latency_ms, memory_peak_mb.
    """
    tracemalloc.start()
    snapshot_before = tracemalloc.take_snapshot()

    constitution = Constitution(
        team_name="mem-bench-team",
        conflict_strategy=ConflictStrategy.MOST_RESTRICTIVE,
        roles=[
            RoleDefinition(
                name="orchestrator",
                permissions=[Permission.READ, Permission.WRITE, Permission.DELEGATE],
                max_budget_usd=500.0,
                allowed_tools=["*"],
                denied_tools=[],
            ),
            RoleDefinition(
                name="worker",
                permissions=[Permission.READ, Permission.EXECUTE],
                max_budget_usd=10.0,
                allowed_tools=["search"],
                denied_tools=[],
            ),
        ],
    )
    enforcer = ConstitutionEnforcer(constitution)
    actions = [
        AgentAction(
            agent_id="agent-bench",
            role="worker",
            action_type=ActionType.TOOL_CALL,
            details={"tool_name": "search"},
            timestamp=datetime.now(tz=timezone.utc),
        ),
        AgentAction(
            agent_id="agent-bench",
            role="orchestrator",
            action_type=ActionType.BUDGET_SPEND,
            details={"amount_usd": 5.0},
            timestamp=datetime.now(tz=timezone.utc),
        ),
    ]

    for i in range(_ITERATIONS):
        enforcer.evaluate(actions[i % len(actions)])

    snapshot_after = tracemalloc.take_snapshot()
    tracemalloc.stop()

    stats = snapshot_after.compare_to(snapshot_before, "lineno")
    total_bytes = sum(stat.size_diff for stat in stats if stat.size_diff > 0)
    peak_kb = round(total_bytes / 1024, 2)

    result: dict[str, object] = {
        "operation": "enforcement_memory_usage",
        "iterations": _ITERATIONS,
        "peak_memory_kb": peak_kb,
        "current_memory_kb": peak_kb,
        "ops_per_second": 0.0,
        "avg_latency_ms": 0.0,
        "memory_peak_mb": round(peak_kb / 1024, 4),
    }
    print(
        f"[bench_memory_usage] {result['operation']}: "
        f"peak {peak_kb:.2f} KB over {_ITERATIONS} iterations"
    )
    return result


def run_benchmark() -> dict[str, object]:
    """Entry point returning the benchmark result dict."""
    return bench_enforcement_memory_usage()


if __name__ == "__main__":
    result = run_benchmark()
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    output_path = results_dir / "memory_baseline.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"Results saved to {output_path}")
