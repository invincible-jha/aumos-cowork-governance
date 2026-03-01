"""Comparison visualiser for aumos-cowork-governance benchmark results."""
from __future__ import annotations

import json
from pathlib import Path


def _load(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)  # type: ignore[return-value]


def main() -> None:
    results_dir = Path(__file__).parent / "results"

    result_files = [
        "throughput_baseline.json",
        "latency_baseline.json",
        "memory_baseline.json",
    ]

    print(f"\n{'=' * 80}")
    print("  aumos-cowork-governance Benchmark Results")
    print(f"{'=' * 80}")
    print(f"{'Operation':<40} {'Ops/sec':>12} {'Avg Latency':>12} {'Peak Mem':>12}")
    print("-" * 80)

    for fname in result_files:
        data = _load(results_dir / fname)
        if data is None:
            print(f"  (no results for {fname} — run benchmark first)")
            continue
        operation = str(data.get("operation", fname))
        ops_sec = float(data.get("ops_per_second", 0))  # type: ignore[arg-type]
        avg_lat = float(data.get("avg_latency_ms", 0))  # type: ignore[arg-type]
        peak_kb = float(data.get("peak_memory_kb", 0))  # type: ignore[arg-type]
        ops_str = f"{ops_sec:,.0f}" if ops_sec > 0 else "n/a"
        lat_str = f"{avg_lat:.3f}ms" if avg_lat > 0 else "n/a"
        mem_str = f"{peak_kb:,.0f}KB" if peak_kb > 0 else "n/a"
        print(f"{operation:<40} {ops_str:>12} {lat_str:>12} {mem_str:>12}")

    print(f"{'=' * 80}")
    print("  Run all benchmarks:")
    print("    python benchmarks/bench_constitution_throughput.py")
    print("    python benchmarks/bench_voting_latency.py")
    print("    python benchmarks/bench_memory_usage.py")
    print(f"{'=' * 80}")


if __name__ == "__main__":
    main()
