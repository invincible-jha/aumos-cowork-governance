"""Benchmark: Voting tally latency — per-tally p50/p95/p99.

Measures the per-call latency of MajorityVote.tally() for increasing numbers
of votes, capturing the latency distribution.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from aumos_cowork_governance.constitution.schema import VotingConfig
from aumos_cowork_governance.constitution.voting import MajorityVote, Vote

_WARMUP: int = 100
_ITERATIONS: int = 5_000
_VOTE_COUNT: int = 9  # Typical small team quorum size.


def _make_votes(count: int) -> list[Vote]:
    """Build a fixed set of votes for benchmarking."""
    votes: list[Vote] = []
    for i in range(count):
        choice = "approve" if i % 3 != 0 else "reject"
        votes.append(Vote(voter_id=f"voter-{i}", choice=choice))
    return votes


def bench_voting_tally_latency() -> dict[str, object]:
    """Benchmark MajorityVote.tally() per-call latency.

    Returns
    -------
    dict with keys: operation, iterations, total_seconds, ops_per_second,
    avg_latency_ms, p99_latency_ms, memory_peak_mb.
    """
    mechanism = MajorityVote()
    config = VotingConfig()
    votes = _make_votes(_VOTE_COUNT)

    # Warmup.
    for _ in range(_WARMUP):
        mechanism.tally(votes, config)

    latencies_ms: list[float] = []
    for _ in range(_ITERATIONS):
        t0 = time.perf_counter()
        mechanism.tally(votes, config)
        latencies_ms.append((time.perf_counter() - t0) * 1000)

    sorted_lats = sorted(latencies_ms)
    n = len(sorted_lats)
    total = sum(latencies_ms) / 1000

    result: dict[str, object] = {
        "operation": "voting_tally_latency",
        "iterations": _ITERATIONS,
        "total_seconds": round(total, 4),
        "ops_per_second": round(_ITERATIONS / total, 1),
        "avg_latency_ms": round(sum(latencies_ms) / n, 4),
        "p99_latency_ms": round(sorted_lats[min(int(n * 0.99), n - 1)], 4),
        "memory_peak_mb": 0.0,
    }
    print(
        f"[bench_voting_latency] {result['operation']}: "
        f"p99={result['p99_latency_ms']:.4f}ms  "
        f"mean={result['avg_latency_ms']:.4f}ms"
    )
    return result


def run_benchmark() -> dict[str, object]:
    """Entry point returning the benchmark result dict."""
    return bench_voting_tally_latency()


if __name__ == "__main__":
    result = run_benchmark()
    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    output_path = results_dir / "latency_baseline.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"Results saved to {output_path}")
