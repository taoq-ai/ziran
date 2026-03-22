"""Performance benchmarks for ZIRAN operations.

Measures timing, throughput, and memory usage for core operations
like vector loading, library initialization, and benchmark generation.

Usage:
    uv run python benchmarks/performance_metrics.py
    uv run python benchmarks/performance_metrics.py --json results/performance.json
"""

from __future__ import annotations

import argparse
import gc
import json
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any


def _measure_operation(
    name: str,
    fn: Any,
    *args: Any,
    iterations: int = 1,
    **kwargs: Any,
) -> dict:
    """Run an operation multiple times and collect timing/memory stats.

    Returns dict with timing (min, max, mean) and peak memory delta.
    """
    times: list[float] = []

    # Warm-up run
    fn(*args, **kwargs)

    gc.collect()
    tracemalloc.start()
    mem_before = tracemalloc.get_traced_memory()[0]

    for _ in range(iterations):
        gc.collect()
        start = time.perf_counter()
        result = fn(*args, **kwargs)
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    mem_after, mem_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "name": name,
        "iterations": iterations,
        "timing_seconds": {
            "min": round(min(times), 4),
            "max": round(max(times), 4),
            "mean": round(sum(times) / len(times), 4),
        },
        "memory_bytes": {
            "before": mem_before,
            "after": mem_after,
            "peak": mem_peak,
            "delta": mem_after - mem_before,
        },
        "result_summary": _summarize_result(result),
    }


def _summarize_result(result: Any) -> str:
    """Create a short summary of the operation result."""
    if isinstance(result, dict):
        return f"dict with {len(result)} keys"
    if isinstance(result, list):
        return f"list with {len(result)} items"
    if hasattr(result, "vectors"):
        return f"library with {len(result.vectors)} vectors"
    return str(type(result).__name__)


def _bench_library_init() -> Any:
    """Benchmark: Initialize the AttackLibrary."""
    from ziran.application.attacks.library import AttackLibrary

    return AttackLibrary()


def _bench_library_filter_category() -> Any:
    """Benchmark: Filter vectors by category."""
    from ziran.application.attacks.library import get_attack_library
    from ziran.domain.entities.attack import AttackCategory

    lib = get_attack_library()
    return lib.get_attacks_by_category(AttackCategory.PROMPT_INJECTION)


def _bench_library_filter_owasp() -> Any:
    """Benchmark: Filter vectors by OWASP category."""
    from ziran.application.attacks.library import get_attack_library
    from ziran.domain.entities.attack import OwaspLlmCategory

    lib = get_attack_library()
    return lib.get_attacks_by_owasp(OwaspLlmCategory.LLM01)


def _bench_inventory_collection() -> Any:
    """Benchmark: Collect full inventory."""
    from benchmarks.inventory import collect_inventory

    return collect_inventory()


def _bench_owasp_coverage() -> Any:
    """Benchmark: Compute OWASP coverage."""
    from benchmarks.owasp_coverage import collect_owasp_coverage

    return collect_owasp_coverage()


def _bench_benchmark_comparison() -> Any:
    """Benchmark: Generate benchmark comparison."""
    from benchmarks.benchmark_comparison import collect_benchmark_comparison

    return collect_benchmark_comparison()


def _bench_accuracy_metrics() -> Any:
    """Benchmark: Compute accuracy metrics."""
    from benchmarks.accuracy_metrics import collect_accuracy_metrics

    return collect_accuracy_metrics()


def collect_performance_metrics() -> dict:
    """Run all performance benchmarks and collect results."""
    benchmarks: list[dict] = []

    operations = [
        ("AttackLibrary initialization", _bench_library_init),
        ("Filter by category", _bench_library_filter_category),
        ("Filter by OWASP", _bench_library_filter_owasp),
        ("Inventory collection", _bench_inventory_collection),
        ("OWASP coverage computation", _bench_owasp_coverage),
        ("Benchmark comparison", _bench_benchmark_comparison),
        ("Accuracy metrics computation", _bench_accuracy_metrics),
    ]

    for name, fn in operations:
        result = _measure_operation(name, fn)
        benchmarks.append(result)

    # Compute throughput: vectors per second for library init
    lib_bench = benchmarks[0]
    lib_time = lib_bench["timing_seconds"]["mean"]

    from ziran.application.attacks.library import get_attack_library

    lib = get_attack_library()
    vector_count = len(lib.vectors)

    throughput = round(vector_count / lib_time, 1) if lib_time > 0 else 0

    # Performance targets for regression detection.
    # Generous limits to accommodate slow CI runners (shared VMs).
    targets = {
        "library_init_max_seconds": 30.0,
        "inventory_collection_max_seconds": 30.0,
        "benchmark_comparison_max_seconds": 30.0,
        "accuracy_metrics_max_seconds": 30.0,
    }

    # Check targets
    regressions: list[str] = []
    target_checks = [
        ("library_init_max_seconds", benchmarks[0]),
        ("inventory_collection_max_seconds", benchmarks[3]),
        ("benchmark_comparison_max_seconds", benchmarks[5]),
        ("accuracy_metrics_max_seconds", benchmarks[6]),
    ]
    for target_name, bench in target_checks:
        max_time = targets[target_name]
        actual = bench["timing_seconds"]["max"]
        if actual > max_time:
            regressions.append(f"{bench['name']}: {actual:.2f}s > {max_time:.2f}s target")

    return {
        "benchmarks": benchmarks,
        "summary": {
            "total_benchmarks": len(benchmarks),
            "vector_count": vector_count,
            "vectors_per_second": throughput,
            "total_time_seconds": round(sum(b["timing_seconds"]["mean"] for b in benchmarks), 4),
        },
        "targets": targets,
        "regressions": regressions,
        "regression_detected": len(regressions) > 0,
    }


def print_summary(data: dict) -> None:
    """Print human-readable performance metrics."""
    print("Performance Benchmarks")
    print("=" * 70)

    for bench in data["benchmarks"]:
        t = bench["timing_seconds"]
        m = bench["memory_bytes"]
        print(f"\n{bench['name']} ({bench['iterations']} iterations):")
        print(f"  Timing:  min={t['min']:.4f}s  mean={t['mean']:.4f}s  max={t['max']:.4f}s")
        print(f"  Memory:  delta={m['delta']:+,} bytes  peak={m['peak']:,} bytes")
        print(f"  Result:  {bench['result_summary']}")

    s = data["summary"]
    print(f"\n{'─' * 70}")
    print(f"Vectors:         {s['vector_count']}")
    print(f"Throughput:      {s['vectors_per_second']} vectors/sec")
    print(f"Total time:      {s['total_time_seconds']:.2f}s")

    if data["regressions"]:
        print("\nREGRESSIONS DETECTED:")
        for r in data["regressions"]:
            print(f"  - {r}")
    else:
        print("\nAll performance targets met.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Performance benchmarks")
    parser.add_argument("--json", type=Path, help="Write JSON output to file")
    args = parser.parse_args()

    data = collect_performance_metrics()

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(data, indent=2) + "\n")
        print(f"Wrote {args.json}", file=sys.stderr)
    else:
        print_summary(data)

    if data["regression_detected"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
