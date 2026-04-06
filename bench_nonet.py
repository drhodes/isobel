"""
bench_nonet.py — compare plain Python call cost to @nonet call cost.

The benchmark warms each decorated function once before timing, so the reported
@nonet numbers are steady-state calls through an already-started dedicated
worker: pickle round-trip, local IPC, function execution, and parent-side
deserialization.
"""

from __future__ import annotations

import argparse
import gc
import statistics
import time
from dataclasses import dataclass
from typing import Any, Callable

from main import nonet


PAYLOAD = tuple(range(32))


def _noop() -> None:
    return None


def _small_compute() -> int:
    total = 0
    for value in range(128):
        total += value * value
    return total


def _small_payload() -> dict[str, Any]:
    return {
        "count": len(PAYLOAD),
        "head": PAYLOAD[:8],
        "tail": PAYLOAD[-8:],
        "checksum": sum(PAYLOAD),
    }


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    description: str
    plain: Callable[[], Any]
    sandboxed: Callable[[], Any]


CASES: tuple[BenchmarkCase, ...] = (
    BenchmarkCase("noop", "empty call returning None", _noop, nonet(_noop)),
    BenchmarkCase(
        "small_compute",
        "small CPU-bound function returning an int",
        _small_compute,
        nonet(_small_compute),
    ),
    BenchmarkCase(
        "small_payload",
        "small structured result to include pickle overhead",
        _small_payload,
        nonet(_small_payload),
    ),
)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("value must be > 0")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure steady-state per-call overhead added by @nonet.",
    )
    parser.add_argument("--repeats", type=_positive_int, default=7)
    parser.add_argument("--plain-calls", type=_positive_int, default=200_000)
    parser.add_argument("--nonet-calls", type=_positive_int, default=200)
    return parser.parse_args()


def _format_duration(ns_per_call: float) -> str:
    if ns_per_call >= 1_000_000:
        return f"{ns_per_call / 1_000_000:.3f} ms"
    if ns_per_call >= 1_000:
        return f"{ns_per_call / 1_000:.3f} us"
    return f"{ns_per_call:.0f} ns"


def _measure(fn: Callable[[], Any], calls: int, repeats: int) -> list[float]:
    samples: list[float] = []
    fn()  # warm the code path once before timing
    for _ in range(repeats):
        gc.collect()
        gc_was_enabled = gc.isenabled()
        if gc_was_enabled:
            gc.disable()
        try:
            start_ns = time.perf_counter_ns()
            last_result = None
            for _ in range(calls):
                last_result = fn()
            elapsed_ns = time.perf_counter_ns() - start_ns
        finally:
            if gc_was_enabled:
                gc.enable()
        _ = last_result
        samples.append(elapsed_ns / calls)
    return samples


def _print_series(label: str, samples: list[float]) -> None:
    median = statistics.median(samples)
    best = min(samples)
    worst = max(samples)
    print(
        f"  {label:<7} median {_format_duration(median):>10}/call"
        f"  best {_format_duration(best):>10}"
        f"  worst {_format_duration(worst):>10}"
    )


def main() -> None:
    args = parse_args()

    print("Benchmarking plain calls vs steady-state @nonet")
    print(
        f"repeats={args.repeats}  "
        f"plain_calls/sample={args.plain_calls}  "
        f"nonet_calls/sample={args.nonet_calls}"
    )
    print()

    for case in CASES:
        plain_result = case.plain()
        sandbox_result = case.sandboxed()
        if plain_result != sandbox_result:
            raise RuntimeError(
                f"{case.name}: plain result {plain_result!r} "
                f"!= sandboxed result {sandbox_result!r}"
            )

        plain_samples = _measure(case.plain, args.plain_calls, args.repeats)
        sandbox_samples = _measure(case.sandboxed, args.nonet_calls, args.repeats)
        plain_median = statistics.median(plain_samples)
        sandbox_median = statistics.median(sandbox_samples)
        delta = sandbox_median - plain_median
        ratio = sandbox_median / plain_median if plain_median else float("inf")

        print(f"{case.name}: {case.description}")
        _print_series("plain", plain_samples)
        _print_series("@nonet", sandbox_samples)
        print(
            f"  overhead median {_format_duration(delta):>10}/call"
            f"  ratio {ratio:>10.1f}x"
        )
        print()


if __name__ == "__main__":
    main()
