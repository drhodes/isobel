"""
profile_nonet.py — fine-grained profiling of the @nonet per-call hot path.

Usage
─────
    # Human-readable cProfile table (default: 300 calls, top 20 functions)
    python profile_nonet.py

    # More calls, more rows
    python profile_nonet.py --calls 1000 --top 40

    # Emit a speedscope-compatible flamegraph JSON, open with:
    #   npx speedscope profile.speedscope.json
    python profile_nonet.py --flamegraph --out profile.speedscope.json

    # Sort by tottime instead of cumtime
    python profile_nonet.py --sort tottime

What is measured
────────────────
Each probe covers one complete round-trip:
    pickle.dumps(args/kwargs)
    → _write_msg (parent side)
    → [IPC + child executes fn + child pickle.dumps result]
    → _read_msg (parent side)
    → _deserialize_result / pickle.loads

Three cases are profiled:
    noop         — zero-work baseline (isolates IPC + serialization cost)
    small_int    — tiny CPU work + small return value
    small_dict   — small structured return (more pickle work)
"""

from __future__ import annotations

import argparse
import cProfile
import io
import json
import pstats
import sys
import time
from typing import Any

from main import nonet


# ── Workloads ────────────────────────────────────────────────────────────────

def _noop() -> None:
    return None


def _small_int() -> int:
    return sum(i * i for i in range(64))


_PAYLOAD = tuple(range(32))

def _small_dict() -> dict[str, Any]:
    return {
        "count": len(_PAYLOAD),
        "head":  _PAYLOAD[:8],
        "tail":  _PAYLOAD[-8:],
        "sum":   sum(_PAYLOAD),
    }


_CASES: dict[str, tuple[Any, Any]] = {
    "noop":       (_noop,       nonet(_noop)),
    "small_int":  (_small_int,  nonet(_small_int)),
    "small_dict": (_small_dict, nonet(_small_dict)),
}


# ── CLI ──────────────────────────────────────────────────────────────────────

def _positive_int(v: str) -> int:
    n = int(v)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return n


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Profile the @nonet per-call hot path.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--calls",     type=_positive_int, default=300,
                   help="Sandboxed calls per case (default: 300)")
    p.add_argument("--top",       type=_positive_int, default=20,
                   help="cProfile rows to display (default: 20)")
    p.add_argument("--sort",      default="cumtime",
                   choices=["cumtime", "tottime", "calls", "pcalls", "name"],
                   help="cProfile sort key (default: cumtime)")
    p.add_argument("--case",      choices=list(_CASES), default=None,
                   help="Run only one case instead of all three")
    p.add_argument("--flamegraph", action="store_true",
                   help="Also emit a speedscope-compatible flamegraph JSON")
    p.add_argument("--out",       default="profile.speedscope.json",
                   help="Output path for --flamegraph (default: profile.speedscope.json)")
    return p.parse_args()


# ── cProfile helpers ─────────────────────────────────────────────────────────

def _run_profile(sandboxed_fn, calls: int) -> cProfile.Profile:
    """Warm once, then profile `calls` invocations."""
    sandboxed_fn()          # warm the worker process
    pr = cProfile.Profile()
    pr.enable()
    for _ in range(calls):
        sandboxed_fn()
    pr.disable()
    return pr


def _print_stats(pr: cProfile.Profile, sort: str, top: int, label: str) -> None:
    buf = io.StringIO()
    ps = pstats.Stats(pr, stream=buf)
    ps.strip_dirs()
    ps.sort_stats(sort)
    ps.print_stats(top)
    print(f"\n{'─' * 70}")
    print(f"  case: {label}")
    print(f"{'─' * 70}")
    print(buf.getvalue())


# ── Speedscope / flamegraph helpers ──────────────────────────────────────────

def _to_speedscope(pr: cProfile.Profile, label: str) -> dict:
    """
    Convert a cProfile.Profile to a speedscope "sampled" profile.

    Each cProfile entry maps to one synthetic sample whose weight is
    its cumulative time in microseconds.  This is an approximation —
    speedscope is designed for wall-clock stacks — but it lets you
    visualise relative cost in the flamegraph UI without a separate
    sampling profiler.
    """
    ps = pstats.Stats(pr)
    ps.strip_dirs()

    frames: list[dict] = []
    frame_index: dict[str, int] = {}
    samples: list[list[int]] = []
    weights: list[float] = []

    def _get_frame(name: str) -> int:
        if name not in frame_index:
            frame_index[name] = len(frames)
            frames.append({"name": name})
        return frame_index[name]

    for func, (cc, nc, tt, ct, _callers) in ps.stats.items():  # type: ignore[attr-defined]
        filename, lineno, funcname = func
        frame_name = f"{funcname} ({filename}:{lineno})"
        fid = _get_frame(frame_name)
        weight_us = ct * 1_000_000          # cumtime → µs
        if weight_us > 0:
            samples.append([fid])
            weights.append(weight_us)

    return {
        "$schema": "https://www.speedscope.app/file-formats/speedscope.json",
        "shared": {"frames": frames},
        "profiles": [
            {
                "type": "sampled",
                "name": label,
                "unit": "microseconds",
                "startValue": 0,
                "endValue": sum(weights),
                "samples": samples,
                "weights": weights,
            }
        ],
        "exporter": "profile_nonet.py",
        "name": label,
    }


def _merge_speedscope(profiles: list[dict]) -> dict:
    """Merge multiple single-profile speedscope dicts into one file."""
    all_frames: list[dict] = []
    frame_index: dict[str, int] = {}
    merged_profiles = []

    for sp in profiles:
        local_to_global: dict[int, int] = {}
        for i, frame in enumerate(sp["shared"]["frames"]):
            key = frame["name"]
            if key not in frame_index:
                frame_index[key] = len(all_frames)
                all_frames.append(frame)
            local_to_global[i] = frame_index[key]

        prof = sp["profiles"][0]
        remapped_samples = [
            [local_to_global[fid] for fid in stack]
            for stack in prof["samples"]
        ]
        merged_profiles.append({**prof, "samples": remapped_samples})

    return {
        "$schema": "https://www.speedscope.app/file-formats/speedscope.json",
        "shared": {"frames": all_frames},
        "profiles": merged_profiles,
        "exporter": "profile_nonet.py",
        "name": "nonet profiling",
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    args = parse_args()

    cases = (
        {args.case: _CASES[args.case]} if args.case else _CASES
    )

    speedscope_parts: list[dict] = []

    for name, (_plain, sandboxed) in cases.items():
        print(f"Profiling [{name}]  calls={args.calls} …", flush=True)
        pr = _run_profile(sandboxed, args.calls)
        _print_stats(pr, args.sort, args.top, name)

        if args.flamegraph:
            speedscope_parts.append(_to_speedscope(pr, name))

    if args.flamegraph:
        merged = _merge_speedscope(speedscope_parts)
        with open(args.out, "w") as f:
            json.dump(merged, f, indent=2)
        print(f"\nFlamegraph written → {args.out}")
        print(f"  View online : https://www.speedscope.app  (drag and drop)")
        print(f"  View locally: npx speedscope {args.out}")


if __name__ == "__main__":
    main()
