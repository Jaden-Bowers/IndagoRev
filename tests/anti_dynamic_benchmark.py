"""Repeated process-latency measurements using the same behavioral oracles."""
from __future__ import annotations

from collections import Counter
import math
from pathlib import Path
import random
import statistics

from anti_dynamic_support import FIXTURES, run_case, success_case


def distribution(values: list[int]) -> dict:
    """Nearest-rank p95; sample stdev is zero for a single observation."""
    if not values:
        return {"count": 0}
    ordered = sorted(values)
    return {
        "count": len(values), "min_ns": ordered[0], "max_ns": ordered[-1],
        "median_ns": statistics.median(ordered), "mean_ns": statistics.mean(ordered),
        "p95_ns": ordered[math.ceil(0.95 * len(ordered)) - 1],
        "stdev_ns": statistics.stdev(ordered) if len(ordered) > 1 else 0,
    }


def summarize(rows: list[dict], iterations: int, modes: list[str]) -> dict:
    groups = []
    ratios = {}
    for fixture in FIXTURES:
        medians = {}
        for mode in modes:
            selected = [row for row in rows if row["case"]["fixture"] == fixture
                        and row["case"]["mode"] == mode]
            samples = [row for row in selected if row["phase"] == "measure"]
            passed = [row["elapsed_ns"] for row in samples if row["status"] == "passed"]
            complete = (len(samples) == iterations and len(passed) == iterations
                        and all(row["status"] == "passed" for row in selected))
            stats = distribution(passed)
            groups.append({"fixture": fixture, "mode": mode, "complete": complete,
                           "requested_samples": iterations, "statuses": dict(Counter(
                               row["status"] for row in samples)), "wall_time": stats})
            if complete:
                medians[mode] = stats["median_ns"]
        if "native" in medians and "gdb" in medians:
            ratios[fixture] = medians["gdb"] / medians["native"]
    return {"complete": all(group["complete"] for group in groups),
            "groups": groups, "gdb_to_native_median_ratio": ratios,
            "statuses": dict(Counter(row["status"] for row in rows))}


def benchmark(build: Path, with_gdb: bool, timeout: float, iterations: int,
              warmups: int, seed: int) -> dict:
    """Shuffle mode/fixture order within each round; preserve every invocation."""
    modes = ["native", "gdb"] if with_gdb else ["native"]
    cases = [success_case(fixture, mode, observe=True) for fixture in FIXTURES for mode in modes]
    generator = random.Random(seed)
    rows = []
    for phase, rounds in (("warmup", warmups), ("measure", iterations)):
        for index in range(rounds):
            order = list(cases)
            generator.shuffle(order)
            for case in order:
                row = run_case(case, build, timeout)
                rows.append({"phase": phase, "round": index, "sequence": len(rows), **row})
            # Per-round progress keeps long debugger runs observable.
            print(f"Benchmark {phase}: {index + 1}/{rounds}", flush=True)
    return {
        "method": "sequential shuffled rounds; fresh process; observe mode; wall clock includes launch/reap",
        "unit": "nanoseconds", "seed": seed, "iterations": iterations, "warmups": warmups,
        "rows": rows, "summary": summarize(rows, iterations, modes),
    }


def markdown_report(report: dict) -> str:
    env = report.get("environment", {})
    counts = report.get("summary", {})
    lines = ["# Anti dynamic analysis fixture benchmark", "",
             f"Started (UTC): `{report['started_utc']}`", "",
             f"Source revision: `{env.get('git_revision', 'unknown')}`", "",
             f"Host: {env.get('platform', 'unknown')}; Python {env.get('python', 'unknown')}.", "",
             f"Functional checks: `{counts}`. Overall exit code: `{report['exit_code']}`.", ""]
    benchmark = report.get("benchmark")
    if not benchmark:
        return "\n".join(lines)
    lines += [f"Measured rounds: {benchmark['iterations']}; warmup rounds: {benchmark['warmups']}; "
              f"shuffle seed: {benchmark['seed']}.", "",
              f"All benchmark groups complete: **{benchmark['summary']['complete']}**.", "",
              "Each invocation uses `--observe`; GDB forwards probe signals. Wall time",
              "includes process launch, debugger startup where applicable, fixture work,",
              "output capture, and process reaping. Warmups are excluded from statistics.", "",
              "| Fixture | Mode | Valid/requested | Median ms | p95 ms | Mean ms | Stdev ms | Complete |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for group in benchmark["summary"]["groups"]:
        stats = group["wall_time"]
        numbers = [f"{stats[key] / 1e6:.3f}" if key in stats else "n/a" for key in
                   ("median_ns", "p95_ns", "mean_ns", "stdev_ns")]
        lines.append(f"| {group['fixture']} | {group['mode']} | "
                     f"{stats['count']}/{group['requested_samples']} | " + " | ".join(numbers) +
                     f" | {group['complete']} |")
    ratios = benchmark["summary"]["gdb_to_native_median_ratio"]
    if ratios:
        lines += ["", "| Fixture | GDB/native median wall-time ratio |", "| --- | --- |"]
        lines += [f"| {name} | {ratio:.2f}x |" for name, ratio in ratios.items()]
    lines += ["", "These are fixture/process latency measurements, not Indago throughput or",
              "debugger evasion success rates. GDB startup dominates short programs;",
              "ratios must not be interpreted as instruction instrumentation overhead.",
              "Host load, caching, ASLR, and scheduling are uncontrolled. p95 is the",
              "nearest-rank sample quantile; this single-host run provides no confidence",
              "interval or cross-machine generalization. Failed, timed-out, unavailable,",
              "and warmup invocations are excluded from timing statistics; an incomplete",
              "group is labeled and does not receive an overhead ratio.", "",
              "See `report.json` for every raw invocation, expectation, and artifact hash.", ""]
    return "\n".join(lines)
