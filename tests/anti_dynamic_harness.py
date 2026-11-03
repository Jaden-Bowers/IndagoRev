#!/usr/bin/env python3
"""Build and validate the anti-analysis fixture corpus, recording all evidence."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import uuid

from anti_dynamic_benchmark import benchmark, markdown_report
from anti_dynamic_support import FIXTURES, execute, functional_cases, run_case, sha256

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/anti_dynamic"


def positive_float(text: str) -> float:
    value = float(text)
    if not 0 < value <= 3600:
        raise argparse.ArgumentTypeError("must be greater than zero and at most 3600")
    return value


def bounded_count(text: str) -> int:
    value = int(text)
    if not 1 <= value <= 1000:
        raise argparse.ArgumentTypeError("must be between 1 and 1000")
    return value


def warmup_count(text: str) -> int:
    value = int(text)
    if not 0 <= value <= 100:
        raise argparse.ArgumentTypeError("must be between 0 and 100")
    return value


def environment(build: Path) -> dict:
    tools = {}
    for tool in ("cmake", "cc", "gdb"):
        path = shutil.which(tool)
        result = execute([path, "--version"], 10) if path else None
        tools[tool] = {"path": path, "version": result["stdout"].splitlines()[0]
                       if result and result["stdout"] else None}
    revision = execute(["git", "-C", str(ROOT), "rev-parse", "HEAD"], 10)
    status = execute(["git", "-C", str(ROOT), "status", "--porcelain"], 10)
    cpu_model = next((line.split(":", 1)[1].strip() for line in
                      Path("/proc/cpuinfo").read_text().splitlines()
                      if line.startswith("model name")), platform.processor())
    cache = {}
    cache_path = build / "CMakeCache.txt"
    if cache_path.exists():
        for line in cache_path.read_text().splitlines():
            if line.startswith(("CMAKE_C_COMPILER:", "CMAKE_C_FLAGS", "CMAKE_BUILD_TYPE:", "CMAKE_GENERATOR:")):
                key, _, value = line.partition("=")
                cache[key] = value
    flags = build / "CMakeFiles/indago_anti_ptrace_guard.dir/flags.make"
    return {
        "cpu_model": cpu_model, "logical_cpus": os.cpu_count(),
        "cpu_affinity": sorted(os.sched_getaffinity(0)),
        "build_cache": cache, "target_flags": flags.read_text() if flags.exists() else None,
        "platform": platform.platform(), "architecture": platform.machine(),
        "python": platform.python_version(), "tools": tools,
        "git_revision": revision["stdout"].strip(),
        "git_status": status["stdout"].splitlines(),
        "artifacts": {name: {
            "source_sha256": sha256(SOURCE / f"{name}.c"),
            "binary_sha256": sha256(build / f"indago_anti_{name}"),
            "binary_bytes": (build / f"indago_anti_{name}").stat().st_size,
        } for name in FIXTURES},
        "source_files": {str(path.relative_to(ROOT)): sha256(path) for path in (
            Path(__file__).resolve(), ROOT / "tests/anti_dynamic_support.py",
            ROOT / "tests/anti_dynamic_benchmark.py", SOURCE / "CMakeLists.txt",
            SOURCE / "gdb_forward_signals.gdb")},
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "out/anti-dynamic-fixtures")
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--gdb", action="store_true", help="include debugger scenarios")
    parser.add_argument("--require-capabilities", action="store_true", help="fail on unavailable cases")
    parser.add_argument("--timeout", type=positive_float, default=15)
    parser.add_argument("--benchmark", action="store_true", help="measure repeated observe-mode invocations")
    parser.add_argument("--iterations", type=bounded_count, default=20)
    parser.add_argument("--warmups", type=warmup_count, default=3)
    parser.add_argument("--seed", type=int, default=1729)
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        parser.error("this harness requires Linux")
    build = args.build_dir.resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir = (args.report_dir or ROOT / "out/anti-dynamic-harness" / f"{stamp}-{uuid.uuid4().hex[:8]}").resolve()
    try:
        report_dir.mkdir(parents=True, exist_ok=False)
    except OSError as error:
        parser.error(f"cannot create fresh report directory: {error}")
    report = {"schema_version": 1, "started_utc": stamp, "options": vars(args).copy(),
              "build_commands": [], "cases": [], "summary": {}, "infrastructure_error": None}
    code = 2
    try:
        if args.gdb and shutil.which("gdb") is None:
            raise RuntimeError("--gdb requires GDB on PATH")
        if not args.no_build:
            for command in (["cmake", "-S", str(SOURCE), "-B", str(build)],
                            ["cmake", "--build", str(build), "--parallel", "2"]):
                result = execute(command, 60)
                report["build_commands"].append(result)
                if result["returncode"] != 0 or result["timed_out"]:
                    raise RuntimeError(f"build failed: {result}")
        for name in FIXTURES:
            binary = build / f"indago_anti_{name}"
            if not binary.is_file() or binary.read_bytes()[:4] != b"\x7fELF":
                raise RuntimeError(f"missing or non-ELF fixture: {binary}")
        report["environment"] = environment(build)
        for case in functional_cases(args.gdb):
            row = run_case(case, build, args.timeout)
            report["cases"].append(row)
            if row["status"] != "passed":
                print(f"{row['status'].upper()}: {case.mode}/{case.fixture}/{case.name}: {row['detail']}")
        counts = Counter(row["status"] for row in report["cases"])
        report["summary"] = dict(counts)
        failed = any(counts[item] for item in ("failed", "error", "timeout"))
        code = int(failed or (args.require_capabilities and counts["unavailable"] > 0))
        print("Functional:", dict(counts), flush=True)
        if args.benchmark:
            report["benchmark"] = benchmark(build, args.gdb, args.timeout,
                                            args.iterations, args.warmups, args.seed)
            benchmark_counts = report["benchmark"]["summary"]["statuses"]
            if any(benchmark_counts.get(item, 0) for item in ("failed", "error", "timeout")):
                code = 1
            if args.require_capabilities and benchmark_counts.get("unavailable", 0):
                code = 1
    except (OSError, RuntimeError, ValueError) as error:
        report["infrastructure_error"] = str(error)
        print(f"ERROR: {error}", file=sys.stderr)
    finally:
        report["exit_code"] = code
        (report_dir / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
        (report_dir / "report.md").write_text(markdown_report(report))
        print(f"Report: {report_dir / 'report.json'}")
    return code


if __name__ == "__main__":
    sys.exit(main())
