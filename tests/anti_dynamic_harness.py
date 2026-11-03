#!/usr/bin/env python3
"""Build and validate the anti-analysis fixture corpus, recording all evidence."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import shutil
import sys
import uuid

from anti_dynamic_support import FIXTURES, execute, functional_cases, run_case, sha256

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/anti_dynamic"


def positive_float(text: str) -> float:
    value = float(text)
    if not 0 < value <= 3600:
        raise argparse.ArgumentTypeError("must be greater than zero and at most 3600")
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
    return {
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
            Path(__file__).resolve(), ROOT / "tests/anti_dynamic_support.py", SOURCE / "CMakeLists.txt")},
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=ROOT / "out/anti-dynamic-fixtures")
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--gdb", action="store_true", help="include debugger scenarios")
    parser.add_argument("--require-capabilities", action="store_true", help="fail on unavailable cases")
    parser.add_argument("--timeout", type=positive_float, default=15)
    args = parser.parse_args(argv)
    if sys.platform != "linux":
        parser.error("this harness requires Linux")
    build = args.build_dir.resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir = (args.report_dir or ROOT / "out/anti-dynamic-harness" / f"{stamp}-{uuid.uuid4().hex[:8]}").resolve()
    report_dir.mkdir(parents=True, exist_ok=False)
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
        print("Functional:", dict(counts))
    except (OSError, RuntimeError, ValueError) as error:
        report["infrastructure_error"] = str(error)
        print(f"ERROR: {error}", file=sys.stderr)
    finally:
        report["exit_code"] = code
        (report_dir / "report.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
        print(f"Report: {report_dir / 'report.json'}")
    return code


if __name__ == "__main__":
    sys.exit(main())
