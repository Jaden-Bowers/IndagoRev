#!/usr/bin/env python3
"""Execute the fixtures with bounded timeouts and check observable behavior."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import sys

FIXTURES = (
    "ptrace_guard", "tracer_status", "encrypted_records",
    "timing_guard", "signal_guard", "encrypted_code",
)
DIGESTS = {
    "tracer_status": "2562c3d0",
    "encrypted_records": "b60463ed",
    "timing_guard": "f134c0fa",
    "signal_guard": "19730a50",
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run(command):
    completed = subprocess.run(command, capture_output=True, text=True, timeout=15)
    require(completed.returncode >= 0, f"crashed: {command}: {completed.stderr}")
    return completed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", type=Path)
    parser.add_argument("--gdb", action="store_true", help="also test debugger detection")
    args = parser.parse_args()
    binaries = {name: args.build_dir.resolve() / f"indago_anti_{name}" for name in FIXTURES}
    checked = 0
    unavailable = []

    def check(name, options, expected, contains=(), absent=(), allow_unavailable=False):
        nonlocal checked
        result = run([str(binaries[name]), *options])
        if allow_unavailable and result.returncode == 77:
            require("payload=" not in result.stdout, f"{name}: unavailable ran payload")
            unavailable.append(f"{name} {' '.join(options)}")
            print(f"UNAVAILABLE {name} {' '.join(options)}")
            return
        require(result.returncode == expected,
                f"{name} {options}: exit {result.returncode}, expected {expected}\n"
                f"{result.stdout}{result.stderr}")
        require(not result.stderr, f"{name}: unexpected stderr: {result.stderr}")
        for marker in contains:
            require(marker in result.stdout, f"{name}: missing {marker!r}")
        for marker in absent:
            require(marker not in result.stdout, f"{name}: unexpected {marker!r}")
        checked += 1

    for name, binary in binaries.items():
        require(binary.is_file(), f"build the missing binary: {binary}")
        check(name, ["--help"], 0, ["usage:"], ["payload="])
        check(name, ["--unknown"], 2, ["usage:"], ["payload="])
        check(name, ["--observe", "--observe"], 2, ["usage:"], ["payload="])
        # A large timing limit avoids ordinary scheduling noise in the baseline.
        options = ["--limit-ms", "60000"] if name == "timing_guard" else []
        markers = ["payload="]
        if name in DIGESTS:
            markers.append(f"digest={DIGESTS[name]}")
        if name == "ptrace_guard":
            markers.append("expected=1 unavailable=0 altered=0")
        check(name, options, 0, markers, allow_unavailable=True)
        check(name, [*options, "--observe"], 0, markers, allow_unavailable=True)

    check("encrypted_records", [], 0, ["records=3"], ["plaintext="])
    check("encrypted_records", ["--observe"], 0, [
        "plaintext=fixture=runtime-secret",
        "plaintext=operation=local-checksum",
        "plaintext=result=inspection-complete",
    ])
    check("encrypted_code", [], 0, [
        "input=0 result=3 expected=3", "input=1 result=10 expected=10",
        "input=7 result=52 expected=52", "input=42 result=297 expected=297",
        "checks=4 erased=1",
    ], ["decoded-checksum="], allow_unavailable=True)
    check("signal_guard", [], 0, ["trap=2 user=2 order=1212"])
    check("timing_guard", ["--limit-ms", "0"], 10,
          ["reason=timing-threshold-exceeded", "slow=3"], ["payload="])
    check("timing_guard", ["--limit-ms", "0", "--observe"], 0,
          ["slow=3", "payload=timing digest=f134c0fa"])
    for value in ("-1", "60001", "abc", "", "1x", "99999999999999999999999"):
        check("timing_guard", ["--limit-ms", value], 2, ["usage:"], ["payload="])
    check("timing_guard", ["--limit-ms"], 2, ["usage:"])
    check("timing_guard", ["--limit-ms", "1", "--limit-ms", "1"], 2, ["usage:"])

    if args.gdb:
        gdb = shutil.which("gdb")
        require(gdb is not None, "--gdb requires GDB on PATH")

        def debug(name, options, expected, markers, commands=()):
            nonlocal checked
            command = [gdb, "--batch", "--nx", "--nh", "--return-child-result",
                       "-ex", "set startup-with-shell off",
                       "-ex", "set disable-randomization off"]
            for item in commands:
                command.extend(["-ex", item])
            command.extend(["-ex", "run", "--args", str(binaries[name]), *options])
            result = run(command)
            require(result.returncode == expected,
                    f"GDB {name}: exit {result.returncode}\n{result.stdout}{result.stderr}")
            for marker in markers:
                require(marker in result.stdout, f"GDB {name}: missing {marker!r}")
            if expected == 10:
                require("payload=" not in result.stdout, f"GDB {name}: gated payload ran")
            if name == "tracer_status":
                require(re.search(r"tracer=[1-9][0-9]*", result.stdout),
                        "GDB did not expose a nonzero TracerPid")
            checked += 1

        debug("tracer_status", [], 10, ["reason=tracer-present-before-payload"])
        debug("tracer_status", ["--observe"], 0, ["payload=tracer-status digest=2562c3d0"])
        signals = ["handle SIGUSR1 nostop noprint pass",
                   "handle SIGTRAP nostop noprint nopass"]
        debug("signal_guard", [], 10, ["trap=0 user=2 order=11"], signals)
        debug("signal_guard", ["--observe"], 0,
              ["trap=0 user=2 order=11", "payload=signal digest=19730a50"], signals)

    print(f"PASS: {checked} checks; {len(unavailable)} unavailable capability cases")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
