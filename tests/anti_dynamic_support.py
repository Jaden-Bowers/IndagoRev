"""Execution and behavioral oracles for the Linux anti-analysis fixtures."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import os
from pathlib import Path
import re
import signal
import subprocess
import time

FIXTURES = (
    "ptrace_guard", "tracer_status", "encrypted_records",
    "timing_guard", "signal_guard", "encrypted_code",
)
DIGESTS = {
    "ptrace_guard": "",  # Filled by an independent hash of the fixture record.
    "tracer_status": "2562c3d0",
    "encrypted_records": "b60463ed",
    "timing_guard": "f134c0fa",
    "signal_guard": "19730a50",
}
PLAINTEXT = (
    "fixture=runtime-secret", "operation=local-checksum", "result=inspection-complete",
)


def fnv1a(data: bytes) -> int:
    value = 2166136261
    for byte in data:
        value = ((value ^ byte) * 16777619) & 0xffffffff
    return value


DIGESTS["ptrace_guard"] = f"{fnv1a(b'indago:ptrace:fixture'):08x}"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class Case:
    name: str
    fixture: str
    mode: str = "native"
    args: tuple[str, ...] = ()
    expected_exit: int = 0
    contains: tuple[str, ...] = ()
    excludes: tuple[str, ...] = ()
    patterns: tuple[str, ...] = ()
    gdb_commands: tuple[str, ...] = ()
    allow_unavailable: bool = False
    gdb_script: str | None = None


def payload_markers(fixture: str) -> tuple[str, ...]:
    if fixture == "encrypted_code":
        return tuple(f"input={x} result={7*x+3} expected={7*x+3}" for x in (0, 1, 7, 42)) + (
            "payload=encrypted-code checks=4 erased=1",)
    label = fixture.replace("_guard", "").replace("_", "-")
    return (f"payload={label} digest={DIGESTS[fixture]}",)


def success_case(fixture: str, mode: str, observe: bool = False) -> Case:
    args = ("--limit-ms", "60000") if fixture == "timing_guard" else ()
    if observe:
        args += ("--observe",)
    markers = payload_markers(fixture)
    excludes = ()
    patterns = ()
    commands = ()
    if fixture == "ptrace_guard":
        markers += ("expected=1 unavailable=0 altered=0",)
    elif fixture == "tracer_status":
        patterns = (r"phase=before pid=[1-9]\d* tracer=0\b",
                    r"phase=after pid=[1-9]\d* tracer=0\b")
        if mode == "gdb":
            patterns = (r"phase=before pid=[1-9]\d* tracer=[1-9]\d*\b",
                        r"phase=after pid=[1-9]\d* tracer=[1-9]\d*\b")
            if not observe:
                return Case("strict", fixture, mode, args, 10,
                            ("reason=tracer-present-before-payload",), ("payload=",),
                            patterns[:1])
    elif fixture == "signal_guard":
        markers += ("probe=signals trap=2 user=2 order=1212",)
        commands = ()
    elif fixture == "encrypted_records":
        markers += ("records=3",)
        if observe:
            markers += tuple(f"plaintext={text}" for text in PLAINTEXT)
        else:
            excludes += ("plaintext=",)
    elif fixture == "encrypted_code":
        if observe:
            markers += ("decoded-checksum=64761977",)
        else:
            excludes += ("decoded-checksum=",)
    elif fixture == "timing_guard":
        markers += ("timing-summary slow=0",)
        patterns = tuple(rf"sample={i} elapsed_ns=\d+ limit_ns=60000000000\b" for i in range(3))
    return Case("observe" if observe else "strict", fixture, mode, args,
                contains=markers, excludes=excludes, patterns=patterns,
                gdb_commands=commands,
                allow_unavailable=fixture in ("ptrace_guard", "tracer_status", "encrypted_code"),
                gdb_script="gdb_forward_signals.gdb" if fixture == "signal_guard" and mode == "gdb" else None)


def functional_cases(with_gdb: bool) -> list[Case]:
    cases = []
    for fixture in FIXTURES:
        cases.extend(success_case(fixture, "native", observe) for observe in (False, True))
        for name, args, exit_code in (
            ("help", ("--help",), 0),
            ("unknown", ("--unknown",), 2),
            ("duplicate-observe", ("--observe", "--observe"), 2),
            ("extra-positional", ("unexpected",), 2),
        ):
            cases.append(Case(name, fixture, args=args, expected_exit=exit_code,
                              contains=("usage:",), excludes=("payload=", "probe=")))
    for observe in (False, True):
        cases.append(Case(
            "zero-limit-observe" if observe else "zero-limit-strict", "timing_guard",
            args=("--limit-ms", "0") + (("--observe",) if observe else ()),
            expected_exit=0 if observe else 10,
            contains=("timing-summary slow=3",) + (payload_markers("timing_guard") if observe
                       else ("reason=timing-threshold-exceeded",)),
            excludes=() if observe else ("payload=",)))
    for index, args in enumerate((
        ("--limit-ms", "-1"), ("--limit-ms", "60001"), ("--limit-ms", "abc"),
        ("--limit-ms", ""), ("--limit-ms", "1x"), ("--limit-ms", "1.0"),
        ("--limit-ms", "99999999999999999999999"), ("--limit-ms",),
        ("--limit-ms", "1", "--limit-ms", "1"),
    )):
        cases.append(Case(f"invalid-limit-{index}", "timing_guard", args=args,
                          expected_exit=2, contains=("usage:",), excludes=("payload=",)))
    if with_gdb:
        for fixture in FIXTURES:
            cases.extend(success_case(fixture, "gdb", observe) for observe in (False, True))
        for observe in (False, True):
            cases.append(Case(
                "suppressed-trap-observe" if observe else "suppressed-trap-strict", "signal_guard",
                "gdb", ("--observe",) if observe else (), 0 if observe else 10,
                ("probe=signals trap=0 user=2 order=11", "reason=signal-delivery-changed") +
                (payload_markers("signal_guard") if observe else ()),
                () if observe else ("payload=",), gdb_commands=(
                    "handle SIGUSR1 nostop noprint pass", "handle SIGTRAP nostop noprint nopass")))
    return cases


def command_for(case: Case, build: Path, gdb: str = "gdb") -> list[str]:
    target = [str(build / f"indago_anti_{case.fixture}"), *case.args]
    if case.mode == "native":
        return target
    if case.mode != "gdb":
        raise ValueError(f"unknown execution mode: {case.mode}")
    command = [gdb, "--batch", "--nx", "--nh", "--return-child-result",
               "-ex", "set startup-with-shell off", "-ex", "set disable-randomization off",
               "-ex", "set pagination off", "-ex", "set confirm off",
               "-ex", "set debuginfod enabled off"]
    for item in case.gdb_commands:
        command.extend(("-ex", item))
    if case.gdb_script:
        script = Path(__file__).resolve().parent / "fixtures/anti_dynamic" / case.gdb_script
        return command + ["-x", str(script), "--args", *target]
    return command + ["-ex", "run", "--args", *target]


def execute(command: list[str], timeout: float) -> dict:
    """Time process creation through reaping; kill the entire group on timeout."""
    started = time.perf_counter_ns()
    result = {"command": command, "returncode": None, "stdout": "", "stderr": "",
              "timed_out": False, "error": None}
    environment = dict(os.environ, LC_ALL="C", LANG="C")
    # Do not let inherited preload hooks silently change the baseline.
    for name in ("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"):
        environment.pop(name, None)
    try:
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              text=True, start_new_session=True, env=environment) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate()
            result.update(returncode=process.returncode, stdout=stdout, stderr=stderr)
    except OSError as error:
        result["error"] = str(error)
    result["elapsed_ns"] = time.perf_counter_ns() - started
    return result


def validate(case: Case, result: dict) -> tuple[str, str]:
    if result["error"]:
        return "error", result["error"]
    if result["timed_out"]:
        return "timeout", "process group exceeded timeout and was killed"
    code = result["returncode"]
    out = result["stdout"]
    if code == 77 and case.allow_unavailable:
        if "payload=" in out:
            return "failed", "unavailable capability emitted a payload"
        # GDB startup failures also return nonzero; require actual inferior evidence.
        evidence = {"ptrace_guard": "reason=tracing-denied-or-unavailable",
                    "tracer_status": "/proc/self/status",
                    "encrypted_code": "reason=requires-linux-x86-64-sysv"}
        denied_mapping = case.fixture == "encrypted_code" and any(
            text in result["stderr"] for text in ("mmap:", "mprotect executable:", "mprotect writable:"))
        if evidence.get(case.fixture, "\x00") not in out + result["stderr"] and not denied_mapping:
            return "failed", "exit 77 without capability diagnostic"
        return "unavailable", "fixture capability unavailable"
    if code != case.expected_exit:
        return "failed", f"exit {code}, expected {case.expected_exit}"
    if case.mode == "native" and result["stderr"]:
        return "failed", "unexpected native stderr"
    for text in case.contains:
        if text not in out:
            return "failed", f"missing output: {text!r}"
    for text in case.excludes:
        if text in out:
            return "failed", f"unexpected output: {text!r}"
    for pattern in case.patterns:
        if re.search(pattern, out) is None:
            return "failed", f"missing pattern: {pattern!r}"
    return "passed", "behavior matched"


def run_case(case: Case, build: Path, timeout: float, gdb: str = "gdb") -> dict:
    result = execute(command_for(case, build, gdb), timeout)
    status, detail = validate(case, result)
    return {"case": asdict(case), "status": status, "detail": detail, **result}
