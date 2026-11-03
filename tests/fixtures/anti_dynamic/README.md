# Anti dynamic analysis fixtures

Standalone Linux C11 reverse engineering inputs, approximately 200 source lines
per executable. Each contains a harmless calculation behind an analysis obstacle.
Builds only compile and link; they do not execute the fixtures.

```sh
cmake -S tests/fixtures/anti_dynamic -B out/anti-dynamic-fixtures
cmake --build out/anti-dynamic-fixtures
out/anti-dynamic-fixtures/indago_anti_ptrace_guard
```

Generated ELF binaries and debug information remain in ignored `out/`. Sources
are committed; generated binaries are reproducible build artifacts. Compile with
optimizations disabled to preserve inspection points and intermediate values.

| Target suffix | Technique |
| --- | --- |
| `ptrace_guard` | A disposable child calls `PTRACE_TRACEME` twice; the parent decodes its exit status. |

All fixtures accept `--observe` to continue the calculation after a detected
obstacle, and `--help`. Exit codes: 0 completed, 1 system/internal error,
2 invalid arguments, 10 analysis obstacle detected, 77 unavailable capability.
Observation mode does not hide system errors or unavailable capabilities.

`ptrace_guard` confines the ptrace relationship to a child and never stops that
child deliberately. The first call can fail because of a debugger, container
policy, seccomp, or another restriction; this is reported as unavailable (77),
not conclusive debugger detection. A successful first call should make the
second fail with EPERM; two successes indicate emulated or altered behavior.
The parent never invokes the calculation on its unavailable path.

`indago_anti_tracer_status` reads `Pid` and `TracerPid` from `/proc/self/status`
before and after a bounded record transformation. A nonzero tracer blocks the
payload result with exit 10, unless `--observe` is supplied. Missing procfs is
unavailable (77); malformed records fail (1). The snapshots have a race window
and are an inspection exercise, not proof that instrumentation is absent.

`indago_anti_encrypted_records` keeps three strings encoded with a deterministic
xorshift XOR stream. Each is decoded into a temporary allocation, validated,
hashed, re-encoded, compared to its original ciphertext, and explicitly wiped.
`--observe` prints plaintext during the decoded interval. This is reversible
obfuscation with embedded keys, not cryptographic protection. It exercises
short-lived runtime data rather than detecting a debugger.

`indago_anti_timing_guard` measures three bounded volatile loops with the
monotonic clock. Any sample above `--limit-ms N` gates the final digest (10).
The default is 250 ms; `--limit-ms 0` exercises detection and `--observe` permits
the digest despite it. Scheduling, host load, and instrumentation can all cause
threshold crossings; timing alone does not establish debugger presence.

`indago_anti_signal_guard` installs handlers, temporarily unblocks its two probe
signals, and raises SIGUSR1/SIGTRAP twice in a known order. Signal suppression
changes the handler counters or delivery order and gates the digest (10).
Handlers and the original mask are restored before completion. In GDB, use
`handle SIGUSR1 nostop noprint pass` and `handle SIGTRAP nostop noprint pass`
for normal delivery; suppressing either exercises the changed-delivery branch.
SIGTRAP here comes from `raise`, not an architecture-specific breakpoint opcode.
