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

| Target suffix | Source lines | Technique |
| --- | --- | --- |
| `ptrace_guard` | 186 | Two `PTRACE_TRACEME` calls in a disposable child. |
| `tracer_status` | 186 | `/proc/self/status` tracer checks around a calculation. |
| `encrypted_records` | 185 | Transient string decryption, checksum, re-encryption, and erasure. |
| `timing_guard` | 179 | Three monotonic timing checks around volatile loops. |
| `signal_guard` | 181 | SIGUSR1/SIGTRAP delivery counters and ordering. |
| `encrypted_code` | 194 | Runtime code decryption with RW/RX permission transitions. |

All fixtures accept `--help` and `--observe`. In guard fixtures, observation
mode continues the calculation after a detected obstacle; in encryption
fixtures, it prints intermediate decoded information. Exit codes: 0 completed, 1 system/internal error,
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

`indago_anti_encrypted_code` decodes a 13-byte Linux x86-64 SysV function that
returns `7 * input + 3`, checks its checksum, and runs four fixed inputs. Memory
transitions RW to RX to RW, then is re-encoded, compared, wiped, and unmapped.
No page is simultaneously writable and executable. `--observe` prints the
plaintext checksum. Other architectures and denied executable mappings return
77. This is an explicit runtime code discovery fixture; the fixed bytes are
reversible obfuscation. ENDBR64 supports indirect branch tracking environments.

## Smoke checks

Run the bounded subprocess checks after building (Python 3.10+):

```sh
python3 tests/fixtures/anti_dynamic/smoke.py out/anti-dynamic-fixtures
```

The runner checks help and invalid arguments, fixed payload digests, encryption
round trips, all four decoded function results, signal ordering, and timing
threshold gating with and without observation mode. Every process has a
15-second timeout. Capability failures (77) are reported separately and do not
count as successful payload checks. Other failures, including crashes, fail the
runner. No tests run implicitly during the build.

To also exercise debugger-dependent branches, on a host that permits ptrace:

```sh
python3 tests/fixtures/anti_dynamic/smoke.py out/anti-dynamic-fixtures --gdb
```

This requires GDB and checks a nonzero TracerPid, strict gating, observation
mode, and suppressed SIGTRAP delivery. A debugger startup failure fails the
explicit `--gdb` run. Plaintext validation and timing thresholds are fixture
behavior, not a claim of robust protection against analysis tools.

## Evidence harness

The reporting harness builds the standalone environment and exercises native
strict/observe behavior, help, rejected arguments, and deterministic timing
threshold paths. `--gdb` adds execution of every fixture under GDB plus explicit
signal suppression. Native baseline timing uses a 60-second threshold so normal
host scheduling does not cause incidental failures. This tests the fixtures;
it does not benchmark Indago's analysis engine.

```sh
python3 tests/anti_dynamic_harness.py --gdb --require-capabilities
```

Python 3.10+, CMake 3.25+, a Linux C compiler, and GDB for debugger mode are
required. No Python packages are installed. `--no-build`, `--build-dir`,
`--report-dir`, and `--timeout` customize the run. Report directories must be
new; by default each run gets a unique directory under
`out/anti-dynamic-harness/`. Reports preserve commands, stdout/stderr, exit
codes, timeouts, expectations, source/binary hashes, and host/tool versions.
Timeouts kill the process group, including debugger children. Each fixture
process receives a C locale with inherited LD_PRELOAD, LD_AUDIT, and
LD_LIBRARY_PATH removed. This controlled runner is not a security sandbox.

Exit codes are 0 for matched behavior (capability cases may be unavailable),
1 for failed checks, and 2 for infrastructure errors. `--require-capabilities`
makes unavailable cases fail the overall run. A crashed process, timeout, or
GDB startup failure never counts as an expected detection. Raw evidence stays
in ignored `out/`; publish only the reviewed reports you intend to retain.

## Repeated benchmark

```sh
python3 tests/anti_dynamic_harness.py --gdb --require-capabilities \
  --benchmark --iterations 30 --warmups 5 --seed 1729
```

Functional checks run before the benchmark. Every fixture is measured in
`--observe` mode so native and GDB invocations reach the same payload, including
the procfs tracer fixture. GDB forwards both signal probes. Mode/fixture order
is shuffled with the recorded seed within each round; invocations are serial.
Warmups and failed/unavailable invocations stay in the evidence but are excluded
from latency statistics. A group is complete only when all warmup and measured
invocations pass. Median, mean, sample standard deviation, nearest-rank p95,
and GDB/native median ratios are written to `report.json` and `report.md`.

The measured wall interval includes launch, GDB startup, fixture execution,
output capture, and process reaping. These short programs primarily measure
process/debugger startup cost. Ratios are not estimates of instruction-level
instrumentation overhead. This benchmark does not run Indago, compare tracing
engines, or establish robust evasion. Iterations default to 20 (range 1–1000),
warmups to 3 (range 0–100), and the shuffle seed to 1729.
