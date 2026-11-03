# Anti dynamic analysis fixture benchmark

The 2026-11-03 baseline passed 61 functional scenarios and all 420 benchmark
invocations across six Linux fixture binaries. All 12 fixture/mode groups have
30 valid measured samples plus five excluded warmups. There were no failed,
unavailable, or timed-out invocations. The harness also passed its 17 unit
tests and all three registered CTest suites, including the opt-in GDB suite.

The benchmark measures the fixtures under native execution and GDB. It does
not run the Indago analysis engine. The complete generated tables are in
[baseline/report.md](baseline/report.md), with every command, expected result,
stdout/stderr, exit code, timing sample, source hash, and binary hash retained
in [baseline/report.json](baseline/report.json).

## Measured results

All timings below are milliseconds of wall time per fresh invocation, including
process launch, GDB startup when used, output capture, and process reaping.
Every measured invocation uses `--observe` so both modes reach the payload.

| Fixture | Native median | Native p95 | GDB median | GDB p95 |
| --- | ---: | ---: | ---: | ---: |
| ptrace_guard | 0.976 | 1.147 | 125.057 | 144.096 |
| tracer_status | 0.789 | 0.944 | 123.133 | 138.854 |
| encrypted_records | 0.739 | 0.909 | 123.462 | 140.723 |
| timing_guard | 3.879 | 4.238 | 123.433 | 139.069 |
| signal_guard | 0.744 | 0.879 | 130.835 | 143.669 |
| encrypted_code | 0.766 | 0.920 | 124.869 | 138.856 |

The GDB/native median ratios range from 31.82x to 175.82x. The approximately
120–130 ms startup interval dominates these short programs; these ratios do
not isolate instruction instrumentation cost or encryption cost. The timing
fixture does more native work, so its ratio is smaller. Signal forwarding uses
a conditional GDB catchpoint and explicit signal delivery, which adds work to
that scenario.

## Behavioral coverage

| Technique | Verified behavior |
| --- | --- |
| ptrace | Native and GDB-parent runs reach the expected first-success/second-EPERM branch and fixed digest. GDB follows the parent and detaches from its forked child; this does not test a debugger following that child. |
| Procfs | Native snapshots have TracerPid 0. GDB strict mode sees a nonzero tracer and exits 10 without a payload; observation mode reaches the expected digest. |
| Encrypted records | The fixed digest and all three plaintext records match; default execution does not print plaintext. The binary performs its re-encryption comparison. |
| Timing | The 60-second baseline threshold passes. A zero threshold produces three slow samples and exits 10; observation mode permits the same digest. |
| Signals | Native and selectively forwarded GDB signals produce counters 2/2 and order 1212. Suppressing SIGTRAP produces 0/2 and order 11, gating the payload unless observation mode is enabled. |
| Encrypted code | Inputs 0, 1, 7, and 42 return 3, 10, 52, and 297. The decoded checksum and final completion marker match. The fixture checks re-encryption before wiping/unmapping. |

The 61-scenario matrix also covers help, unknown/positional arguments, duplicate
observation flags, malformed timing limits, strict/observe behavior, and GDB
execution of every fixture. System denials, crashes, missing output, and GDB
startup errors cannot count as expected detections. The unit suite exercises
the runner's timeout cleanup of a process with a descendant, result
classification, statistics, and reproducible shuffled ordering.

The benchmark checks observable behavior and fixture self-checks. It does not
independently dump process memory to prove erasure, inspect page tables to
verify W^X, or show that a reverse engineering tool cannot recover the data.
Runtime integrity-failure branches and the altered/intercepted-ptrace branch
are not deliberately injected by this matrix.

## Environment and provenance

- Harness/fixture source revision: `cfdfd8c28b99105a88b125f10014863137a7da07`.
- Run start: 2026-11-03 21:47:55 UTC.
- Host: Linux 6.6.87.2 Microsoft WSL2, x86-64, glibc 2.39.
- CPU: Intel Core i7-13650HX, 20 logical CPUs; allowed affinity recorded in JSON.
- Compiler: Ubuntu GCC 13.3.0; CMake 3.28.3; Python 3.12.3.
- Debugger: Ubuntu GDB 15.0.50.20240403.
- Target flags: `-std=c11 -O0 -g -fno-inline -Wall -Wextra -Wpedantic -Werror`.
- Method: serial shuffled rounds, seed 1729; five warmups and 30 measured rounds.
- Execution timeout: 15 seconds per invocation; native timing threshold 60000 ms.

The run required host ptrace permission and was performed outside the agent's
restricted sandbox. The report records the pre-existing dirty `xair/XAIR_SYM`
submodule; the standalone fixture build uses no XAIR components. The raw report
also records local paths for its exact commands. Debug paths, compiler versions,
and toolchain changes can change binary hashes on a different host.

## Reproduce

From the repository root, with Python 3.10+, CMake 3.25+, GCC or a compatible
Linux C compiler, and GDB installed:

```sh
cmake -S tests/fixtures/anti_dynamic -B out/anti-dynamic-benchmark/build \
  -DINDAGO_ANTI_ENABLE_GDB_TESTS=ON
cmake --build out/anti-dynamic-benchmark/build --parallel 2
ctest --test-dir out/anti-dynamic-benchmark/build --output-on-failure
python3 tests/anti_dynamic_harness.py \
  --build-dir out/anti-dynamic-benchmark/build \
  --gdb --require-capabilities --benchmark \
  --iterations 30 --warmups 5 --seed 1729
```

No Python packages, network downloads, container runtime, or external services
are required. Each run writes a new report directory under ignored
`out/anti-dynamic-harness/`; `--report-dir` can choose another fresh directory.
Build/test and runner options are documented in the
[fixture README](../../tests/fixtures/anti_dynamic/README.md).

This is one development baseline on a shared WSL2 host. CPU placement,
frequency, load, cache state, and ASLR were not pinned. Warmups are excluded;
p95 uses the nearest-rank sample quantile and standard deviation is the sample
standard deviation. No confidence intervals, repeated independent host runs,
comparative tracing-engine results, or evasion success rates are claimed.
