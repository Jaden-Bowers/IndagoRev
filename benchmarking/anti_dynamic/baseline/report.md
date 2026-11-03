# Anti dynamic analysis fixture benchmark

Started (UTC): `20261103T214755Z`

Source revision: `cfdfd8c28b99105a88b125f10014863137a7da07`

Host: Linux-6.6.87.2-microsoft-standard-WSL2-x86_64-with-glibc2.39; Python 3.12.3.

CPU: 13th Gen Intel(R) Core(TM) i7-13650HX; logical CPUs: 20.

Functional checks: `{'passed': 61}`. Overall exit code: `0`.

Measured rounds: 30; warmup rounds: 5; shuffle seed: 1729.

All benchmark groups complete: **True**.

Each invocation uses `--observe`; GDB forwards probe signals. Wall time
includes process launch, debugger startup where applicable, fixture work,
output capture, and process reaping. Warmups are excluded from statistics.

| Fixture | Mode | Valid/requested | Median ms | p95 ms | Mean ms | Stdev ms | Complete |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ptrace_guard | native | 30/30 | 0.976 | 1.147 | 0.952 | 0.105 | True |
| ptrace_guard | gdb | 30/30 | 125.057 | 144.096 | 126.519 | 7.602 | True |
| tracer_status | native | 30/30 | 0.789 | 0.944 | 0.787 | 0.090 | True |
| tracer_status | gdb | 30/30 | 123.133 | 138.854 | 124.292 | 6.665 | True |
| encrypted_records | native | 30/30 | 0.739 | 0.909 | 0.738 | 0.095 | True |
| encrypted_records | gdb | 30/30 | 123.462 | 140.723 | 125.504 | 8.743 | True |
| timing_guard | native | 30/30 | 3.879 | 4.238 | 3.891 | 0.233 | True |
| timing_guard | gdb | 30/30 | 123.433 | 139.069 | 124.721 | 6.663 | True |
| signal_guard | native | 30/30 | 0.744 | 0.879 | 0.741 | 0.071 | True |
| signal_guard | gdb | 30/30 | 130.835 | 143.669 | 131.458 | 6.962 | True |
| encrypted_code | native | 30/30 | 0.766 | 0.920 | 0.762 | 0.104 | True |
| encrypted_code | gdb | 30/30 | 124.869 | 138.856 | 127.419 | 9.924 | True |

| Fixture | GDB/native median wall-time ratio |
| --- | --- |
| ptrace_guard | 128.07x |
| tracer_status | 156.10x |
| encrypted_records | 166.98x |
| timing_guard | 31.82x |
| signal_guard | 175.82x |
| encrypted_code | 163.06x |

These are fixture/process latency measurements, not Indago throughput or
debugger evasion success rates. GDB startup dominates short programs;
ratios must not be interpreted as instruction instrumentation overhead.
Host load, caching, ASLR, and scheduling are uncontrolled. p95 is the
nearest-rank sample quantile; this single-host run provides no confidence
interval or cross-machine generalization. Failed, timed-out, unavailable,
and warmup invocations are excluded from timing statistics; an incomplete
group is labeled and does not receive an overhead ratio.

See `report.json` for every raw invocation, expectation, and artifact hash.
