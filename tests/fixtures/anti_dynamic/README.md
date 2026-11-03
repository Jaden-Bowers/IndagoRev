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
