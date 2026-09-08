# Bounded development qualification — 2026-09-07

This is the retained **schema-6 external-harness milestone** report. Later schema-7
provider/controller work and its additional short tests are described in
[the built-in harness notes](builtin-harness.md). Binary hashes below identify the
earlier build, not a subsequently rebuilt executable at the same output path.

This pass checks the current native CLI/core milestone and the first external-owner
harness stage. It is **not production certification or a claim of automatic analysis
of arbitrary malware, protected programs or systems**.

## Time and execution policy

Windows suites use `tests/bounded_qualification.ps1`: a 480-second maximum suite
watchdog, with CTest cases individually limited to 180 seconds. Short smoke suites
used 120/180-second caps. The watchdog terminates only its own launched process tree.
Linux uses `timeout --kill-after=5s 480s` around
`tests/bounded_linux_qualification.sh`, with each child suite capped at 180 seconds.
No test run exceeded ten minutes; the longest completed run was 311 seconds.

The WSL native rebuild spent several minutes scanning/configuring the large source
and bundled-engine tree. Build time is separate from test execution time.
Only source-backed benign runtime fixtures were executed. The IR development corpus
was used for **static** analysis; no unidentified samples or FLARE-On binaries were
executed. No paid model endpoint, model key, VM, kernel driver or network experiment
was used.

## Results

| Check | Result | Observed duration |
|---|---|---:|
| Pre-harness Windows native suite, 11 cases | Passed | 169 s |
| Final Windows native suite, including harness, 12 cases | Passed | 166 s |
| Windows PE64/ELF64 complete static gate: import, inventory, functions, Ghidra decompile/tokens/CFG/types/variables/calls/xrefs, AIRECE flow/slice, XAIR semantics, persisted/rebuilt index | Passed | 297 s on corrected wrapper |
| Windows x64 runtime: persistent breakpoint, stack/registers, captured-state symbolic witness, watchpoint, multi-region reanalysis | Passed | 5 s |
| Windows x86 runtime, same workbench flow | Passed | 5 s |
| Windows generated-code write/execute recovery, runtime dependency/event packet, raw-telemetry bundle export/import | Passed | 2 s |
| New native harness and knowledge-negative tests | Passed, 2 cases | 2 s |
| Final Windows harness CLI: propose, execute real XAIR inventory, reuse job, context, evidence retrieval, partial report, release | Passed | 1 s |
| Linux knowledge/bundles using all five IR synthetic PE fixtures | Passed | 2 s |
| Linux harness PE, ELF64, ELF32 | Passed | 1 s / 1 s / <1 s |
| Linux runtime workbench, fresh ELF64/ELF32 compiled from `tests/runtime_fixture.c` | Passed | 2 s / 2 s |

The initial 60-second AIRECE test allowance was too short for its repeated PE/ELF
operation/view checks. It passed in 108 seconds with the bounded 180-second allowance.
The first Windows watchdog wrapper also refreshed away the process exit code and
reported a null value despite completed smoke assertions. That wrapper defect was
fixed; the native and static suites were rerun. Original logs remain for audit.

## Improvements made after review

- Bundle imports now validate the declared single-project snapshot, runtime record
  scope, terminal jobs/sessions, observation hashes and runtime relationships before
  publishing a workspace. Checksums are integrity checks, not trusted authorship.
- Both manifest paths receive containment checks. Bounded file reads detect a
  changing file length instead of allowing growth beyond their byte ceiling.
- Removed a chained increment in SQL limit/offset binding to make sequencing explicit.
- Investigation ownership/runner leases cannot be restored from a bundle. A live
  controller must release ownership before export; stale leases are stripped.
- Added rejection tests for forged/mismatched project declarations, active jobs,
  active sessions and cross-project runtime records.
- Added native [harness ownership, recovery, budgets and reporting](harness.md),
  including a lost-proposal-response regression that prevents double charging.

## Build identity and retained evidence

Both primary executables include the native harness and use workspace schema **6**.
Older executables reject that schema so older retention/export implementations cannot
silently overlook investigation records. Existing schema-5 workspaces migrate on open.

| Binary | Bytes | SHA-256 |
|---|---:|---|
| `out/build/Release/indago.exe` | 1,313,226,240 | `dc98d561d3be23c59169f488aba98b2335abf95401d2fe7ec41fd32a4431254d` |
| `out/linux/indago` | 1,452,619,968 | `b4c7dcb256b8532c42ce61f99c9253c3785403fa62f40ddaf37f6a765aef88ad` |

Windows machine-readable results/stdout/stderr are in `out/qualification-*/`.
Notable final runs:

- Native, 12/12: `out/qualification-native-97bf9799035b48ac8138a2b33360da53/`
- Static: `out/qualification-static-9dc8c626c5a94b95886e75d22b5927f3/`
- Runtime x86: `out/qualification-runtime-d6468d129b15458f8fcd6877dc911688/`
- Runtime evidence: `out/qualification-runtime-evidence-d03cb2d0c30240dda98367abf98163e5/`
- Harness CLI: `out/qualification-harness-06ea5fed81dd4ac2af6c81cc3d8e98fa/`
- Linux aggregate: `out/harness-linux-qualification.log`; detailed logs and fresh
  fixtures: WSL `/tmp/indago-linux-qualification.wBdz4O/`.
- Builds: `out/harness-final-build.log`, `out/harness-tests-build.log`, and
  WSL `/home/jaden/.cache/indago/harness-build.log`.

Test workspaces are retained in the log-reported temporary locations. No material
user files were deleted. The retention unit test moves only its own synthetic orphan
into recoverable quarantine.

## Not covered by this pass

Long fuzzing/soak, hostile-parser isolation, concurrency stress, full architecture/
compiler/OS matrices, all Ghidra operations on 32-bit targets, reverse-engineering
answer correctness, model/provider qualification, kernel/whole-system analysis,
replay, VM lifecycle and multi-process system-level acceptance remain unqualified.
The first harness stage has no built-in inference or generated-code execution.
Read its explicit remaining-work list before treating it as the full planned harness.
