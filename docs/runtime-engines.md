# Bundled native runtime engines

This is an initial engine-integration slice, not completion of every dynamic
milestone or a production qualification report.

## Implemented

- Windows debugger control now uses Microsoft's DbgEng interfaces, not the
  custom Win32 debugger. The old `src/runtime_windows.cpp` remains as historical
  bootstrap code but is not compiled or selected as a fallback.
- Launch/attach, one-shot breakpoints, registers, memory, modules, threads,
  continue, step, pause, detach and terminate retain the existing CLI surface.
  DbgEng owns exception processing, breakpoint bytes and instruction stepping.
  Requests that inspect a running debugger session require `runtime pause`.
- DbgEng's owner thread remains inside its event wait while running. The CLI
  worker remains responsive; SetInterrupt is the only cross-thread engine call.
- DynamoRIO 11.3.0 source tag is vendored at revision
  `59352ff71fefdb8542fc5bd2ae3b76181a50072e`. The Indago collector and deployment
  host are native C, built for each target bitness. No `drrun`, Python, service
  installation or system-wide DynamoRIO registration is required.
- Windows and Linux executables embed the matching engine/helper/client files.
  On first use, payloads are extracted into a per-user content-hashed cache.
  Existing mismatched payload files are rejected rather than silently replaced.
  Windows loads the private DbgEng DLL by absolute path with restricted DLL search.
  These are third-party components, not third-party software installations.

## Instrumentation CLI

Only use trusted fixtures on the host, or use a disposable lab VM. This is not
a sandbox. An instrument request with `--file` explicitly launches a new process.
Frida additionally accepts explicit `--pid` attach; it does not silently restart
an existing debugger session, and attach cleanup does not terminate its target.

```text
indago --workspace work runtime instrument --project demo --file sample.exe --max-events 1024 --timeout-ms 5000
indago --workspace work runtime status --project demo --session run_ID
indago --workspace work runtime observations --project demo --session run_ID --kind instrumentation_block --limit 100
indago --workspace work runtime observations --project demo --session run_ID --kind instrumentation_summary
indago --workspace work runtime cancel --project demo --session run_ID
```

The first command returns a session ID with `pending` while collection runs.
Poll `status` for terminal state and `result_status`. The immutable summary is
also referenced by `summary_id`. `argv` and `cwd` can be provided with the usual
runtime JSON `--request` file.

The collector observes **executed main-image basic-block entries**, including
repeated entries, native thread IDs, runtime PCs, RVAs and decoded block size.
It does not mistake translated-but-unexecuted blocks for execution. Normalized
locations link observations to the existing artifact/static anchors. Native
records remain available; instruction semantics still belong to XAIR.

Limits: 1–10,000 block events, 1–60,000 ms run duration, 4 MiB ingested event
file, 64 KiB helper output, paginated evidence. Reaching the event cap stops
collection but lets the target run until exit or the time limit. Cancellation
and the time limit terminate the explicitly launched target; interrupted
collection retains its readable prefix and is marked partial/cancelled. A
normal exit does not make a capped collection complete. No child tracing is
enabled. Production crash/orphan recovery remains unqualified.

The DynamoRIO collector is not instruction-value tracing, full memory access
tracing, API hooks, dynamic taint or record/replay. The separate bundled Frida
recipes and code-epoch/capture feedback are described in [runtime feedback](runtime-feedback.md).
`runtime trace` remains
the separate debugger-stepping operation. Instrument runs support status,
observations and cancel, not debugger commands.

## Rebuilding embedded components

Windows development prerequisites: CMake, VS 2022 C/C++ tools, Windows SDK and
Perl (the script can use Git for Windows' Perl). Run:

```powershell
./tools/build-runtime-engines.ps1
cmake --build out/build --config Release --target indago --parallel 6
```

Linux development prerequisites: CMake, Ninja, GCC/G++, Perl, x86 multilib,
GMP/MPFR/ncurses development packages and Texinfo for the private GDB build.
Run `bash tools/build-gdb.sh`, `sh tools/build-runtime-engines.sh`, and
`sh tools/build-frida.sh`, then rebuild the main native executable.
`INDAGO_ENGINE_BUILD_ROOT` selects its build cache; normal builds do not fetch
anything. `INDAGO_RUNTIME_PAYLOAD_DIR` can select the staged payload directory.
Linux x86 targets/helpers still require the operating system's 32-bit loader
and libc. The application does not bundle a replacement operating system.

The source build uses upstream engine boundaries. The Linux wrapper corrects
upstream's build-tree Release mapping and pins its bool feature result for a
GNU C11 build on GCC 15. These are build settings, not new instruction semantics.

DbgEng is pinned to NuGet `Microsoft.Debugging.Platform.DbgEng` version
`20260319.1511.0`. Its original SDK license and package metadata are retained in
`vendor/dbgeng`; DynamoRIO's full license is retained and embedded. DbgEng package
SHA-256: `875678516f9ceed4a1c8b9b106d165106fcaa38723ad7c584c47b95b231600de`.
Public distribution still needs the product's notices/EULA and redistribution
review; embedding does not remove upstream terms. No public release is made here.
DynamoRIO is a vendored source snapshot, not a Git submodule. Its upstream
revision marker is kept in the snapshot; the development clone's Git metadata
was archived locally at `out/vendor-history/dynamorio.git` without removing source.

## Development checks recorded

- DbgEng PE64 and PE32: static inventory/address resolution, breakpoints,
  captures, XAIR symbolic branches, debugger stepping and persisted observations.
- DbgEng attach/pause/detach on a trusted Windows fixture.
- DynamoRIO PE64, PE32, ELF64 and ELF32: executed blocks, static location links,
  event-limit partial results and cancellation.
- A copied Windows executable with no adjacent engine files ran both the
  DbgEng and DynamoRIO smoke workflows. A copied Linux executable ran the
  DynamoRIO workflow using embedded payloads.
- Four existing Windows core/version/capability/static-model checks passed.

These are small functional checks only, not robustness or production gates.

## Subsequent workbench update

See [runtime workbench](runtime-workbench-progress.md) for private GDB/MI,
debug controls and child following, effects telemetry, late Frida hooks/attach,
multi-region reanalysis, and selected-path symbolic/witness operations.
Ghidra and its JVM are now privately embedded as well.

## Still pending beyond the bounded workbench

- Universal post-instruction memory-effect confirmation and continuous complete
  write/execute coverage. Current records explicitly identify write attempts.
- rr/PANDA replay stages; Triton only if a measured XAIR_SYM gap justifies it.
- Production qualification, recovery hardening, packaging signing and distribution
  compliance. GUI, terminal UI and MCP/harness work are untouched.
