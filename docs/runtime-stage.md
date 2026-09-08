# Native runtime stage

Indago now has persistent native debugger sessions through the CLI. A session
is owned by another instance of the same `indago` executable (`__runtime`), not
by a Python service. Separate CLI invocations communicate through a durable
SQLite request queue. All debugger calls happen on the owning worker thread.

## Scope and safety

- Windows x64 host: PE x64 and PE x86/WOW64 targets, using privately bundled DbgEng.
- Linux x64 host, including WSL: ELF x64 and ELF x86 targets, using private GDB/MI.
- DynamoRIO instrumentation is separate from debugging and supports both formats
  on their native host. See [bundled engine workflow](runtime-engines.md).
- Static XAIR/AIRECE and installed Ghidra queries remain separate from execution.
  Both formats can be statically analyzed on either host.
- Execution requires `runtime launch --file ...` or `runtime attach --pid ...`.
  Importing, indexing, decompiling, and symbolic analysis do not execute targets.
- **This is host execution, not a sandbox.** Only run trusted fixtures here or
  use a disposable lab VM for untrusted binaries. No privilege escalation or
  host debugger-policy changes are performed automatically.
- Attach requires OS permission. Linux Yama/container policy can deny it;
  protected Windows processes are outside this implementation's scope.

This implements the basic debugger-backed slice, not the entire M3 autonomous
runtime product. Initial bundled Frida recipes and byte-identity feedback are
documented in [runtime feedback](runtime-feedback.md). Kernel/driver debugging, multi-process
coordination, anti-debug handling, and full dynamic taint remain future work.

## CLI workflow

Use the same project/workspace for static and runtime operations. Examples use
`indago`; substitute `out/build/Release/indago.exe` on Windows.

```text
indago --workspace work project create --name demo
indago --workspace work target import --project demo --file sample.exe
indago --workspace work query --project demo --backend xair --operation inventory
indago --workspace work query --project demo --backend xair --operation cfg
indago --workspace work query --project demo --backend ghidra --operation functions

indago --workspace work runtime launch --project demo --file sample.exe
```

Launch returns an `id` such as `run_...` and stops before normal execution:
Windows at its initial loader breakpoint, Linux at the initial exec event. Attach stops an
existing process. The original executable path is used (rather than its hashed
content-store copy), preserving ordinary executable-relative behavior. Launch
imports and verifies its file hash; this does not eliminate filesystem races or
prove that all subsequently mapped/executed bytes match the file.

```text
indago --workspace work runtime modules --project demo --session run_ID
indago --workspace work runtime resolve --project demo --session run_ID --static-address 0x140001000
indago --workspace work runtime breakpoint --project demo --session run_ID --static-address 0x140001000
indago --workspace work runtime continue --project demo --session run_ID --wait true
indago --workspace work runtime registers --project demo --session run_ID
indago --workspace work runtime capture --project demo --session run_ID
indago --workspace work runtime step --project demo --session run_ID
indago --workspace work runtime trace --project demo --session run_ID --max-steps 128 --timeout-ms 5000
indago --workspace work runtime observations --project demo --session run_ID --kind capture
indago --workspace work runtime detach --project demo --session run_ID
```

Windows may first stop at the loader's initial breakpoint. Inspect the event and
continue again to reach your breakpoint. Other exceptions/signals are retained,
not silently swallowed. `continue` returns immediately by default; `--wait true`
waits within the deadline and attempts to pause the target if the deadline expires.

Address selectors:

- `--address`: literal runtime VA.
- `--static-address`: original image VA, relocated through a loaded module.
- `--rva`: offset from the loaded module base.
- `--function fn_ID`: existing shared static function identity.
- `--artifact SHA` and/or `--module mod_ID`: disambiguate module instances.

Without an explicit artifact, a launched session defaults to its imported image.
An ambiguous module returns an error. Deferred module breakpoints are now supported
by the [runtime workbench](runtime-workbench-progress.md). `resolve` returns the static location anchor and indexed backend
entities at that anchor, retaining AIRECE/Ghidra as separate views.

Additional commands: `sessions`, `status`, `threads`, `pause`, `memory`,
`remove-breakpoint`, `cancel`, `terminate`, and `request --id rtq_ID`. Every
session command requires `--project` and `--session`. Request lookup retrieves a
pending or completed command without replaying it. Do not blindly retry a
state-changing command after a client timeout. Queue ordering is serialized;
the production idempotency/recovery story for runtime is not yet qualified.

Software breakpoints default to **one-shot**; `one_shot:false` requests persistence
through the native debugger. Detach restores remaining breakpoints
and lets the process continue. `terminate` explicitly kills only the debugged
process. Neither operation promises to terminate independently spawned children.
The default session lifetime is 30 minutes, configurable with `--lifetime-ms`
up to 24 hours; expiration attempts a clean detach, not a kill.

`--signal 0` preserves the backend's normal signal/exception disposition.
Linux additionally accepts a signal number 1–64 or `-1` to suppress delivery.
Windows accepts `1` for not-handled or `-1` for handled. This can change target
behavior, so override only deliberately.

## Captures and concrete-seeded symbolic work

`capture` records general-purpose registers, flags, 64 bytes at the stopped PC,
and explicitly selected memory ranges. SIMD/FPU registers are not captured.
Supply ranges through a JSON request file; addresses below are illustrative:

```json
{
  "memory": [
    {"address": "0x000000000020f000", "size": 1024}
  ]
}
```

```text
indago --workspace work runtime capture --project demo --session run_ID --request capture.json
indago --workspace work runtime symbolic --project demo --session run_ID --observation obs_ID --mode solve_branch --request symbolic.json
```

For a symbolic input, explicitly relax a captured register or captured bytes:

```json
{
  "symbolic_registers": ["rcx"],
  "symbolic_memory": [],
  "timeout_ms": 1000
}
```

Alternatively use `"symbolic_memory": [{"address":"0x...","size":1}]`.
Every symbolic byte must exist in the referenced capture. Register names must
match native inputs to the lifted block; Windows x64 arguments often start in
`rcx`, Linux x64 in `rdi`, and x86 arguments commonly reside on the stack.
These are caller-selected assumptions, not automatic calling-convention guesses.

XAIR lifts the **captured live bytes**, not a second hand-written x86 semantics
layer. Its native input-register/value and flag mappings seed XAIR_SYM. Captured
memory seeds native memory objects. Selected symbolic inputs also receive native
taint labels. The output retains native status/completion/verdicts, expression
DAGs, taint IDs, captured provenance, and missing-state assumptions.

Modes are `solve_branch`, `path_condition`, `symbolic_slice`, `taint`, and
`source_to_sink`. These are deliberately block-local:

- Branch checks explore both polarities of the native block condition. Models
  are solved under that specific polarity; they are not replayed automatically.
- Path conditions and slices expose the block's native expression dependencies,
  not a reconstructed full execution path.
- Taint exposes native labels on outputs and the branch condition.
- `source_to_sink` additionally requires symbolic inputs and a `sink` output
  register in the request JSON. It reports matching native output findings.

Uncaptured memory, external calls, TLS, opaque instructions, and missing vector
state can make results partial. Symbolizing a register does not retroactively
change captured flags or other state. A SAT result is not a reachability proof
from process entry. These derived results do not modify the live process and
remain usable after detach because they depend on persisted captures.

## Evidence, identity, and bounds

The workspace's `runtime.sqlite3` (version 1) holds sessions, requests, and
append-only observations with SHA-256 checks and indexes by session, kind, and
static anchor. It does not change the static database's version 3 schema.
Observation hashes cover the original stored record; CLI response fields such
as `request_id`, `status`, and `sha256` are transport annotations.

Each execution gets a session/process instance identity, native PID/thread IDs,
thread instance IDs in snapshots, and module-load instance IDs. Module path/hash,
load base, image base, and RVA establish file-location links. Those links are
explicitly marked **file identity only**: self-modification and instrumentation
can make live code differ from the file. Actual captures retain their bytes.
Module observations are a stop-time/debug-event inventory, not complete loader
telemetry; Linux load/unload events between snapshots can be missed.

Default/hard limits:

- Runtime request: 64 KiB; response: 2 MiB.
- Memory: 64 KiB per read or aggregate capture, at most 16 capture ranges.
- Trace: default 128, maximum 10,000 instruction steps; 60-second maximum
  command deadline. `--from`/`--to` optionally restrict an inclusive/exclusive
  runtime address interval; leaving it ends the trace.
- Trace output contains at most 256 observation IDs. Read the remaining indexed
  observations with `--offset`/`--limit` (maximum 1,000/page).
- `runtime cancel` interrupts an active bounded trace. It is not a process kill;
  use `pause` to stop ordinary continued execution.
  For a separate `runtime instrument` run, cancellation terminates the target
  explicitly launched for that bounded run and retains partial evidence.
- Symbolic: at most 64 captured instruction bytes/32 instructions, 256 symbolic
  memory bytes, 16 symbolic register names, 64 MiB native analysis budget,
  10-second maximum wall deadline, 1 MiB result content.

Debugger tracing single-steps a selected thread. Linux uses GDB's native
all-stop scheduling; Windows uses DbgEng's native scheduling. It changes scheduling
and may block on synchronization/system calls; deadlines attempt to pause it.
This is not high-throughput tracing, record/replay, or whole-process taint.
Unexpected worker/host crashes, stale PID reuse, simultaneous breakpoint hits,
disk exhaustion, and teardown races remain production-qualification work.

## Build and development checks

Windows uses the existing x64 CMake build. The same executable debugs x86 via
WOW64. Linux also uses an x64 executable, with x86 compatibility in the kernel:

```sh
cmake -S . -B out/linux-build -G Ninja -DCMAKE_BUILD_TYPE=Release -DINDAGO_BUILD_TESTS=OFF
cmake --build out/linux-build --target indago -j6
```

The current WSL development build is at
`/home/jaden/.cache/indago/native-build/indago`; a copy is delivered at
`out/linux/indago`. Use Linux paths and a Linux-local workspace for live sessions.
Ghidra and its JDK are privately embedded on both platforms; an installed
Ghidra, Java, GDB or Python is not a runtime prerequisite. See the engine build
documentation for staging those payloads when rebuilding from source.

The Ghidra adapter now passes the file-preferred image base to its native ELF
loader, avoiding synthetic PIE offsets that would split otherwise matching
static/runtime locations. Its session key records this loader-policy change;
old immutable evidence remains historical and is not silently rewritten. If a
workspace path contains a dot-prefixed directory, only Ghidra's disposable
project cache moves to `TEMP/indago-ghidra-projects`; evidence stays in the
workspace.

`tests/runtime_smoke.ps1` and `tests/runtime_smoke.sh` exercise import/inventory,
launch, relocation, breakpoint, captured-state symbolic branch alternatives,
memory, step, trace, persisted evidence, and detach. `runtime_attach_smoke.*`
exercises attach/pause/detach. Build the harmless fixture with CMake target
`indago_runtime_fixture`, or compile `tests/runtime_fixture.c` for x86/x64.
These are development smoke checks, not the postponed production gate.
