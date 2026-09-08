# Runtime workbench implementation record

This records the bounded implementation of the eight requested CLI workstreams,
not a production qualification or a claim of universal coverage.

Subsequent improvements to memory completion, runtime feedback and Ghidra
recovery are documented in [analysis depth](analysis-depth.md).

- Linux: private source-built GDB 17.1, Python/Guile disabled, bounded MI adapter.
  The old ptrace source is not selected by CMake. GDB owns process control,
  breakpoints, unwinding and registers.
- Debug controls: stack/crash inspection, step-over/out, native breakpoint IDs,
  persistent/conditional/deferred breakpoints, watchpoints and process inventory/
  selection. New options use runtime JSON requests (`one_shot`, `condition`,
  `expression`, `hardware`, `access`, `follow_children`, `breakpoint_id`).
  Child following is opt-in for debugger launch/attach. Process selections retain
  separate process/address-space/module/thread identities; observed child births
  retain parent identity when available. Linux also stops on fork/vfork/exec.
  PID-only parent observations outside the debug session are not invented identities.
- DynamoRIO: `telemetry: "effects"` adds pre-instruction memory operand and
  control-transfer observations. `code_scope: "all"` includes non-main-image
  code. Effects are attempted accesses, not confirmation that an instruction
  completed. Sampled block bytes retain epochs and preceding page-write-attempt
  sequence links. Budgets and incomplete coverage remain explicit.
- Frida: `config` and `network` recipes, module-load hook installation, and
  `runtime instrument --backend frida --pid PID`. Attach cancellation detaches
  instrumentation; it must not kill the existing process. Spawned bounded
  experiments retain their existing termination policy.
- Ghidra: defined exception/TLS metadata, address-taken reference candidates,
  and revisioned `create_structure` annotations under `/IndagoUser`.
- Captures: `code_regions` records bounded discontiguous reads during one stop.
  Each region has an epoch and read interval. Reanalysis makes separate ELF RX
  segments, preserves individual raw artifacts, and rejects overlaps or groups
  from incompatible capture stops. Shared memory can still change externally.
- Symbolic: optional `path` lists up to 16 captured native block addresses.
  Native SSA bindings, memory state and branch constraints cross block edges.
  Paths may span discontiguous code regions belonging to the same capture group.
  Unresolved edges/calls are rejected or remain native partial results; external
  calls are not silently assumed successful.
- `validate-witness` explicitly applies a stored SAT model to the still-stopped
  captured state and single-steps toward the predicted destination. It changes
  inputs and advances the target. It is a bounded current-state oracle, not
  record/replay or proof of reachability from entry. Register/code/captured-memory
  changes reject stale requests; code-overlapping input writes are rejected.

GDB source archive is retained in `vendor/gdb` and embedded with its license.
The build helper also stages the non-libc shared dependencies and notices.
Upstream GDB MI protocol: https://sourceware.org/gdb/current/onlinedocs/gdb.html/GDB_002fMI.html

## JSON request examples

Pass these objects with `runtime OP --project NAME --session ID --request FILE`.
Existing direct CLI options continue to work. Backend expression syntax remains
native (GDB expressions on Linux, DbgEng expressions on Windows).

```json
{"static_address":"0x140001000","one_shot":false,"condition":"@rcx == 7"}
```

The above is a Windows `breakpoint` request. Use `breakpoints` to obtain a
`native_breakpoint_id`, then `remove-breakpoint` with `{"breakpoint_id":"ID"}`.
For `watchpoint`, use `{"address":"0xADDRESS","size":4,"access":"write"}`.
Windows x86 hardware does not support read-only watches; use `readwrite` when
that broader scope is acceptable. `stack`, `crash`, `processes`, `step-over` and
`step-out` accept the normal session options. `select-process` takes `pid`.

For launch: `{"argv":["arg"],"follow_children":true}`.
For instrument: `{"telemetry":"effects","code_scope":"all"}` with DynamoRIO,
or `--backend frida --recipe config` / `network`; Frida accepts `--pid` for attach.
Instrument collectors are single-process; debugger child following is not an
implicit request to inject instrumentation into every descendant.

For capture:

```json
{"size":256,"code_regions":[{"address":"0xOTHER_REGION","size":128}],"memory":[{"address":"0xDATA","size":128}]}
```

For symbolic: `{"observation":"CAPTURE_ID","path":["0xPC","0xNEXT_BLOCK"],"symbolic_registers":["rdi"]}`.
For the **mutating** witness experiment:
`{"observation":"SYMBOLIC_ID","terminal_index":0,"branch_index":0,"max_steps":128}`.
Supply actual hexadecimal addresses in place of the placeholders above.

Ghidra `annotate` retains the current `expected_revision` guard. A structure
annotation is `{"kind":"create_structure","name":"Record","size":8,"fields":[{"name":"field","offset":0,"type_path":"/int"}]}`;
field type paths must exist in that program's datatype manager.

## Focused development verification

- PE32 and PE64: persistent breakpoint, native stack/extended registers, concrete
  witness, hardware write watchpoint, step-out, two-region static reanalysis.
- ELF32 and ELF64: the same workflow using private GDB, plus baseline debug smoke.
- Windows and Linux: child inventory/selection and persisted parent/child identity.
- Windows PE32/PE64: effects/transfer collection and Frida attach deadline leaving
  the existing fixture alive; Windows Frida code capture/reanalysis and bounded
  DynamoRIO cancellation regression checks.
- Linux ELF32/ELF64: DynamoRIO bounded/cancelled collection and Frida generated
  code capture/reanalysis, API records and collection limits.
- Final Linux payload rebuild: configuration/network recipe checks and Frida
  capture/reanalysis passed with the updated synchronous module-load hooks.
- Windows: configuration API records and an immediate call into late-loaded
  `ws2_32.dll` are observed by the network recipe. The fixture uses an invalid
  socket, so this check sends no network traffic.
- Ghidra: pagination, p-code evidence, token offsets, persistent revisioned edits,
  structure creation and native difficult-control-flow coverage export.
- Native XAIR selected-path check: preceding branch constraint reaches the final
  branch and excludes the infeasible outcome.

The narrow XAIR builder extension is retained as
`components/patches/xair-block-reopen.patch` against the locked upstream revision.
It reopens unfrozen blocks for CFG stitching; it adds no instruction semantics.

## Explicit limits

Ghidra exception/TLS exports are native associations and candidates, not a guarantee
of complete exception edges or proven virtual dispatch. DynamoRIO effects include
attempts and narrowly confirmed post-instruction stores; sampled code prefixes and
bounded page-write links are not complete memory tracing. Extra-module locations may remain unanchored when
no image identity was captured. Frida recipes export bounded API arguments/results,
not complete application protocol reconstruction. Symbolic external calls retain
native unresolved/partial handling; no implicit success model, full SIMD state,
deterministic replay, or whole-process taint is claimed. These are coverage limits,
not successful proofs. rr/PANDA and production qualification remain separate work.

GUI/MCP/harness/terminal UI and extensive robustness testing were not included.
