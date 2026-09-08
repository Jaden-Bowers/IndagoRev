# Static/dynamic analysis depth

This development increment implements stronger runtime feedback, bounded
post-instruction memory observations, and deeper native Ghidra recovery.
It does not add another debugger or instruction-semantics implementation.

## Runtime feedback

Use `runtime feedback --project NAME --session RUN --observation OBS --backend xair`.
`ghidra` is also supported. The observation determines the operation:

- `module_loaded`: verify the recorded file hash, import that module, preserve
  its runtime origin, and run inventory/functions analysis.
- `control_transfer_taken`: publish an `observed_control_flow` relationship in
  the static index under producer **runtime**, and analyze the destination CFG.
  Both endpoint artifacts and static/runtime addresses remain intact. Native
  AIRECE/XAIR and Ghidra CFGs are not rewritten or treated as equivalent.
- Captured code, executed block epochs, or `write_execute`: import the observed
  bytes into the existing synthetic analysis container and retain lineage back
  to the code observation and, when available, the completed-write observation.

Transfer attempts are insufficient: the collector must observe the matching
target block entry on the same thread. The observation retains its linked
attempt record. Unmapped endpoints remain runtime evidence; use captured-code
reanalysis rather than assigning them an invented static artifact.

Inspect published relationships with
`index relations --project NAME --backend runtime --kind observed_control_flow`.
Each feedback observation has its own analysis scope; repeated publications
remain versioned. Module imports become normal project targets, so specify a
target/artifact explicitly when subsequently analyzing a different image.

DynamoRIO reports bounded module load/unload records, including file identity
and load addresses. File hashes are collected **after** the run, with a 256 MiB
aggregate hashing budget; they do not prove that loaded memory matched those
files. Missing, changed, truncated or over-budget files retain diagnostics.
Feedback verifies the hash again before importing. Frida module observations
use the same explicit import/feedback path.

## Memory completion and write/execute links

Instrument request:

```json
{"telemetry":"effects","code_scope":"application"}
```

`main` collects main-image code; `application` adds unmapped code, including
generated-code candidates; `all` includes other modules as well. Module events
are bounded separately to 256. Execution/effect events retain the 10,000-event
maximum and normal run/cancellation limits.

`memory_effect` retains the pre-instruction attempt. A safe fall-through
post-instruction callback adds `memory_effect_completed`, with its attempt ID,
address and up to 16 observed after-bytes. `write_confirmed` is true only for
the narrow native DynamoRIO `OP_mov_st` class that reached that callback.
Other instructions retain completion snapshots without claiming a conditional
write committed. Control transfers, interrupts, system calls, faults, unsupported
instruction boundaries and exhausted budgets need not have completion records.

`write_execute` links a completed store's page history to a later block entry,
its byte epoch and the persistent write observation. This is **not** proof of
sole causation: another thread may change memory, the mapping may be reused,
or the executed bytes may occupy a different part of the same page. Snapshots
are not atomic cross-thread state, complete memory tracing, or record/replay.

## Ghidra recovery

The existing `control_flow` operation now includes:

- `exception_relations`: protected-function to handler associations obtained
  from Ghidra's typed runtime-function/unwind data, including bounded pointer
  traversal, plus GCC LSDA protected call-site/landing-pad associations from
  native analyzer annotations and references. These are not normal CFG
  successors or proven exception paths; type/filter selection is unresolved.
- `initialization_callbacks`: mapped PE TLS callbacks and ELF initializer/
  finalizer pointers. TLS discovery checks the native callback field because
  Ghidra may name the directory datatype `IMAGE_THUNK_DATA`.
- `virtual_dispatch`: native CALLIND sites, defining p-code IDs, and bounded
  constant-pointer-chain recovery to mapped functions. Unknown receivers stay
  unresolved; static writable-table contents are explicit assumptions.
- `virtual_table_slots`: bounded function-pointer slots in named virtual-table
  candidates, including primary Itanium address-point candidates. Table entries
  do not prove receiver compatibility or actual dispatch.

Handler, initializer and virtual-slot relationships, plus resolved
`static_dispatch_candidate` relationships, are indexed with their native
producer and source locations. Metadata traversal, pointer tables,
symbol scans and p-code traversal are bounded and cancellation-aware. Full
language-specific exception scope recovery, complete C++ class reconstruction,
and production qualification remain separate work.

## Focused checks

The development fixtures cover completed stores and transfer feedback into the
static index, module import with origin, generated-code write/execute reanalysis,
and C++ fixtures with PE SEH/TLS, ELF GCC LSDA/initializers and virtual dispatch.
Completed-write, transfer-feedback and generated-code checks passed for PE
x86/x64; generated-code checks also passed for ELF x86/x64. Ghidra handler and
callback recovery passed on PE64 and ELF64; PE64 also passed constant global
function-pointer recovery and persisted `static_dispatch_candidate` lookup.
Core contract and static-model
checks passed. These are focused functional checks, not an extensive robustness
or release-qualification suite.
