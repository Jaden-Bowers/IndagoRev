# Native tool field guide

Read only the section relevant to the current question. Do not run a checklist of
every engine. Prefer the already-active named tool. `tools_search` activates at
most twelve specialized tools at a time; it is not needed before common analysis.

## Understand selected native code

Use `decompile {"address":"current"}` for a GUI-selected function, or an explicit
VA returned by `functions`. `selection` requires one unambiguous quoted address.
Inspect `ghidra_assembly`, `xair_semantic` or `xair_cfg` when pseudocode leaves a
specific ambiguity. Use `airece_slice`/`airece_flow` for a bounded data-flow
question, not an automatic whole-program pass. Backend disagreement is evidence;
retain each native interpretation. File offsets, native VAs and managed tokens
are different address spaces.

## Find callers, inputs and comparisons

Use `xrefs` or `ghidra_calls` at the selected function. Resolve the concrete source
and sink before `airece_flow` or `sym_source_to_sink`. A solver timeout or unknown
does not mean unsatisfiable. Replay candidate inputs with the original target
only in a host-authorized session. `runtime_solve_input` consumes an observed
Frida input-comparison identity; it does not invent an input mapping.

## Containers and managed programs

Use `managed_artifact` to inspect supported containers/documents/WASM. Use
`transform_run` with `spec:{"method":"container_member","entry":"literal/name"}`
to publish a supported member with lineage. For archive formats outside that
parser use `artifact_inspect` with the pre-resolved archive tool. For JAR/class
bytecode use `artifact_inspect` operation `bytecode`. Imported .NET dependency IDs
belong in `managed_decompile.dependencies`; do not put host paths in that field.
Read source files with normal file tools rather than native decompilers.

## Decode bytes and test an algorithm

For a known finite transform, prefer native operations:

```json
{"offset":0,"size":4,"spec":{"method":"xor","key_hex":"01"}}
```

That is a `transform_run` request. Its output is a derived artifact, not proof the
target applies XOR. `calculation_evaluate` supports a bounded finite expression:

```json
{"source":{"offset":0,"max_bytes":4},"iterations":4,"emit":["xor",["byte","i"],1]}
```

For algorithms outside those operations, use `helper_run` only when its native
confinement environment is available. Example Python helper with generated input:

```json
{"language":"python3","source_code":"import sys\nsys.stdout.buffer.write(bytes(b ^ 1 for b in sys.stdin.buffer.read()))\n","input":{"generated_hex":"41424344"},"validation":{"kind":"none"}}
```

Use `algorithm_candidate` to pin the hypothesis, source, tested domain and input
generator; run those exact bytes through helper and original-target experiments;
then `algorithm_compare` retains agreement and counterexamples. Repair source
based on concrete diagnostics. Do not call finite agreement universal equivalence.
Windows-native confined helpers are unavailable: use a configured Linux native
session or report that limitation, never silently downgrade to unrestricted host
execution. Ordinary coding/shell tools remain a separate, explicit host facility.

## Debug or collect observations

Use `tools_search {"query":"runtime_launch runtime_breakpoint runtime_continue"}`.
`runtime_launch` binds the active hashed binary and returns a session ID.
Use that exact ID for subsequent operations; never guess the latest session.
Breakpoints accept a static VA or explicit runtime address; resolve mappings first.
Use `runtime_instrument` with backend `frida` and a focused recipe, or `dynamorio`
with bounded telemetry. `runtime_capture` → `runtime_reanalyze` preserves code-epoch
identity. `experiment_run` compares one or two reproducible cases using existing
engines; stdout agreement alone is not acceptance. rr is supported Linux only.

If a call is pending/interrupted, inspect `runtime_status` and `runtime_request`,
or `workflow_status` / `experiment_reconcile`. Do not repeat an uncertain mutation.
Cancellation is a request, not proof that every target side effect was undone.

## Packet evidence, services and guests

`packet_inspect` reads offline packet evidence; `runtime_network` reads observations.
Use `service_contract` to distinguish captured responses, inferred responses and
invented experimental stimuli. Use `service_observe` to compare against a pinned
capture. Simulated responses cannot prove an original service would behave that way.
`guest_run` uses only operator-granted, pinned QEMU profiles; guest provisioning,
network configuration and security assessment remain operator responsibilities.

## Evidence, edits and finishing

Native pagination retrieves more evidence. `evidence_read` retrieves another page
of a result already collected; `native_evidence_read` follows native evidence IDs
and pointers. `function_views` keeps Ghidra/AIRECE claims separate. Retrieve narrow
graph neighborhoods and relevant knowledge rather than replaying old logs.

Renaming/retyping/commenting requires an annotation grant and the current Ghidra
revision. Re-read after a conflict. A GUI selection is invalid after its source or
revision changes. Record concise established facts, candidate, failed approach
and unresolved obligation. A `reason_solution` record is not independent grading.
Report the supported conclusion and remaining uncertainty; tool markup is not a
final answer.
