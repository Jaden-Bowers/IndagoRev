# Pre-Task 8 and bounded protection-analysis interfaces

The implementation profile is Linux x86-64 (including the Linux CLI in WSL).
Windows-native generated helpers still fail closed; explicitly assessed Windows
target experiments continue through the existing execution grant. This is not a
disposable malware lab, universal devirtualizer, or all-FLARE-On coverage claim.

## Contained model helpers

`workbench/helper.run` accepts `python3`, `c17`, `c++20`, `smt2`, and
`unicorn-x86`. The core/controller remain C/C++. Python uses the installed
interpreter with `-I -S -B`: no site initialization, user packages or package
installation. Both interpreter and standard-library tree hashes are sealed at
proposal and checked in both execution namespaces. System libraries/toolchains
remain operator-managed; these are content pins, not a remotely attested OS image.

The primary `input` accepts a 256 KiB scoped slice. Up to four additional
`inputs:[{name,target_id,offset,max_bytes}]` are admitted only from investigation
components, with a 1 MiB aggregate ceiling. Pins, not megabytes of hex, travel in
the action capsule. The worker receives primary bytes on stdin and named slices
at `/input/files/NAME`. All original hashes are rechecked at publication.

`output_files:[NAME]` requests regular files under `/tmp/output/NAME`, at most
four and 4 KiB total. Publication rejects links, nonregular files, excess bytes
and nondeterministic repeated results. Each file retains its hash and bytes in
the immutable helper receipt. `validation:{kind:artifact_bytes,output_file:NAME,
expected:{offset,max_bytes}}` validates a requested file against up to 4 KiB of
the original artifact. Without `output_file`, validation compares stdout.
No generated result is automatically admitted as a target or accepted as a solve.
The legacy `target_execution:false` helper field denotes no original host-target
launch action. Arbitrary confined helper code can interpret or emulate supplied
bytes; the field is not proof that no target-derived logic ran. It never confers
the separate original-target runtime grant or establishes behavioral acceptance.

Failed sources, exceptions and source revisions are retained as action receipts.
The model retrieves bounded diagnostics and proposes a new action with corrected
source. The same investigation model performs the repair; no second model is
required. The live repair fixture uses the external-owner harness API with one
local Qwen model; it is not a full built-in-controller benchmark.

## Shared Linux worker isolation

`isolated_worker.hpp` supplies a fail-closed systemd user-service/cgroup wrapper:
768 MiB aggregate memory by default, no swap, bounded tasks, one CPU worth of quota, a wall
deadline and control-group termination. Unique units are stopped and their state
checked after execution. Bubblewrap supplies user/PID/network/IPC isolation,
read-only admitted inputs, a private 64 MiB temporary filesystem and replaced
environment. The user service manager, cgroup delegation and bubblewrap are
operator prerequisites; no privilege or host-kernel-policy fallback is attempted.
Enrichment has a measured larger profile: 2 GiB aggregate memory and 256 MiB
temporary storage for its packaged runtime/signature databases. Other profiles
retain their smaller limits. Resource-manager failure reasons, including OOM,
are retained in bounded diagnostics.

Helpers retain their additional seccomp restrictions and per-process limits.
Managed/artifact parsing uses scoped mounts and returns extracted bytes through a
bounded private receipt channel rather than a writable host directory. LIEF,
enrichment workers and upstream packet dissection use the shared parser wrapper.
Windows parser workers use per-process committed-memory limits where configured;
they are not described as filesystem sandboxes. Persistent Ghidra sessions and
trusted original-target debugger runs are not migrated to this Linux parser
profile. Disposable guest execution and hostile-parser qualification remain
separate work; do not infer unattended-execution authority from these profiles.

## Bounded x86/x64 emulation

Build the separate GPL-2.0 Unicorn worker with `tools/build-emulation.sh` or
`tools/build-emulation.ps1`, then reconfigure Indago to embed the staged worker
and notices. CMake verifies the pinned 2.1.4 source archive. The MIT controller
communicates via JSON and does not link Unicorn. No new x86 semantic layer exists.

Use `language:unicorn-x86` with JSON in `source_code`:

```json
{"bits":32,"base":4096,"entry":4096,"stop":4104,"instructions":32}
```

The pinned input slice is mapped at `base`. Optional `registers`, `memory`,
`observe` and `handlers` provide explicit initial state and observation selectors.
Additional regions are page aligned and total mapped memory is at most 2 MiB.
Memory regions may use `input:NAME` to initialize from `/input/files/NAME`, instead
of placing large tables in model-authored JSON. Both x86 addresses and canonical
x64 user-space addresses above 4 GiB are supported.
Execution is limited to 10,000 instructions, the helper wall deadline, a 16 MiB
translation buffer and bounded output. Interrupts, syscalls and port I/O stop as
unmodeled; there is no target OS or host API passthrough. Unmapped memory and
invalid instructions retain native errors. Stop-address completion is not proof
of target acceptance. Unspecified CPU/memory state is an emulation assumption.

Receipts retain register state, memory writes, observed edges and possible
dispatchers. A repeated site with multiple successors is only a candidate, not
proof of a VM. `handlers:[{entry,exit,registers,virtual_state?:{address,size}}]`
records before/after register and virtual-memory snapshots for bounded observed
traversals. It does not infer a universally valid handler semantics. The original
code slice and request hashes remain in the enclosing helper record; guest writes
do not silently replace original evidence or XAIR/Ghidra views.

## Environment and observer comparisons

Experiment cases may select another **already granted** engine and a
`managed_trace` setting. Arguments, stdin, named files, environment, observation
engine, tracing and bounded `timeout_ms` controls are recorded in
`comparison.changed_controls`. Timeouts range from 100 to 10,000 ms per case.
The existing investigation wall/cancellation and uncertain-outcome rules remain.

Paired complete I/O observations compare output and exit codes. Engine-specific
observations remain native and may not be comparable. `observer_changed` records
a changed observation configuration, not causal proof. Host clock virtualization,
kernel environments and unavailable service simulation are not manufactured by
setting an environment variable. Those require the explicit environment profiles
of Tasks 9–10. A missing event is never evidence that behavior did not occur.

## Bounded verification

- `tests/helper_tests.cpp`: scoped files, references, pin tampering, exceptions,
  isolation, quotas, timeout, output overflow, repeatability and cancellation.
- `tests/expansion_live_repair.cjs`: local-model repair using actual harness
  diagnostics and independent original-byte validation.
- `tests/expansion_emulation.cjs`: original x86/x64 fixtures, unsupported calls,
  instruction limits, unmapped memory, code mutation and handler/dispatch records.
- `tests/expansion_observer.cjs`: original CoreCLR fixture without/with EventPipe.
- `tests/experiment_tests.cpp`: explicit environment contrast and grant rejection.
- Existing artifact, managed, controller and workbench regressions.

All fixtures are source-built or inert generated data. No archive challenge is
executed, no answer material is consulted and the frozen benchmark is unchanged.

Recorded gates include 18 helper actions, 11 harness emulation cases, a local Qwen
repair (two attempts, one generation), paired CoreCLR observations, source-backed
LIEF/capa/FLOSS/packet tests, and Windows/Linux controller/workbench regressions.
The Windows standalone emulation worker also passed five bounded fixture cases;
this does not turn Windows-native generated helper execution into a supported
sandbox profile. Logs are under `out/expansion-*.log`.

### Final verification (2026-09-12)

- `out/expansion-handoff-helper-tests.log`: 18 Linux helper actions passed.
- `out/expansion-final-emulation-tests.log`: 11 harness emulation cases passed.
- `out/expansion-final-observer-tests.log`: complete baseline/EventPipe pair passed.
- `out/expansion-handoff-experiment-tests.log`: experiment and control checks passed.
- `out/expansion-handoff-linux-tests.log`: controller/workbench 2/2 passed.
- `out/expansion-handoff-managed-tests.log`: imported dependency and persisted
  cross-assembly relationship checks passed inside the Linux worker profile.
- Windows native rebuild and helper fail-closed/experiment checks passed; the
  rebuilt standalone emulation worker passed 5 cases (`out/emulation-worker-p6oQkj`).
- Live Qwen repair evidence: `out/expansion-live-repair-i9UlCG/summary.json`.
  This used the external-owner harness API, not a Linux-hosted model connection.

These are bounded development checks, not completion of the remaining catalogue
adapters, universal protection recovery, or hostile-target qualification.
