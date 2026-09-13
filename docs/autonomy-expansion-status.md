# Autonomy expansion: implementation status

The pre-Task 8 and during-Task 8 interfaces now have a bounded Linux implementation.
See [the current contract](pre-task8-and-protection.md) for supported profiles,
limits and explicit exclusions. This does not change the frozen benchmark or
claim full protection recovery, hostile-target qualification or universal coverage.

The subsequent algorithm-reconstruction loop, service-behavior contracts,
failure-driven evaluation and bounded QEMU guest lifecycle are now implemented.
See [reconstruction/services/evaluation](reconstruction-services-evaluation.md)
and [guest profiles](qemu-guests.md) for exact boundaries and measured failures.
These do not close the catalogue adapter backlog or prove all-challenge autonomy.

## Contained helpers

Implemented Linux `python3` through the existing helper namespace and seccomp
boundary, with isolated interpreter flags, proposal-bound executable hash,
version receipts, original-byte validation and bounded exception diagnostics.
Source revisions use the existing action history. Windows remains fail-closed.
The interpreter and standard-library contents are pinned at proposal and checked
in each execution. Multiple scoped inputs, 256 KiB slices, 1 MiB aggregate input,
bounded regular-file output and output-file reference validation are implemented.
A local Qwen repair test passed after one model generation and two native attempts.
The runtime is operator-managed rather than a separately bundled/attested OS image.

## Shared worker isolation

The process launcher accepts an optional `process_memory_bytes` limit. Windows
uses per-process committed-memory job limits; POSIX uses `RLIMIT_AS`. Linux helper
and parser profiles additionally use delegated cgroup aggregate quotas, scoped
read-only mounts, isolated networking, replaced environment, private tmpfs and
control-group termination. Managed extraction returns bounded receipt bytes without
a writable host mount. This is not a blanket sandbox claim for Windows, persistent
Ghidra sessions, original-target debugger execution, or kernel vulnerabilities.

## Catalogue adapters

See `catalogue-runtime-coverage.md`. Remaining adapters are unchanged by this
increment: Android resources, VBA/XLM semantics, XNB, HDL and selected legacy/disk
formats. Existing routes do not constitute implemented semantics.

## Protection recovery

The separate pinned Unicorn worker exposes bounded x86/x64 execution, guest state,
memory observations/writes, edges, dispatcher candidates and selected handler
before/after snapshots. Unsupported OS calls stop explicitly. Guest addresses are
not silently certified as original program addresses. Paired experiments record
environment/observer controls and compare complete observations without claiming
causation. A CoreCLR baseline/tracing pair passed with unchanged output and exit.
General devirtualization, native/emulated equivalence across arbitrary APIs and
host-clock virtualization remain research/environment work, not achieved claims.

## Increment verification

Linux helper checks passed with 18 actions, including Python copy/reference
validation, exceptions, isolation, timeout, output overflow and memory exhaustion.
Shared process-launcher checks passed on Linux and Windows. Windows helper checks
confirmed fail-closed behavior. Logs include `out/expansion-final-helper-tests.log`,
`out/expansion-observer-tests.log` and `out/expansion-live-tests.log`.
Linux tests used 90-second command deadlines;
no challenge was executed. These checks do not qualify a hostile-target sandbox.
