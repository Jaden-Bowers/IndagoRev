# Target-system declarations and static harness binding

`indago system create|show|list|preflight` supplies a native, persisted declaration
of a program or cooperating group. It reuses immutable knowledge revisions,
artifact dependencies and portable bundles. It does not allocate a machine, stage
files, install a service/driver, resolve secrets, connect to endpoints or execute
anything. A declaration is not evidence that an environment exists.

Example `system create --request FILE` input:

```json
{
  "project": "demo",
  "title": "Client/service experiment declaration",
  "manifest": {
    "os": "windows",
    "architecture": "mixed",
    "components": [
      {"name": "server", "target_id": "tgt_IMPORTED_SERVER", "role": "service", "path": "bin/server.exe"},
      {"name": "client", "target_id": "tgt_IMPORTED_CLIENT", "role": "program", "path": "bin/client.exe"}
    ],
    "launches": [
      {"name": "server", "component": "server", "readiness": "service_ready"},
      {"name": "client", "component": "client", "depends_on": ["server"], "argv": ["--offline"]}
    ],
    "environment": {"LAB_TOKEN": {"secret_ref": "operator_supplied_test_token"}},
    "requirements": [{"kind": "runtime", "name": "required-runtime", "version": "operator-selected"}],
    "isolation": "vm",
    "network": "disconnected",
    "reset": "snapshot",
    "limits": {"wall_ms": 60000, "capture_bytes": 16777216, "events": 10000, "memory_bytes": 2147483648}
  }
}
```

The result is a `system_manifest` knowledge record with a deterministic body hash.
Component IDs resolve within the project and pin imported content hashes/sizes.
An optional component `artifact_sha256` must match. Roles are program, service,
library, driver or data. Launch references must exist and must not launch library
or data components. Dependencies are checked for missing names, duplicates and
cycles; the recorded `launch_order` is deterministic. Readiness values are
`process_started`, `service_ready` or `operator_signal`—obligations for a future
executor, not observations. Optional `stdin_component` references an imported
component; arguments remain literal strings, never shell commands.

Guest paths are relative and unique; traversal, absolute paths, device names and
file/directory overlaps are rejected. The Windows v1 path subset is ASCII with
case-insensitive collision checking; full Unicode/guest-filesystem equivalence is
not claimed. Linux paths remain case-sensitive. This path validation does not
stage files or replace future guest-side safe-open checks.

Environment entries contain exactly one `value` or unresolved `secret_ref`.
Windows variable names are checked case-insensitively. Empty literal values are
allowed. Do not put credentials in literal values: manifests and bundles are
portable provenance, not secret stores. Requirement kinds are runtime, service,
device, secret, endpoint and kernel_profile; they may declare name/version but
cannot grant permission to fetch or install them.

Bounds: 64 KiB input manifest, 32 components, 32 launches, 32 arguments per launch,
32 environment entries and 64 requirements. Guest OS is Windows/Linux and declared
architecture x86/x64/mixed. Only VM/snapshot isolation and disconnected/simulated
network policy are admitted. Limits are positive: at most 600,000 ms, 512 MiB
capture, one million events and 8 GiB guest-memory declaration. These are requested
future lab ceilings, not resource allocations or enforcement claims.

## Preflight

```text
indago system preflight --project demo --id kn_MANIFEST
```

Preflight verifies the manifest digest and checks component identity/integrity
under a shared hash-byte budget. A request may set `max_bytes` (default 16 MiB,
maximum 64 MiB). Duplicate content is hashed once; skipped, missing or changed
artifacts remain explicit. Bounded reads guard against file growth during hashing.

The current result always has `ready_for_execution: false`,
`status: capability_blocked` (CLI exit 3), and explicit gaps for lab allocation,
guest/snapshot/reset attestation, externally enforced network isolation and guest
requirements. Verified artifact bytes never substitute for containment. WSL is a
build/test environment, not a hostile-code lab. No malicious sample is executed
by creation or preflight.

## Harness binding

An operator may add `"system_manifest": "kn_MANIFEST"` to `harness create`.
The harness pins its knowledge ID/revision/body hash. Unless explicitly selected,
the primary is the first declared component—not the latest project import.
Manifest component target IDs become the static roots, deduplicating aliases for
the same target. An explicitly supplied scope must cover exactly that declared
target set. A model cannot bind a new manifest through a board update.

`harness read` with `family: investigation, operation: manifest` returns the pin
and a no-execution-authority policy. The normal scoped knowledge reader can retrieve
the declaration; large records retain the existing narrowing/omission policy.
Final reproducibility metadata retains the pin. Derived-artifact admission remains
a separate explicit grant and does not rewrite the bound system declaration.

Next: provider-bound allocation and attestation, immutable environment/snapshot
identities, quarantine on failed reset, and runtime/helper grants that require
those verified states. This implementation is the declaration/identity portion,
not a disposable-lab lifecycle implementation.

## Development checks, 2026-09-07

Windows native process/harness/controller/knowledge checks passed 4/4 in 7.79s;
CLI harness binding and knowledge/preflight passed in 1.76s/3.51s under separate
60-second storage-guarded watchdogs. Linux native checks passed 5/5 and CLI
regression 6/6. Logs: `out/system-binding-windows-checks.log`,
`out/system-binding-linux-checks.log`, `out/system-binding-linux-cli-checks.log`.
Tests cover deterministic ordering, cycles, path/environment collisions, byte
budgets, refusal of host/WSL/external-network grants, bundle preservation and static
harness/report binding. No live inference, hostile execution or live-network capture.
