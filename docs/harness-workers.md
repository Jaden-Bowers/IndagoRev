# Native workbench workers and publication recovery

Harness knowledge, validator and transform actions now run through an internal
`__workbench` entry point of the same native executable. No interpreter, additional
analysis engine, model, shell or target execution is introduced.

## Process control

The parent starts one child using literal arguments containing the workspace and
existing action/runner identities. The child reads the persisted request, checks
the active runner lease and dispatch marker, and revalidates scope, grants and
dependency pins. An absent runner, repeated publication or changed request is
rejected. These internal arguments are not a public mutation authorization API.

The existing native process supervisor enforces the 10-second wall ceiling and
bounded stdout/stderr. Investigation cancellation reaches it through an atomic
callback; Windows Job Objects or Linux process groups terminate the child tree.
On Linux the direct worker also receives a parent-death kill signal, with a
parent-identity race check before execution. A publication committed before
termination remains recoverable; cancellation prevents derived admission if it
wins before settlement.

This is process fault/lifetime separation, **not a security sandbox**. The child
runs as the same user and can access the workspace. It must not execute unknown
targets or generated helpers. Memory remains input/operation bounds and declared
accounting, not an OS-enforced quota; the executable's bundled payload mappings
are not a 64 MiB process. Read-side integrity/freshness checks and receipt settlement
still execute in the parent. These limits remain distinct from disposable VM labs.

## Exact publication pointers

An internal thread-local dispatch context supplies the project, investigation,
action, runner and normalized request hash to knowledge publication. Callers cannot
inject this context through workbench JSON. Each immutable knowledge revision
records `harness_origin`; its action's `publication` records the exact knowledge
ID, revision, content hash and matching origin.

The knowledge revision and publication pointer commit in **the same SQLite
transaction**. A missing/expired/wrong runner, request mismatch or second
publication causes rollback, not an unlinked knowledge revision. This reuses the
existing action/record tables and portable bundle machinery; no schema version or
new sidecar receipt store is needed.

The parent reconstructs the bounded result from that committed revision, never
from a fuzzy search for similar notes. Recovery verifies its hash and origin,
operation kind and, for transforms, parent/spec/range and output target identity.
Derived admission still applies the existing size/scope/cancellation checks.
`publication_recovered` distinguishes an abnormal/missing child completion from
the normal receipt path. Recovery does not execute the operation again. Current
freshness is recomputed; the original knowledge revision remains immutable.

If no exact publication exists, an interrupted action remains
`outcome_unknown: true` and is not replayed automatically. Transform staging,
content import and derivation metadata precede the final knowledge transaction;
termination there can still leave an unadmitted artifact. Legacy unlinked outcomes
cannot safely be reconstructed by guessing. Atomic publication of every filesystem
effect, orphan reconciliation and independent behavioral proof remain separate
work. Recovery's `target_selection_changed` is null when the historical selection
transition cannot be established; the investigation primary remains pinned.

Portable imports retain publication provenance but strip active runner leases and
new mutation/derivation grants. Local database editing is not an adversarial
authentication boundary.

Windows bounded development verification: worker-process, harness, controller and
knowledge suites passed 4/4 in 7.79 seconds (`out/system-binding-windows-checks.log`).
Tests include timeout/callback cancellation, missing runner refusal, publication
rollback, lost-receipt recovery, corrupted-pointer refusal and derived recovery
without repeat publication. CLI harness binding passed under a 60-second storage-
guarded watchdog. Linux native HTTP/model/harness/knowledge/process checks passed
5/5 with individual 60-second deadlines (`out/system-binding-linux-checks.log`),
and bounded CLI regression passed 6/6 (`out/system-binding-linux-cli-checks.log`).
