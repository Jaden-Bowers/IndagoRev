# Static contracts, identity and indexes

For the later behavior/hypothesis layer, transitive dependencies, evidence packets,
batch execution and portable bundles, see [knowledge workbench](knowledge-workbench.md).
The static index below remains the backend-discovery foundation for that layer.

This implementation is C++20 with embedded SQLite. No runtime target execution,
debugger, trace capture, GUI, or model harness is introduced here.

## Contracts and jobs

`contracts/json/indago.{action,result,evidence}.v1.schema.json` describe the
actual service boundary. They are embedded at build time; `schema show --name
action` returns the same contract used by native validation. Unknown action
fields, invalid bounds, unknown backend operations and invalid addresses are
rejected before a job is created. Requests are limited to 1 MiB.

Optional `idempotency_key` is scoped to a project. Repeating a normalized request
returns the same job/result; reusing its key for different input is rejected.
Job states progress from queued to running to a terminal state. An exclusive
lease prevents duplicate execution/publication. Heartbeats renew a 30-second
lease; `job recover --project NAME` fences expired running jobs as interrupted.
Recovery does not replay analysis. Submit a new request/key to retry. Queued
jobs can be run again through the same action request. `job events --project
NAME --id job_ID` exposes append-only state events.

SQLite commits raw evidence references, derived indexes and the completed job
together. Content hashes are verified. Analysis JSON files are convenience
mirrors; SQLite and the immutable raw object are authoritative. Raw objects
left before an interrupted transaction are unpublished, not evidence.

## Static identities

- Artifact: SHA-256 of original bytes.
- Location anchor: artifact + address space + exact 64-bit virtual address.
- Discovery (`ent_`): revision + producer + native JSON pointer.
- Native IDs: scoped to their containing backend document, never global SSA IDs.

Program/ram/virtual memory locations map to the shared program space; external,
register and other backend spaces stay separate. Original space labels remain.
Image-relative and file offsets are added only with available mappings and
checked arithmetic. Overlapping file mappings remain explicit candidates.
XAIR inventory mappings can support later views of the same artifact; mapping
evidence is identified. Native exports are never rewritten into a shared IR.

Names and function boundaries are backend claims, not identity. New discoveries
at the same anchor get new entity IDs. Previous discoveries remain available.
This supports changed boundaries without claiming two recoveries are equivalent.

## Index queries

```powershell
indago index entities --project demo --kind function
indago index entities --project demo --kind string --search configuration
indago index entities --project demo --kind constant
indago index entities --project demo --address 0x140001000
indago index relations --project demo --kind call
indago index relations --project demo --source ent_ID
indago index claims --project demo --subject ent_ID
indago index compare --project demo --anchor loc_ID
indago index revisions --project demo --history true
```

Kinds include functions, blocks, instructions, operations, SSA values, constants,
strings, symbols/imports/exports, types, variables, tokens and native evidence.
Relations include CFG edges, calls, xrefs, function/block membership, SSA
definitions/uses and memory effects. Unresolved endpoints stay null with native
records and any known locations retained. A call target of zero is not invented
as a resolved function. Source mappings and raw JSON pointers support drill-down.

Claims retain subject, predicate, native value, producer, revision, source pointer,
scope, evidence dependencies and an unvalidated state. `compare` shows differing
claims at an anchor without deciding which backend is correct. Native related
pipelines are not treated as independent experimental validation.

The latest successful/partial result per artifact/backend/operation/address/view/
argument scope is current; previous claims inherit superseded freshness. Failed
retries do not hide usable earlier knowledge. Use `--history true` or an explicit
`--revision` to retrieve prior views. This is static evidence freshness, not a
general-purpose inference engine for arbitrary user-authored hypotheses.

Queries support `--artifact`, `--backend`, `--revision`, `--limit`, `--offset` and
kind-specific filters. `next_offset` signals another page. Raw textual views
remain evidence; the index extracts structured backend records, not guesses
from pseudocode prose. Backend semantic completeness remains distinct from index
coverage. Index extraction is capped at 100,000 entities per result.

## Migration and verification

The original index migration introduced schema 3; the current core opens schema 5
for knowledge records and storage-publication safeguards without
deleting existing artifacts/evidence. Run `index rebuild --project NAME` to
backfill old records; this rebuild verifies raw hashes and atomically replaces
only derived indexes. Newer unsupported database versions are rejected.

Tests cover schema validation, high-bit addresses, file mapping, namespace-scoped
SSA links, backend disagreements, idempotency, lease recovery, publication fencing,
superseded evidence, deterministic reindexing, legacy migration and source pointers.
The PE/ELF gate additionally exercises real Ghidra and integrated XAIR endpoints.
Windows is tested; Linux qualification and broader semantic coverage remain
separate work. No security sandbox or universal instruction coverage is claimed.
