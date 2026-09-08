# Deterministic knowledge workbench

This is the native CLI/core layer beneath a future harness. It stores and queries
knowledge; it does not call an LLM, execute generated helpers, provision a lab,
or claim autonomous understanding. Existing analysis engines remain separate.

Use `indago workbench capabilities` and `indago schema show --name workbench`.
Each family accepts `--request FILE`. `--project`, `--id`, `--artifact`, `--kind`,
`--search`, `--anchor`, `--address`, `--limit` and `--offset` can also supply common
fields, provided they do not conflict with the request. stdout is JSON; normal
partial/budget/cancellation exit codes remain 3/130. A validator returning a
counterexample is a successfully executed check, not a tool failure.
Rejected workbench actions return exit 2 with `error_code`: `invalid_request`,
`revision_conflict`, `integrity_failure`, `busy_or_ownership_lost`,
`resource_limit`, or `not_found`. Inspect stored batch/job state before resuming
after a lost owner; do not blindly retry a side effect.

Requests are <=1 MiB; responses are bounded to 2 MiB, with smaller graph budgets.
Operation-specific validators reject unknown fields. The embedded schema documents
shared transport types; native validation adds operation requirements and identity
checks. `capabilities.workbench` is available in the main capability response.

## Behavior contracts, hypotheses and products

`knowledge put|show|list|refresh|impact` exposes append-only revisions in SQLite.
`refresh` computes freshness; it does not rewrite assertions. Supported kinds:
`behavior`, `hypothesis`, `question`, `summary`, `assumption`, `product`,
`recognition`, `signature`, plus operation-owned `transformation` and `validation`.

Example `knowledge put` request (substitute real identities):

```json
{
  "project":"demo", "kind":"behavior", "title":"Configuration decoding",
  "state":"inferred", "scope":{"artifact_sha256":"ARTIFACT_SHA256"},
  "body":{
    "inputs":["configuration bytes"], "outputs":["decoded fields"],
    "guards":[], "state_changes":[], "side_effects":[],
    "unknowns":["malformed-input behavior"]
  },
  "assumptions":["selected function is reached"],
  "support":["EVIDENCE_ID"], "counterevidence":[],
  "dependencies":[{"type":"entity","id":"ENTITY_ID"}]
}
```

Hypotheses require `prediction`, `alternatives` and `unknowns` in `body`.
Other bodies are extensible objects: products can describe decoder/parser source
artifacts, interfaces, toolchain identities and validation obligations. Body prose
is a caller assertion, not mechanically checked semantic entailment.

Updates require `id` and the current `expected_revision`; omission means creation
at revision zero. Existing revisions are never overwritten. Records are <=256 KiB.
Caller writes cannot claim `validated` or create operation-owned validation records.
Other state labels retain `assertion_origin: caller_assertion` explicitly.

Core workspace schema 5 prevents older executables from opening these workspaces;
existing targets and evidence migrate without deletion. Runtime schema remains 2.

Dependencies (max 128 combined) name project-owned `record`, `artifact`, `entity`,
`evidence`, `revision`, `observation` or `epoch`. Pins are resolved at publication;
an explicit stale pin is rejected. `support`/`counterevidence` reference evidence
IDs; runtime observations can be explicit dependencies or `scope.observation_id`.
`scope.epoch_id` and `scope.artifact_sha256` also become checked dependencies.

Freshness follows pinned record revisions and current static analysis heads.
Ghidra Program revision advancement within one backend session identity invalidates
older dependent views conservatively. Runtime observations remain time-scoped:
a later code epoch does not retroactively disprove an earlier observation.
Traversal is bounded (32 levels/4096 visits); exhausted traversal reports unknown,
not current. Artifact existence is checked during retrieval; full byte integrity
is checked when consumed/exported. `knowledge impact` accepts `type` and `id` and
returns current records that transitively depend on that identity.

## Graphs and evidence packets

- `graph search`: bounded name/string/constant lookup in existing normalized indexes.
- `graph neighborhood`: BFS over explicit normalized relationships and location anchors.
- `graph packet`: the neighborhood, backend claims, disagreements and raw-evidence links.
- `graph event`: a checked runtime observation plus its anchored static packet, when mapped.

Neighborhood/packet seeds: `id`, `anchor`, `address` (prefer also `artifact`), or
`search`. Options: `direction: in|out|both`, `depth: 0..8`, `limit: 1..1000`,
`kinds` (relationship-kind filter), `output_bytes: 4096..2097152`.
An event request uses `observation` instead of a static seed.

Addresses shared by different backend discoveries provide navigation, not IR
equivalence. Native Ghidra function-body ranges add evidence-backed membership
links for address-selected results. Traversal does not prove path feasibility,
cross-process causation or that an unresolved endpoint does not exist. Native
payloads are omitted from packets; retrieve their evidence IDs/JSON pointers.
Frontier/byte limits set `partial`. Narrow the seed/filter to explore omitted paths.

## Coverage gaps

`coverage report` accepts `project`, optional `artifact`, `limit` and `scan_limit`.
It reports per-backend discovery counts, explicit native semantic gaps, unresolved
relationship endpoints, incomplete jobs, functions without an indexed address-
selected analysis, and runtime observer-scope reminders.

Gap enumeration is a lower bound. Counts are discoveries, not unique functions or
a completeness percentage. A whole-image analysis may contain function details
even without an address-selected query. Runtime event loss and unsupported states
remain in their native observations; the report does not certify their absence.
`negative_inference_allowed` is always false.

## Recognition and derived artifacts

`recognize scan` requires an artifact; optional `publish` stores its findings.
Built-in markers identify candidate Go/Rust/CLR/MSVC/GCC runtime text, and symbol
prefixes identify support-code candidates. Markers can be decoys or embedded
content; they do not establish a language or application behavior.

Create a `signature` knowledge record with body `sha256`, optional file `offset`
and `size`, and reference provenance. Recognition matches exact bytes against
that signature and records its revision/freshness. The label remains caller-owned.
No library code is hidden and no universal library fingerprint database is shipped.

`transform run` requires `artifact` and `spec`, with optional byte `offset`/`size`:

```json
{"project":"demo","artifact":"ARTIFACT_SHA256","offset":0,"size":16,
 "spec":{"method":"xor","key_hex":"01ff"},
 "assumptions":["key alignment begins at this selected range"]}
```

Methods: `slice`, repeating-key `xor`, strict `hex_decode`, canonical padded
`base64_decode`. No shell or arbitrary target code executes. Input artifacts are
bounded to 16 MiB, selected regions to 4 MiB. Exact original/derived hashes,
engine/spec identity, file-range mappings and assumptions are persisted.
Decoded groups do not acquire invented instruction addresses. Empty output is
allowed. Derived artifacts become project targets: select the original target
explicitly when necessary. Unknown/new transformations can be described as
caller-authored products, but are not silently executed or labeled validated.

## Finite behavioral checks

`validate compare` checks exact byte equality. `validate transform` applies one
built-in transformation to each input and compares its output to supplied expected
bytes. Requests require `scope`, `cases` (1..64), optional subject record/title:

```json
{"project":"demo","scope":{"inputs":"three supplied reference cases"},
 "subject":"PRODUCT_RECORD_ID",
 "cases":[{"actual_artifact":"ACTUAL_SHA256","expected_hex":"414243"}]}
```

For transformation checks, use `input_artifact` and top-level `spec`. Expected
data is exactly one of `expected_artifact` or `expected_hex`. Aggregate comparison
data is <=16 MiB. Results preserve actual/expected hashes and sizes, first mismatch
and short byte excerpts, even on failure. Validation is a separate record; it
does not promote the subject automatically. Passing cases validate finite byte
comparisons only: expected outputs are caller-supplied and not automatically an
independent oracle. Program execution, protocol drivers and semantic equivalence
remain outside these validators and can later use the same product/dependency model.

## Resumable bounded batches

`batch create|show|run|cancel|events` uses durable IDs and exclusive renewable
leases. A create request has `project`, aggregate `budget`, and 1..64 ordered
steps. Each step has `name`, an ordinary static action `request`, optional
`depends_on` naming preceding steps, and `allow_partial_dependencies` (false
by default). Target IDs and hashes are frozen when the batch is created.

Budgets: `wall_ms`, `output_bytes`, `memory_bytes`, `max_jobs`. Execution is
sequential. Per-attempt wall/output ceilings are reserved conservatively before
submission, including failed/interrupted attempts. Startup overhead outside native
worker budgets is not a hard end-to-end deadline. Memory is a per-active-job
ceiling, not cumulative allocation across time. Artifacts/results stay in the
existing evidence store; batch results contain references, not duplicate raw data.

`batch run` accepts `{project,id}`. Completed/partial steps are not repeated;
dependent steps decide explicitly whether partial evidence is acceptable. A lost
owner can be resumed after its 30-second lease expires. Expired static job leases
use existing fenced recovery. Reservation/idempotency keys survive interruption.
An active job is not stolen just because its batch owner disappeared.

Failed/interrupted read analyses require `retry_failed:true`, with at most two
attempts per step and remaining aggregate budget. `reset_cancel:true` explicitly
resets a requested cancellation. Cancellation propagates to the currently running
static job. No runtime experiments, Ghidra annotations or session-control edits
are retried through this batch interface. This is not a distributed scheduler.

## Portable bundles and retention

`bundle export` takes `project`, a nonexistent `destination`, optional `max_bytes`
(default 1 GiB). Settle queued/running jobs and runtime sessions first. A bundle
contains project-scoped SQL records, immutable targets/evidence, knowledge history,
runtime observations, and referenced raw telemetry files located inside the
workspace. Hash manifests bound and verify every copied object. External paths
are not followed; unavailable raw telemetry is listed in the manifest. Original
recorded paths remain provenance; portable bytes are addressed by their hashes.

`bundle import` takes `source` and a nonexistent workspace `destination`. Import
uses staging, checks hashes/table/column identities and foreign keys, and finalizes
only after database handles close. It never merges into an existing workspace.
Interrupted staging directories are retained for diagnosis. Checksums provide
integrity, not authenticity or proof that target-produced observations are true.
Saved Ghidra Programs, engine caches, live processes, and VM images are not included;
reanalyze original artifacts to reopen backend sessions.

`retention plan` scans all project/history references conservatively. Only
unreferenced content objects older than 24 hours are candidates. `retention
quarantine` requires the exact `plan_digest`; it moves candidates into a recoverable
workspace quarantine with a manifest. It never permanently deletes files. Active
jobs/runtime sessions and publication leases block maintenance. All current core,
runtime and workbench publishers participate. Older executables reject schema 5;
do not manually downgrade the schema to run them against this workspace.

The build's `INDAGO_BUNDLE_PROFILE=runtime` omits foreign-platform Ghidra native
helpers and Java runtime-construction `jmods` when present. Runtime modules, the
compiler, source archives and notices remain. `full` preserves the earlier payload.
`generated/bundle-profile.json` reports exact savings; this is not a Java-free or
multi-process-free binary. Private engine extraction remains necessary.

## Focused checks

- `indago_knowledge_tests`: records, conflicts, dependency freshness, graph bounds,
  gap reporting, transformations, finite validators, recognition, portable bundles,
  retention and publication locking.
- `tests/knowledge_cli_smoke.ps1`: the user's documented IR synthetic PE64 corpus,
  native inventory/CFG, dependencies, resume, aggregate budgets and cancellation.
- `tests/knowledge_runtime_smoke.ps1`: runtime dependency and event packets plus
  portable runtime evidence/raw telemetry round-trip.
- Existing Ghidra and generated-code checks verify the reduced runtime payload
  and storage changes against benign fixtures.

These are focused development checks, not production qualification. No unidentified
IR samples or malware are executed on the host.
