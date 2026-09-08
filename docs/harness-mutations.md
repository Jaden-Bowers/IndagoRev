# Harness knowledge and finite-validation actions

This increment reuses the native knowledge workbench through the existing harness
proposal/run mechanism. It adds no interpreter, target execution, remote service,
new semantic engine. A separate [derived-artifact grant](harness-derived.md) now
permits bounded transform publication and scoped admission.

## Grant and request contract

An operator must include `"workbench_mutations": true` in `harness create`.
Omission, including on older saved investigations, leaves mutations disabled.
The immutable component scope and shared action/output/wall reservations still
apply. Neither the model nor a board update can grant this permission. Imported
bundles retain history but disable this permission; create an explicitly granted
investigation to do new mutation work after import.

Both external and built-in owners use an ordinary proposal containing:

```json
{
  "backend": "workbench",
  "operation": "knowledge.put",
  "arguments": {
    "kind": "summary",
    "title": "Input-decoding hypothesis",
    "body": {"text": "Candidate decoder; behavior not independently verified"},
    "support": ["ev_EXISTING_SCOPED_EVIDENCE"]
  }
}
```

This is the nested `request`, not a complete proposal. Include the usual
gap/prediction/expected-evidence/fallback and owner/revision/key fields. The
built-in controller uses the same request through its `analyze` decision.

Select another scoped component using `target_id` or `artifact_sha256` on the
request. `arguments.project` and `arguments.scope`, when provided, must match the
selected component. They are filled automatically when omitted.

Supported operations:

- `knowledge.put`: **new** summary, hypothesis, behavior, question, assumption or
  product assertions. State is `inferred` (default), `unknown` or `contradicted`.
  No caller-supplied record ID/update revision; no model-authored `validated`,
  `derived` or `observed` assertion through this capsule. Structured dependency
  kinds are artifact, record and evidence. Author is tied to the investigation.
- `knowledge.revise`: replace the body of this investigation's own untouched
  assertion, supplying `id`, `expected_revision` and `body`. The kind and component
  cannot change. Omitted title/state/assumptions/dependencies/support/counterevidence
  retain the prior bounded request values; explicit replacements (including empty
  arrays) are honored. Operator revisions remove the internal ownership marker,
  so matching a revision number alone does not permit overwriting operator work.
  Computed records and other investigations' assertions are not revisable here.
- `validate.compare`: existing finite exact-byte comparison. Each case supplies
  `actual_artifact` and exactly one of `expected_artifact`/`expected_hex`.
- `validate.transform`: applies the existing bounded slice/XOR/hex/base64 operation
  **in memory for comparison**, not publication of a new target. Each case supplies
  `input_artifact` and an expected representation; the request also supplies `spec`.
- `transform.run`: publishes derived bytes only with the additional explicit
  `derived_artifacts` grant. See [admission, storage and recovery](harness-derived.md).

Validators accept a `subject` knowledge ID to retain the tested hypothesis as a
dependency. For example, nested arguments for an intentional counterexample:

```json
{
  "subject": "kn_EXISTING_SCOPED_HYPOTHESIS",
  "cases": [{
    "actual_artifact": "EXACT_SCOPED_ARTIFACT_SHA256",
    "expected_hex": "00",
    "label": "candidate output"
  }]
}
```

The selected component, every input/expected artifact and all structured
dependencies must remain in investigation scope. Dependencies are checked
transitively. Current dependency revisions are pinned during proposal and
rechecked before dispatch; revisions changing in between cause failure before
the mutation. Direct knowledge dependency pins are also passed to the existing
workbench, which performs its own publication-time validation. Validators carry
their subject as a pinned record in `arguments.dependencies`; that pin is checked
inside the knowledge publication transaction, closing the subject-revision race
between harness preflight and publication. This is local
concurrency control, not an authentication boundary against an operator editing
the SQLite store.

Every harness mutation also rechecks the complete action dependency-pin set under
the publisher's write transaction. This includes support/counterevidence and the
predecessor head of `knowledge.revise`, without creating a self-dependency in the
knowledge graph. A retained evidence reference with a changed revision fails
closed instead of silently refreshing; remove or replace it explicitly as part of
a new assertion revision. Revision history and old validator outcomes remain
available. A validator for revision 1 does not establish revision 2's correctness.

## Bounds, cancellation and recovery

The capsule uses a fixed reservation of 10,000 ms, 65,536 output bytes, 64 MiB
declared memory and 16 items. Omit `budget` or supply that exact reservation.
Knowledge/validator arguments are at most 32 KiB. At most 32 explicit dependencies
and 16 entries per support/counterevidence list are admitted. Validation accepts
1–16 cases, at most 256 KiB per referenced case artifact and 1 MiB aggregate
case bytes. Existing workbench integrity/freshness checks still apply.

These are conservative accounting/data bounds, **not an OS-enforced memory limit**.
The mutation now runs in a killable native child with a ten-second parent-enforced
wall ceiling. Cancellation can terminate it; a previously committed publication
is retained. This is process control, not a hostile-code security sandbox.
Parent-side receipt/freshness checks remain in-process. See [worker and recovery contract](harness-workers.md).

The action's dispatch marker is committed before calling the workbench. Its receipt
is then saved in the durable action, including knowledge IDs/revisions, scientific
state and freshness. Validator receipts include pass/fail and at most four bounded
counterexamples. Full records and test specifications remain in the knowledge store
and are accessible with scoped `harness read` or the operator's normal knowledge CLI.

Repeating a completed action returns the same receipt without a second publication.
Knowledge publication now commits an exact action-linked pointer in its own
transaction. If the final receipt is lost, that exact revision can be recovered
without replay. Without this pointer, resumption reports `interrupted` with
`outcome_unknown: true` and does **not** dispatch again. An identical normalized mutation cannot bypass that
guard merely by using a new proposal key. Inspect history before deciding on a
different action. An exception after dispatch is conservatively treated the same
way unless its exact committed pointer is recovered. Knowledge revision and
publication pointer are atomic; filesystem staging/import and final admission are
separate transactions, so this is not exactly-once publication of every side effect.

## Scientific and implementation limits

Passing a comparison establishes equality only for the finite supplied cases.
Expected outputs are caller/model supplied, not an independent behavioral oracle.
Contradicted validation is a successfully completed computation with a negative
result, not an engine failure. Knowledge assertions are retained as assertions;
the harness cannot label its own note a verified observation.

Final report claims still use native `evidence_ids`; knowledge receipts are not
automatically promoted into semantic citations or independent solve certificates.
`verified_solve` remains false. Bounded derived-artifact admission and transform
publication and guarded assertion revision are now available; remaining work includes product workflows,
independent behavioral validators and isolated runtime/helper workers.

## Bounded development verification, 2026-09-07

Guarded revisions and publication-time action pins: Windows native 4/4 passed
in 6.26 seconds (`out/harness-revisions-windows-checks.log`); Linux native 5/5
passed (`out/harness-revisions-linux-checks.log`, each test deadline 60 seconds,
outer watchdog 240 seconds). Linux CLI knowledge/PE/ELF32/ELF64 harness and benign
runtime suites passed 6/6 (`out/harness-revisions-linux-cli-checks.log`). Tests
cover competing revisions, operator overrides, computed-record refusal, exact
revision receipt recovery, publication-time stale pins and a scripted five-step
note → negative comparison → revision → positive comparison → partial report.
The test's expected bytes are supplied by the fixture, not an independent solve oracle.

Earlier mutation-only baseline:

- Windows native harness/model/knowledge: 3/3 passed in 3.32 seconds, each with a
  60-second test deadline (`out/harness-mutations-windows-checks.log`).
- Windows CLI harness: passed in 1.06 seconds under the free-space/scratch guard
  (`out/qualification-harness-61b510f52bc947efa75c8b11a9c0fc93/`).
- Linux native HTTP/model/harness/knowledge: 4/4 passed, each with a 60-second
  deadline (`out/harness-mutations-linux-checks.log`).
- Linux CLI knowledge, PE/ELF32/ELF64 harness and source-backed runtime suites:
  6/6 passed (`out/harness-mutations-linux-cli-checks.log`, outer watchdog 120 seconds).

Tests cover explicit grants, ordinary note state, negative/positive finite byte
results, counterexamples reaching the scripted controller, transitive scope,
stale pins before dispatch and at publication, receipt reuse, unknown-outcome
non-replay and imported-grant stripping. No live model inference or unknown target
execution was performed. C: still had approximately 45.3 GiB free afterward.
