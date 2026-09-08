# Native investigation harness: external-owner stage

The harness is implemented in C++ and available through `indago harness`.
This page describes the external-owner workflow, which never invokes another LLM.
The [built-in provider loop](builtin-harness.md) now supports one pinned local or
OpenRouter model behind the same bounded static-action controller. The operator
authorized local LM Studio inference on 2026-09-07; see the built-in harness page
for its pinned endpoint/model. Cloud inference remains unconfigured. Live model
analysis quality is not qualified merely by a successful tool-call transport.

## Implemented

- Explicitly component-pinned investigations, required facts, stop-condition notes, a revisioned
  board, action history and explicit terminal reports in the existing SQLite store.
- A single 60-second owner lease. Tokens are returned only when creating/claiming;
  only their hashes are stored. Renew before expiry. Mutation requires a live token
  and usually `expected_revision`. This is local concurrency control, not a remote
  authentication boundary. An operator with filesystem access can edit the database.
- Explicit owner release/transfer after settling or cancelling actions. Claiming an
  expired/released lease preserves the declared owner; changing it requires transfer.
- Bounded static AIRECE/XAIR/XAIR_SYM/Ghidra/ILSpy actions through the existing service,
  retaining native results in normal evidence records. Ghidra annotations, session
  controls, runtime launch, shell, generated scripts, networking and internal
  inference are outside this first envelope.
- Opt-in [knowledge and finite-validation mutations](harness-mutations.md) through
  the same proposal/run controls, with pinned dependencies and conservative
  interrupted-write handling. This is not a target-execution grant.
- Persistent action proposals with gap, expected evidence, prediction and fallback.
  The normalized request fixes backend, target, arguments and resource limits.
- Idempotent proposal keys and stable backend job keys. Completed results are reused
  after a controller restart; active backend jobs are not stolen or repeated.
  A runner heartbeat keeps its owner alive. Cancellation reaches the active job.
- Conservative aggregate reservations, a maximum of three identical normalized
  action requests, context byte limits, paginated actions/events, and reports that
  distinguish citation validation from scientific proof.
- Portable evidence bundles include investigations/actions but never restore live
  ownership/runner leases. Release the owner before exporting.
- Read-only [saved-report audits](report-audit.md) detect stale/incomplete citations
  and Ghidra Program changes without rewriting historical answers.

The standalone runtime CLI remains available to an explicitly authorized operator.
The harness's restricted action dispatcher does not restrict direct CLI access or
provide OS containment for hostile binary parsers. Do not confuse an action allowlist
with a malware sandbox.

## Start an investigation

First create a project and import a target with the existing CLI. Save this request:

```json
{
  "project": "demo",
  "objective": "Explain how the input is validated",
  "required_facts": ["input source", "acceptance condition", "observable result"],
  "stop_conditions": ["Report a gap when the required environment is unavailable"],
  "owner": {
    "mode": "external",
    "name": "analysis-client",
    "model_declaration": "one selected external model; supplied by caller"
  },
  "budget": {"max_actions": 16, "wall_ms": 120000, "output_bytes": 1048576}
}
```

Run `indago --workspace WORKSPACE harness create --request create.json`.
Keep the returned `id`, `owner_token` and `revision`. Do not include the token in
model context or target/helper environments. `harness show --project demo --id ID`
returns state without the token. `harness capabilities` advertises the actual stage.

For every mutation, use the latest revision returned by `show`. Example proposal:

```json
{
  "project": "demo", "id": "inv_ID", "owner_token": "lease_TOKEN",
  "expected_revision": 1, "key": "initial_inventory",
  "proposal": {
    "gap": "input source",
    "expected_evidence": "Imports, entry point and format metadata",
    "prediction": "The inventory exposes candidate input APIs",
    "fallback": "Inspect available functions or report missing metadata"
  },
  "request": {
    "backend": "xair", "operation": "inventory",
    "budget": {
      "wall_ms": 10000, "output_bytes": 65536,
      "memory_bytes": 2147483648, "max_items": 128
    }
  }
}
```

Submit with `harness propose --request proposal.json`. It returns an action `id`
and the new `investigation_revision`, but does not run the backend. Then invoke
`harness run` with `project`, investigation `id`, `owner_token`, current
`expected_revision` and `action_id`. This synchronous execution is bounded by the
reserved worker budget; the already-durable action ID enables recovery if the
caller loses its connection. A repeated completed run returns the same job/result.

`harness renew` and `cancel` need `project`, `id`, `owner_token`, but no revision.
`claim` needs `project`, `id`, `expected_revision` and succeeds only once the lease
expires or is released. It returns a new token. If a backend worker was lost, inspect
the job and use the existing `job recover` command to mark expired worker leases as
`interrupted`; that is not target completion. A genuinely new attempt requires a new
proposal key and consumes another reservation. No dynamic side effect is replayed.

## Board, context and reports

`checkpoint` replaces `board`, whose fields are string arrays `hypotheses`,
`failed_approaches`, `next_actions`, and a string `notes`. Policy, ownership and
budgets cannot be changed through the board. Stop-condition text is reasoning
guidance for the external owner, not arbitrary executable predicates.

`context` takes `project`, `id`, optional `output_bytes` (4–128 KiB, default 32 KiB)
and optional `address`. It reconstructs current state and recent actions, optionally
including a small graph packet. Native payloads are retrieved separately by exact
evidence ID. Omissions are explicit. Byte accounting is not tokenizer-specific
16K/32K context qualification. Target text is labeled as untrusted data.

`actions` and `events` take `offset`/`limit` (maximum 128) and return `next_offset`.
`finish` takes the ordinary ownership/revision fields plus:

```json
{
  "status": "partial",
  "answer": "An input API was identified; the acceptance condition remains unknown.",
  "claims": [{
    "fact": "input source", "text": "The inventory identifies the candidate input API.",
    "evidence_ids": ["ev_ID"], "limitations": ["Import presence is not observed execution"]
  }],
  "gaps": ["acceptance condition", "observable result"]
}
```

Claims must reference a declared required fact and existing evidence from the pinned
component set/project. `answered` additionally requires every fact covered, no gaps and
current, completed evidence. This checks references/scope/status, **not entailment**;
reports always set `verified_solve: false`. Native backend uncertainty is not erased.
The report is a snapshot and does not automatically become a fresh proven claim when
later analysis changes. Recheck cited revisions before reusing an old conclusion.

Other terminal states: `budget_exhausted`, `unsupported`, `environment_unavailable`,
`contradictory`, `capability_blocked`, `failed`, `cancelled`. Final reports retain
claims, gaps and reproducibility metadata; board/action history retains failed
approaches and per-action elapsed time. Reserved wall/output budgets are conservative,
not measurements of peak RAM/VRAM, model cost or total controller startup overhead.

## Limits and next stages

Maximum 128 proposals, 600,000 ms aggregate worker-wall reservations, 16 MiB reserved
backend output; each worker is limited to 120,000 ms and 2 GiB declared memory budget.
Underlying backend budget enforcement/overhead remains as documented by that backend.
Requests are at most 256 KiB; boards 32 KiB; final records 128 KiB. Reservations are
not refunded. Identity scope is **at most 32 root/admitted components per investigation**;
the budget is shared, not multiplied by component count. Runtime system manifests
and execution grants are separate work.

## Component scope and read packets

Creation optionally accepts `target_id` for the primary component and
`scope: {"target_ids": ["tgt_PRIMARY", "tgt_COMPONENT"]}`. The primary must be in
the set. IDs are resolved inside the project and pinned to content hashes. The
root set is immutable; newly imported/discovered artifacts do not silently become
authorized. Omission retains the original single-primary behavior, including for
saved investigations predating this field.

An explicit `derived_artifacts` creation grant additionally permits a separate
ledger of verified scoped-transform outputs, never arbitrary discovered imports.
The root fingerprint and primary remain unchanged. See [derived-artifact contract](harness-derived.md).

`harness scope --project demo --id inv_ID` inspects the set. Proposals select a
component using `request.target_id` and/or `request.artifact_sha256`; inconsistent
pairs or unlisted components are rejected. Omitting both selects the pinned primary,
never the project's most recently imported target. Reports retain per-citation
artifact identity and the full reproducibility component set.

`harness read --request FILE` accepts investigation `project`/`id` plus
`family`, `operation` and nested `request`. It uses the same 4 KiB packet policy
as built-in model retrieval. Supported reads: graph search/packet/neighborhood,
coverage report, evidence show, knowledge show/list and investigation scope.
Graph/coverage/knowledge-list reads optionally select a scoped `artifact`;
evidence/knowledge-show checks the exact record and its scope. Knowledge's
structured dependencies are checked transitively, including pinned revisions;
runtime dependencies require future runtime grants. Lists explicitly mark scope
omissions and retain their scan cursor. Large packets return a narrowing diagnostic
and hashes, not deceptively truncated native JSON.

For component paging use `family: "investigation", operation: "scope"` and
`request: {"offset": 0, "limit": 8}`. Large context packets omit the full component
list with a retrieval hint before dropping the objective. `context` optionally
selects `target_id`/`artifact` for its graph address.

Still needed for the full planned harness:

- Live provider capability probes/qualification and tokenizer-specific context accounting.
- Richer knowledge revision, unlinked filesystem-effect reconciliation, security
  isolation and independently graded behavioral validators. New assertions,
  finite byte validators and bounded derived publication/admission are available
  behind explicit grants.
- Provider-attested runtime/helper grants tied to disposable labs. System
  declarations can now [bind static roots and report provenance](system-manifest.md).
- Task-specific behavioral validation and independently measured solve criteria.

No model endpoint, API key, paid inference, or unidentified executable was used to
verify this stage. See `tests/harness_tests.cpp`, `tests/harness_cli_smoke.ps1` and
`tests/harness_cli_smoke.sh`. The workspace schema is now **7**; older executables
reject it so their retention/export code cannot overlook the new durable records.
