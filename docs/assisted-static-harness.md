# Controller-assisted static investigations

The opt-in `assisted_static` exploration recipe moves mechanical work from the
model into the native controller. It does **not** claim to solve arbitrary
FLARE-On challenges or prove behavioral conclusions.

## Responsibilities

- Before the first inference call, the controller obtains bounded XAIR inventory
  through the ordinary owned, budgeted action path. It saves available format,
  architecture, entry and image-base scalars as exact snapshot observations.
- `function` selects a native address reference. The controller issues four
  independently charged actions: Ghidra decompile, XAIR CFG, Ghidra calls and
  Ghidra xrefs. Each receives 20 seconds and 128 KiB of output reservation.
  A durable cursor and normal action idempotency keys support resumption.
  A full workflow is preflighted against all three remaining budgets before its
  first dispatch; resumed work uses its existing reservations. The assisted recipe
  publishes retained observations automatically when no full workflow fits.
  Waiting jobs are returned, not resubmitted as new actions. Authority/budget
  failures stop the workflow; backend failures remain visible in its results.
- Bounded pseudocode is read automatically. At most eight native call-destination
  references form the discovery frontier; visited locations are not reanalyzed
  by the function action. These are candidates, not proof of function identity,
  reachability, application relevance, or observed execution.
- `record` copies a complete scalar from verified native evidence, pins the raw
  hash and generates a citation plus an exact-equality check. The model does not
  supply the value, hash, citation metadata, or report JSON. The ledger holds
  at most 16 observations. Each observation is rechecked on report publication.
  The assisted recipe also saves selected address references and complete small
  pseudocode scalars automatically. Larger pseudocode remains in native evidence.
- `finish {saved:true}` assembles a partial report from the ledger. The assisted
  recipe rejects handwritten reports. Early finishing is rejected when an
  unvisited destination and budget for a full four-action workflow remain.
  The final reserved generation can always report gaps. Provider contract or
  budget exhaustion also retains saved observations instead of an empty report.

Required facts remain gaps: an exact observation attached to a fact is **not**
proof that the fact was resolved. In particular, saving pseudocode is not solving
its acceptance predicate. Backend semantics remain separate, and every report
still sets `verified_solve: false`. The frontier is bounded, not exhaustive;
indirect calls, omitted callees, and unexplored candidates can remain.

## Decision examples

```json
{"kind":"function","payload":{"evidence_id":"ev_RETURNED_ID","pointer":"/program/entry"}}
```

```json
{"kind":"record","payload":{"fact_index":0,"evidence_id":"ev_RETURNED_ID","pointer":"/program/architecture"}}
```

```json
{"kind":"finish","payload":{"saved":true}}
```

`fact_index` is zero-based. `record` accepts complete scalars of at most 512
encoded bytes, not collections or truncated strings. Existing low-level analyze,
retrieve, and checkpoint decisions remain available. Function and record
decisions also work in other recipes without the assisted recipe's finishing
restrictions.

## Local structured-response mode

An explicitly pinned local profile may set `response_mode: "json_schema"` with
object payload encoding. The request supplies a response schema instead of tools,
and the controller accepts exactly one completed JSON content decision. Tool mode
remains the default. There is no automatic fallback, model substitution, reasoning
scraping, or execution of malformed/truncated responses. The schema constrains
JSON syntax and the outer decision envelope; native validation still enforces
the operation-specific payload and all authority boundaries. This is not a claim
that every decision has a complete provider-enforced semantic schema.

Example local profile: `out/lmstudio-structured-profile.json`. Existing saved
profiles and investigations are not silently modified. Create a new investigation
with the profile and explore using `recipe: "assisted_static"`.

## Remaining autonomy work

The model still selects relevant callees and interprets algorithms. Further work
includes durable hypothesis/acceptance-condition obligations, verified candidate
input derivation, experiment selection, and task-specific solution validators.
Unknown targets are static-only until disposable execution labs are implemented
and explicitly granted. A correct inventory, successful decompilation, or checked
snapshot report is not a FLARE-On solve.
