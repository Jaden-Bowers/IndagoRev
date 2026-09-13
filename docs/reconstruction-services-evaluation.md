# Algorithm reconstruction, service contracts and failure-driven evaluation

These additions implement Tasks 5, 6 and 8 of the autonomy expansion, not a claim
that Tasks 8–10 of the all-FLARE-On roadmap are universally solved. The native
controller remains C/C++. Model inference, original-target execution and helper
execution retain their existing separate grants.

## Reconstruction loop

Use `harness propose/run` with backend `workbench`, operation `research.run`.
Arguments contain `body`; project, artifact scope and dependency pins are supplied
by the controller. Retrieve `research/tools` for the compact operation reference.

1. `body.kind: algorithm_candidate` records `domain`, `assumptions`, exact scoped
   knowledge `evidence:[{id,revision}]`, `language`, and `source_code`. Source
   extraction is the investigation model's hypothesis, not a native semantic proof.
   Evidence records should retain original analysis citations and locations.
2. `generator:{seed_hex,count}` returns 2–16 deterministic, distinct baseline,
   empty, length-boundary and bit-perturbation inputs. These are generic
   discriminators, not a guarantee of distinguishing arbitrary algorithms.
3. Execute the source with `helper.run input:{generated_hex:HEX}`. Generated
   input is limited to 4 KiB, hash-pinned and explicitly experimental; it cannot
   also claim an original address. Normal artifact-backed helper inputs remain.
4. Execute matching stdin against the explicitly granted original target with
   `experiment.run`. Existing tools collect native receipts; this workflow does
   not invent observations or automatically expand execution authority.
5. `body.kind: algorithm_comparison` takes `candidate:{id,revision}` and up to
   16 `pairs:[{helper:{id,revision},experiment:{id,revision},case:0}]`.
   The controller verifies native publication origins, exact revisions, artifact
   scope, source hashes, language, input hashes, helper repeatability and complete
   original I/O. It compares exact stdout and persists the complete tested inputs,
   controls, mismatches, incomplete observations and receipt references.
6. Revise with a new candidate's `previous` pointing to the comparison. Retained
   counterexamples are included in proposed tests and cannot be silently dropped:
   an agreement result requires replay of their inputs. History is immutable;
   successful revision does not delete earlier counterexamples.

`agreement_on_tested_inputs` means only that. It never establishes universal
equivalence, a success branch, original-service acceptance or a verified solve.
Incomplete helpers expose bounded native diagnostics and a repair next step.
Knowledge products remain `unknown` semantic state. Existing independently
graded solve certification remains separate.

This first comparison profile binds **stdin to stdout**. VM state/register
relations and other channels can be recorded by existing emulation/experiment
receipts, but are not silently coerced into this equality profile. Arbitrary
cross-channel or whole-program equivalence remains future specialized work.

## Service-behavior contract

`service_contract` requires a hypothesis, responses and nonempty `reject_if`
observations. Each response declares:

- `origin`: `captured`, `inferred`, or `invented_stimulus`.
- Exact `hex`, rationale, nonoverlapping `variable_ranges` and bounded `timing`.
- Captured responses additionally reference `{target_id,offset,max_bytes}` in an
  admitted artifact; mismatching bytes are rejected, not relabeled as observed.

Capture-byte equality does **not** establish endpoint attribution, application
framing or measured timing. Timing must currently be marked unknown, inferred or
invented. Locally replaying captured bytes remains a simulated service action.

`service_observation` references a contract/response and a new scoped capture
slice. It tests fixed bytes and length while respecting variable ranges. It
records rejection or agreement on those bytes; timing and endpoint attribution
remain unproven. Prose `reject_if` conditions are retained research obligations,
not falsely reported as automatically evaluated predicates.

These are durable contracts for Task 9 peers, not a claim that arbitrary protocol
servers have been implemented. No contract or simulated response produces an
acceptance certificate.

## Failure-driven evaluation

Operator-only CLI commands (not model tools):

```
indago evaluation matrix --request matrix.json
indago evaluation record --request attempt.json
indago evaluation compare --request pair.json
indago evaluation recipe --request recipe.json
indago evaluation show --request show.json
```

`matrix` validates the frozen catalogue, capability-to-challenge assignments and
bounded statuses (`unknown`, `missing`, `implemented`, `fixture_tested`,
`challenge_tested`). These are explicit operator assessments, not grades.
`tools/capability-matrix.cjs` generates a **filename-derived lower bound** with
unknown capability assessments, including all catalogue rows. It does not confuse
a filename route with parser/algorithm coverage. The 116-challenge denominator
and 2025 holdout are unchanged.

Attempts retain model/settings/seed, budgets, feature flags, split, outcomes,
metrics and machine-readable failure categories. Minimal source/request
reproductions are hash-checked and copied to content-addressed storage in an
evaluation root disjoint from the investigation. Records are immutable and
self-hashed. Operator-supplied outcomes do not become independently graded solves.

Matched comparisons reject different models, settings, seeds, tasks, artifacts,
budgets or multiple changed features. A matched pair is not a causal/generalization
claim. Repeat across private tasks and seeds before drawing broader conclusions.

Recipe publication requires native tested agreement plus explicit operator
answer-free review and applicability/limitation text. Export includes the helper
source and validation digest/count, but not challenge identity, inputs, outputs,
expected answers or counterexample payloads. Source can itself encode an answer;
semantic absence of hardcoding is **not** automatically proven. Review is a real
gate. Recipes live in the separate operator store and are not automatically
injected into held-out investigations.

## Bounded gates

- `tests/research_workflow.cjs`: counterexample/revision loop, mismatched inputs
  and sources, forged receipts, capture validation, protocol falsification,
  evaluation confounds and answer-free recipe export.
- `tests/research_live_ablation.cjs`: exact local Qwen model, real contained helper
  failures, model-selected original-target inputs and native output comparisons.
  Features: `native_diagnostics`, `input_suggestions`, `counterexample_feedback`,
  `validated_recipe`. Each invocation compares one feature, with one generation
  per variant. Failed model outcomes remain recorded, not suppressed.

The first four pairs yielded **6/8 tested agreements**. Both diagnostic variants
and both recipe variants passed. With input suggestions and with counterexample
context, Qwen twice repeated the invalid Python bytes-XOR expression; their paired
baselines passed. This demonstrates functioning failure capture and that extra
context can hurt this model—not that the harness eliminates model limitations.
All tests use tiny source-built fixtures, not archive challenges or benchmark
answer material. These are development measurements, not held-out transfer proof.
