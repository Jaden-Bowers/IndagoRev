# Bounded autonomous runtime experiments

Task 5 connects the investigation model to existing runtime adapters; it does not
introduce a debugger. The implemented scope is bounded, operator-granted
experimentation on trusted host targets, not universal process containment.

## Authority and inputs

Create the investigation with `workbench_mutations:true` and an explicit grant:

```json
{"runtime_execution":{"trusted_host_execution":true,
 "targets":[{"target_id":"tgt_ID","file":"/absolute/original/fixture"}],
 "engines":["io","debugger","frida","dynamorio","rr"]}}
```

Only grant the engines and original artifacts intended for execution. The original
file is canonicalized and hash-checked at creation and dispatch. Derived artifacts
do not acquire execution authority. Portable import removes the grant. Arbitrary
PIDs, executable paths, debugger commands and instrumentation scripts are not model
inputs. This is NOT a sandbox: targets can use host resources/network and create
children. Use a disposable target system before running untrusted samples.

Retrieve `experiment/capabilities`, then propose:

```json
{"backend":"workbench","operation":"experiment.run","arguments":{
 "engine":"io","prediction":"Only the candidate produces acceptance",
 "cases":[
  {"label":"positive","argv":["--fixture"],"input_hex":"7965730a",
   "files":{"payload":"626f756e64"},"environment":{"EXPERIMENT_VALUE":"explicit"}},
  {"label":"negative","argv":["--fixture"],"input_hex":"6e6f0a",
   "files":{"payload":"626f756e64"},"environment":{"EXPERIMENT_VALUE":"explicit"}}
 ]}}
```

All engines accept literal argv, bounded stdin, plain-named files and explicit
environment entries. Limits: two distinct cases, 16 arguments, 4 KiB stdin,
four files, 16 environment entries; action reservation 40 seconds/64 KiB.
Omit the action budget. Each case gets an owned working directory.
Input manifests record hashes and preparation, not proof of actual target delivery.

- I/O uses the existing hash-checked original-byte copy and replacement environment.
- GDB uses fixed-shell, quoted literal arguments and native-owned redirections.
  No arbitrary shell command surface is exposed.
- DbgEng adopts a suspended process created with explicit input/output handles and
  environment. DbgEng owns subsequent debug events and control.
- Frida uses bounded native stdin delivery and registered recipes; DynamoRIO inherits
  controlled worker input handles. Engine-added environment variables can remain.
- rr inherits controlled input, records, packs and replays through the existing adapter.
- Loader/shell injection environment variables are rejected. Relative dependencies
  must be supplied explicitly; this is not installation/environment virtualization.

An operator target entry may include `acceptance_oracle`, an absolute path to an
`indago.io-oracle.v1` file outside the model workspace. Its hash is sealed and
rechecked at execution. The original-target I/O validator runs the distinct
negative control; the model cannot replace the oracle or infer acceptance from a
mere output difference. The oracle is applied to the first case, with its own
negative control; the second case retains ordinary observation semantics.

## Observation and follow-up

Default debugger steps select original entry, continue, capture, then XAIR
reanalysis. Up to six explicit steps can select `breakpoint`, `continue`,
`capture`, `registers`, `modules`, `threads`, `trace`, `reanalyze`.
Breakpoints accept scoped `static_address`, `rva`, or `function`; capture
and reanalysis retain runtime/static lineage. Traces cap at 32 steps; captures
at two 1-KiB ranges. Initial loader stops are bounded and recorded.

For one debugger case, up to two separately granted companions are supported:
`companions:[{target_id,argv:["--companion"],ready:{file:"ready",hex:"5245414459"}}]`.
Readiness checks exact bytes in the companion's owned directory for at most two
seconds. Session identities, readiness evidence and cleanup are retained. This is
a bounded readiness protocol, not arbitrary service discovery or child attachment.

Frida `recipe` selects `io`, `input`, `code`, `modules`, `config`, or `network`.
`input` and `code` allow 256 events. The input recipe automatically produces bounded
native comparison candidates; see [input solving](input-solving-and-runtime-recovery.md).
DynamoRIO `telemetry` selects `blocks` or `effects`. Native bounded event
prefixes and partial verdicts remain intact. rr has a 16-MiB trace budget and only
replays a packed, replay-ready trace.

Compact receipt previews give numbered cases, output, completeness and native
acceptance result. Comparisons retain changed output/exit status and bounded
observation counts/values. They do not establish causal completeness.
Retrieve `experiment/read` using the knowledge ID and a JSON pointer such as
`/comparison` or `/cases/0/observations`. Runtime session IDs are admitted to
scoped observation reads. Use a new prediction and bounded experiment for follow-up.

Typed experiment receipt citations support PARTIAL observation reports only.
They cannot satisfy an answered/verified solve. Independent grading and the
existing proof gate remain unchanged.

## Interruptions and cleanup

Dispatch intent is journaled before launch/steps. Stable experiment keys link
runtime sessions/requests when the returned ID was lost. Immutable publication is
recovered transactionally; settled actions are never re-executed.

Read `experiment/reconcile` with `{action_id:ORIGINAL_EXPERIMENT_ACTION}`.
It checks investigation ownership, request/artifact identity, journal hashes,
native session states and pending request states. The journal scan is bounded to
128 files; missing, ambiguous or incomplete evidence stays unknown. It does not
replay anything and does not equate a terminal process with reversed side effects.

Propose `workbench/experiment.cleanup` with `{action_id:ORIGINAL_EXPERIMENT_ACTION}`
to terminate/cancel only the reconciled owned sessions. Local execution authority
is required. The immutable cleanup product retains before/after state and errors;
read it with an explicit pointer such as `/after`.
Cancellation/lifetime expiry terminate autonomous debugger targets rather than
detaching. Escaped children, host failure and external effects are not guaranteed
to be cleaned or rolled back. Unknown dispatches require reconciliation, not retry.

## Execution policy and research findings

Start with static evidence when a transformation and sink can be established
cheaply. Execute to answer a concrete unresolved branch, input, live-code or
process-interaction question. State a prediction and contrasting input; change one
dimension where possible. Prefer complete output/exit receipts, reached original
locations, selected registers/memory and capture reanalysis, then targeted API or
block observations. Page raw records instead of supplying entire traces.
Changed output, temporal proximity and satisfiable conditions are not causal proof.
Catalogue-wide strategy evaluation remains a later qualification activity.

## rr packaging

`tools/build-rr-linux.sh` installs the private source build under
`out/runtime-payload/linux/replay` (or the configured payload root), retains
provenance/license and checks required bitness helpers. SDK/build/staging/archive
paths are configurable through `INDAGO_RR_SDK`, `INDAGO_RR_BUILD`,
`INDAGO_RR_SDK_STAGE`, and `INDAGO_RR_SOURCE_ARCHIVE`.
No host CPU/PMU/ptrace policy was modified for this work.

## Demonstrations (2026-09-12)

Trusted standalone fixtures only; no malware/challenge execution:

- Windows DbgEng, Frida and DynamoRIO delivered argv/stdin/file/environment inputs;
  target-written output was checked. Native partial telemetry was preserved.
- Linux GDB, Frida, DynamoRIO and rr delivery passed. rr record → pack → replay
  completed with a roughly 2.9-MiB trace.
- Windows harness companion readiness → entry breakpoint → capture → XAIR reanalysis
  → owned-session cleanup completed with native completed results and no unknown
  outcome. Evidence: `out/task5-harness-engine-2i0bSi/summary.json`.
- Live LM Studio `huihui-qwen3.8-27b-abliterated` completed plan → positive/negative
  experiment → partial report in four generations (44.024 seconds model time).
  It reported exact contrasting outputs and a typed receipt citation, not a solve.
  Evidence: `out/task5-live-gnpGOB/summary.json`.
- Drivers: `tests/task5_engine_contract.cjs`, `tests/task5_engine_contract.sh`,
  `tests/task5_harness_engine_contract.cjs`, `tests/task5_live_model.cjs`.
  The native experiment suite includes grants, bounds, receipt reuse/paging,
  reconciliation, cleanup and rejection of observation-only answered claims.
- Final affected native suites passed 5/5 on Windows (21.84 seconds) and 5/5
  on Linux (39.62 seconds): experiments, helpers, worker, harness and model
  controller. Each individual test is bounded; no long qualification run was used.

Remaining beyond this bounded implementation: hostile-target isolation, escaped
child containment, richer IPC readiness protocols, exhaustive engine/architecture
qualification, crash-injection coverage and full-catalogue autonomous evaluation.
