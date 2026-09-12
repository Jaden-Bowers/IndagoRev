# General investigation policy and OpenRouter

The `general` recipe offers selective native actions instead of automatically
starting an entry/callee workflow. The operator supplies an artifact and objective;
the model chooses discovery queries, function addresses, and analysis backends.
The legacy `assisted_static` recipe remains available for historical comparisons.

## OpenRouter setup

`config/openrouter-deepseek.json` pins `deepseek/deepseek-v4-flash-0731` and the
`deepinfra/fp8` endpoint. Provider fallbacks are disabled. The response model
must match exactly, and uncertain network outcomes are not automatically retried.
No local model is used by the development driver. The profile explicitly pins
`tool_payload_encoding: json_string`: the model emits a string containing one
JSON object in the payload parameter, which is strictly decoded before dispatch.
There is no automatic fallback from object encoding.

The profile reads `openrouter_key` from the ignored `.env` in the working
directory. Use `credential_variable` to select another dotenv variable, or omit
it for `OPENROUTER_API_KEY`. `credential_format: raw` retains the existing raw-key
file interface. Dotenv parsing accepts quoted values, comments, CRLF, and an
optional `export` prefix. It rejects duplicate keys and performs no interpolation
or command execution. Keys are read only inside the HTTP adapter; neither values
nor unrelated dotenv variables enter the model request or worker environment.

Profiles require explicit `allow_target_context: true` because native evidence
is sent to the configured remote model. Endpoint selection follows OpenRouter's
[provider-routing contract](https://openrouter.ai/docs/guides/routing/provider-selection).
The adapter omits the optional `parallel_tool_calls` hint for OpenRouter endpoint
compatibility but still rejects multiple returned tool calls. An optional pinned
`reasoning_effort` selects `low`, `medium`, or `high`. Reasoning-enabled OpenRouter
calls use complete non-streaming messages so opaque provider reasoning blocks
survive tool continuation unchanged. They are never interpreted as executable
actions or native evidence. See OpenRouter's
[reasoning preservation contract](https://openrouter.ai/docs/guides/best-practices/reasoning-tokens).

Build with tests enabled, then run the opt-in driver from the repository root:

```powershell
cmake --preset windows-native -DINDAGO_BUILD_TESTS=ON
cmake --build out/native-Windows --config Release --parallel 4
$env:GHIDRA_HOME = 'C:/path/to/ghidra'
$env:JAVA_HOME = 'C:/path/to/jdk'
node tools/investigate-openrouter.cjs out/native-Windows/Release/indago.exe C:/path/to/challenge config/openrouter-deepseek.json 48
```

The supplied profile reserves 524,288 context tokens and 16,384 output tokens,
with a five-minute generation deadline. OpenRouter profiles permit explicit
deadlines up to ten minutes; unknown timeout outcomes are still not replayed.
The client uses a conservative serialized-byte ceiling, not an assumed tokenizer
ratio. OpenRouter profiles can explicitly select up to 1,048,576 context tokens;
the selected endpoint must support the requested allowance. The development driver
requests 60 seconds of native reservation per permitted generation, capped at one
hour, with 64 actions and 8 MiB of native output. Default investigation creation
limits remain unchanged unless the operator supplies a larger budget. Existing
investigations cannot expand their pinned budget on resume.

This explicitly spends inference tokens. It never executes the challenge. Reports
are written beneath `out/openrouter-investigation-*`; the driver deletes temporary
requests containing owner leases. Its objective contains no function addresses,
decoder prescriptions, or known answers. A saved report is not an independent grade.

## Persistent investigation state

Five initial questions cover input, transformation, constraints, acceptance and
output. The model refines them through `plan` decisions, and keeps tasks,
hypotheses, and subsystem summaries in separate collections. Dependencies form
acyclic graphs within each collection. A goal decomposition can itself serve as the queue until more detailed tasks
are added; `active_task` may name a saved goal or task. Analysis requires a
successful planning patch first. Ready tasks are ranked by declared
relevance and the number of unresolved tasks depending on them. These priorities
are model assessments, not verified data-flow facts.

`plan` replaces records by stable ID. The controller binds each patch to the
planning revision captured before inference, so the model does not copy revision
numbers between independent native and planning stores.
That revision advances on successful plan patches or contradictory native checks;
ordinary reads and progress accounting do not invalidate a plan revision.
Invalid dependencies or cycles reject the entire patch. The existing controller
lease and transactional checkpoint protocol persist the pending decision,
completed feedback, and investigation state. Progress accounting is idempotent
per generation, preventing double accounting when a saved response is resumed.
The existing no-replay policy for an interrupted provider request remains intact.
Before native dispatch, the exact normalized request and its bounded budget are
checkpointed. Recovery reuses that request and the generation's idempotency key,
even when the prior reservation exhausted the remaining budget; it does not
recalculate a different request or reserve the completed action twice.

`state` pages goals, tasks, summaries, hypotheses, observation references, saved
facts, recent decision/feedback turns, and retained native value/text chunks with
an offset, limit, revision, total, and continuation offset. Operator tools can use
`harness controller --request FILE` with `collection`, `offset`, and `limit` for
the same pages. Editable collections allow up to 1,024 records each; observation
history allows 4,096 records, subject to a combined 2 MiB storage ceiling. These
are storage bounds, not a requirement to put every record in a model prompt.
Queue summaries are explicitly abbreviated; complete records remain pageable.
Native evidence remains immutable and separately pageable with its source hash.
The general policy retains up to 1,024 native value/text groups (1 MiB within the
state storage budget) instead of evicting everything beyond four groups. Prompt
context includes a bounded recent window; older chunks retain offsets, partial
status, revisions and source hashes and can be retrieved through `state/values`.

Summaries should retain constants, integer widths/signedness, loop bounds,
constraints, uncertainties and evidence references. They never replace exact
native bytes for a proof. `supported` means a model assessment; only the existing
typed proof and publication gates can establish verified requirements.

## Progress, revision and escalation

The model chooses individual Ghidra, XAIR, symbolic or enrichment actions based on
the open question and available capabilities. Runtime observations can be consumed
only from operator-granted sessions. An unavailable runtime environment remains an
explicit gap; this change adds no sandbox or automatic target execution.

The controller permits at most two unproductive repetitions of an analysis/retrieval request, comparing native source fingerprints and ignoring
analysis-budget changes when identifying repeats. Analysis requests are normalized
before comparison, so omitted default fields do not bypass this limit. Four steps without new native
evidence produce a change-of-approach instruction. Default native action budgets
are bounded by remaining resources and become smaller during stalled progress.
Explicit operator budgets and the reserved final reporting turn remain enforced.
Up to 128 model generations may be explicitly requested; resume cannot expand the
pinned allowance. Each generation records request bytes and provider-reported token
usage so context compression can be measured rather than assumed.

Contradictory native hypothesis/candidate checks are surfaced to the controller.
They conservatively reopen supported planning assumptions and tasks, preserving
the contradictory observation. The model must then revise its explanation and
choose a distinguishing test. This is bookkeeping plus a model policy, not an
automatic semantic repair algorithm.

## Evaluation boundaries

Deterministic tests cover credential parsing, model pinning, request construction,
state beyond the former frontier cap, restart serialization, atomic rejection of
dependency cycles, queue priority, duplicate-query suppression, and contradiction
reopening. Native controller tests exercise plan/page/report persistence without
an entry-function prerequisite.

Live challenge results must separately establish answer correctness. Public
FLARE-On challenges cannot prove absence of training-data exposure. Neither passing
one challenge nor reducing prompt size qualifies general autonomous reasoning.
The current evaluation model is DeepSeek; prior Qwen results are historical.

Analysis feedback includes bounded, hash-verified native previews of inventories
and decompilation. These expose evidence without choosing functions for the model.
The prompt retains complete assistant/tool exchanges according to the pinned
context allowance, subtracting the current prompt, output reserve and protocol
headroom. It has no fixed exchange-count cap; compaction halves the available
history space while preserving provider reasoning in each retained message. The most recent exchange is kept whole; if it cannot
fit the pinned context budget, the request fails explicitly. Conversation storage
is bounded to 1 MiB, and separate decision/evidence records remain pageable.
The complete controller checkpoint permits 4 MiB for general investigations,
including the 2 MiB investigation state. Legacy recipes retain their old bounds.
Large page records use explicit omission descriptors and evidence references
instead of silently truncating JSON.

`retrieve` also accepts `family: artifact, operation: read` with either a file
`offset` or a hexadecimal virtual `address`, plus `max_bytes` (1 through 1024). The reader
checks investigation scope and artifact integrity, uses XAIR's static loader for
virtual-address mapping, and rejects unbacked memory. Returned hex bytes include
the artifact hash, slice hash and file offset. This reads constants; it neither
executes the target nor supplies an algorithm. Optional `raw_sha256` pins the read.

`family: calculation, operation: evaluate` applies a bounded, declarative
unsigned-integer expression program to an artifact slice. It supports byte reads,
32-bit arithmetic and bit operations, 8-bit rotates, comparisons, selection, and
persistent variables across at most 256 iterations. The program has fixed limits
on variables, assignments, expression depth and evaluation steps. It has no host
calls, memory writes, jumps, or target execution. Results pin both the artifact
slice and the model-declared program. They establish only that the stated finite
calculation produced those bytes; the model must separately cite native evidence
that the target implements the stated formula.

Partially specified analysis budgets receive the same controller defaults as
omitted budgets. Requested time is capped by the selected backend's allowance and
remaining investigation budget. Native reservation accounting is conservative;
reserved time is not a measurement of elapsed analysis time.

To collect comparable local metrics without exporting prompts or credentials:

```powershell
python tools/summarize-investigations.py out/openrouter-investigation-RUN --output out/metrics.json
```

Metrics explicitly distinguish reserved generations, valid responses, native
actions, prompt bytes, reported token usage and controller proof status. Rejected
or interrupted provider responses may incur usage absent from the logged totals.

To resume a stopped evaluation after inspecting its state:

```powershell
node tools/resume-openrouter.cjs out/native-Windows/Release/indago.exe out/openrouter-investigation-RUN
```

The driver reclaims an expired lease and retains the original model, profile,
recipe and generation allowance. It accepts only `ready` or `response_saved`;
it refuses to replay an uncertain `request_inflight` call. Original artifacts
remain intact, with resume results written separately to `resume-summary.json`.

An explicit HTTP 429 preserves a `ready` checkpoint and its native evidence rather
than finishing the investigation. `Retry-After` seconds and HTTP dates determine
the earliest next attempt; missing headers use a one-minute pause. The resume
command refuses inference before that time. Rejected calls still consume a
reserved generation, keeping the original allowance bounded. Timeouts and unknown
transport outcomes retain the no-replay policy. Resume attempts have separate,
timestamped records as well as `resume-summary.json` for the latest result.

General evidence reads request bounded scalar projections: instruction text,
addresses, widths, constants and other small primitive fields can appear directly
in each record. `value_projection` and `value_omitted` mark partial records; nested
and large fields retain their original pointers. The model's requested page size
is an upper bound, narrowed to the native reader's limit, with exact continuation
offsets. The strict external reader remains available with descriptor-only pages.

Development attempts and unresolved research questions are retained in
[the evaluation record](general-investigation-evaluation.md).
