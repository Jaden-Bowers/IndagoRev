# First live LM Studio harness validation — 2026-09-07

Operator-authorized local inference only. Discovered endpoint:
`http://127.0.0.1:1234/v1/chat/completions`; exact selected model:
`huihui-qwen3.8-27b-abliterated`. The server reports GGUF, IQ3_S, qwen35
architecture and initially **8192 loaded context tokens** (distinct from its advertised
262144 maximum). These are server declarations, not independent weight checks.
No cloud fallback, credentials or target execution. Subsequent operator-authorized
model-specific serving changes are recorded below.

## Implemented and checked

- Fixed local tool selection: this server rejects a named-object `tool_choice`
  with HTTP 400 and accepts `required`. There is still exactly one offered
  `investigate` tool; strict response validation is unchanged. OpenRouter keeps
  its prior named-tool request.
- Added an opt-in `tests/live_local_harness.cjs` driver with loopback/model pins,
  bounded generations, per-generation deadlines, storage preflight, durable logs,
  action/report inspection and citation audit. It is not part of offline tests.
  The initial profile used 8192 context / 1024 output tokens. Earlier exploratory
  profiles used the documented 16384 default before loaded context was inspected.
- Added compact instructions for read-only, no-derived-grant investigations;
  unused mutation instructions remain available only in the richer prompt.
  Generation budgets are visible and the final turn is explicitly asked to finish.
- Retained bounded structured decisions in generation events for diagnosis;
  this does not convert provider reasoning text into actions.
- Added readable XAIR program `format` and `architecture` labels alongside
  unchanged native enum values. A direct static query verifies PE/x86 alongside
  native format 2 / architecture 1 on the selected challenge.
- Windows rebuild succeeded. Latest native controller regression passed in
  2.38 seconds (`out/lmstudio-final-regression.log`), including local request
  compatibility and rejection of reasoning-only text without a structured call.
  Linux has not yet been rebuilt for these live-provider changes.

## Targets and actual outcomes

Source-backed resource fixture:
`out/lief-link-check/Release/indago_resource_fixture.exe`.
FLARE-On 2014 C3: only `such_evil` (7168 bytes) was extracted from C3.zip,
using the year directory's supplied password. No write-ups/solutions were read.
SHA-256 `4ab2023b2f34c8c49ffd15a051b46b6be13cb84775142ec85403a08c0d846c72`.
Extraction and static parsing do not constitute execution or a solved challenge.

| Report under `out/` | Outcome |
| --- | --- |
| `live-local-harness-yTNxG9` | Initial HTTP 400; no actions |
| `live-local-harness-KgSVcx` | Four-generation budget exhausted; no native actions |
| `live-local-harness-YdN2zn` | Fixture: native XAIR action and evidence paging; six-generation budget exhausted |
| `live-local-harness-RKNnzg` | Challenge: native XAIR action and evidence paging; six-generation budget exhausted |
| `live-local-harness-bfOMRe` | Challenge: same bounded loop; final response missing structured call |
| `live-local-harness-A2fCcY` | Compact 8192-context profile: stopped after bounded response-repair failures |

Each live investigation finished in under 50 seconds. **None produced a cited
successful final analysis, and none is a verified solve.** The native-action and
verified evidence-page portions of the loop worked in several runs. Provider
format consistency and reasoning/report quality did not pass qualification.

## Initial serving compatibility issue

`tests/lmstudio_stream_probe.cjs` reproduced HTTP 200 / finish_reason=stop with
no structured tool calls, both with and without streaming. The non-streaming
diagnostic contained tool-like markup only in `reasoning_content`, not a valid
tool invocation. A separate strict JSON-output probe similarly returned its JSON
only in the reasoning field, with empty content. A simple tool probe sometimes
works, so advertised tool support is insufficient to establish this profile's
reliability. The exact model/template/parser cause is not yet established.

The harness intentionally does not scrape and execute reasoning or arbitrary
text as tool calls. The operator subsequently authorized serving configuration
changes; the following section supersedes the earlier pending-permission state.

## Authorized serving repair and follow-up

LM Studio 0.4.16+2 remains on loopback with the same IQ3_S weights and model ID.
Only this model's saved defaults were changed:

- Override the existing Jinja template with `enable_thinking = false` so tool
  calls are not stranded in `reasoning_content`.
- Remove the redundant `safe` filter: LM Studio's custom-template renderer
  rejected it with HTTP 400 / `Unknown StringValue filter: safe`.
- Explain that object parameters contain raw JSON, with an explicit object
  example. Some actual structured calls otherwise contained an escaped string
  for `payload`; those remain rejected, not reparsed into actions.
- Increase loaded context to **12288**, verified with `lms ps --json`, while
  retaining 1024 output tokens, 60-second generations, existing quantization,
  GPU offload and other load settings. No weights were downloaded or replaced.

Saved defaults live in
`C:/Users/Jaden/.lmstudio/.internal/user-concrete-model-default-config/huihui-ai/Huihui-Qwen3.8-27B-abliterated-GGUF/Huihui-Qwen3.8-27B-abliterated-UD-IQ3_S.gguf.json`.
Original defaults and upstream template are preserved in
`out/lmstudio-serving-backup-2026-09-07/`. Restore the original JSON to that
model-specific defaults path and reload the same model at context 8192 to undo
these changes. Do not overwrite unrelated model settings. The pinned current
test profile, including template hash, is `out/lmstudio-serving-profile.json`.

Both non-streaming and streaming diagnostic calls returned typed tool calls
after the template repair. That does **not** qualify reasoning quality:

| Report under `out/` | Actual outcome |
| --- | --- |
| `live-local-harness-5SatZd` | Typed native action; 8K conservative context-byte ceiling then blocked progress |
| `live-local-harness-y7a9JB` | 12K: six typed calls, no repairs, one native action; no final report |
| `live-local-harness-CfRliD` | Rejected escaped-string payloads; no native actions |
| `live-local-harness-WHy4uc` | Fixture: native action and retrieval; final non-finish decision rejected |
| `live-local-harness-e4WY0b` | Cited partial report, but incorrectly called the PE/x86 target ARM64 Mach-O: **semantic failure** |

The last failure is particularly important: current citation IDs do not establish
that prose follows from the cited evidence. Native `/program` values explicitly
said `PE` and `x86`. The model had lost that earlier page after further retrieval.

Follow-up controller fixes reserve the last generation for a finish-only tool
schema and reject other decisions locally. Up to four groups / 1536 JSON bytes
of primitive values from verified native pages survive subsequent feedback,
retaining evidence ID, raw hash, revision and exact JSON pointers. Individual
values over 256 encoded bytes and composite values are omitted. This is bounded
untrusted observation memory, not another IR or a claim of semantic truth.
Offline tests verify retention across an intervening checkpoint, final-turn
restriction and strict rejection. Windows regression passed in 4.50 seconds.

The opt-in live driver now fails its process status when native actions, cited
claims or matching native format/architecture labels are absent. This narrow
label check is not general semantic entailment and never marks a verified solve.

## Final bounded reruns

After observation retention and an explicit exact-required-fact-label instruction:

| Report under `out/` | Time | Result |
| --- | --- | --- |
| `live-local-harness-CvDlto` | 40.14 s | Correct PE/x86 values retained; report rejected for an invented required-fact label. Prose also made an incorrect address-range calculation. |
| `live-local-harness-WpaQ3v` | 38.94 s | Source-backed fixture: one native action, two cited claims, PE/x64 labels match; partial report. Audit correctly flags incomplete native analysis. Prose still misstated a segment end address. |
| `live-local-harness-NDIbdv` | 37.65 s | FLARE-On C3: one native action, two cited claims, PE/x86 labels match; partial report with unresolved behavior. Two citations current, no citation issues; six generations, no repairs. |

The last two runs returned success from the **narrow smoke driver**, not a
semantic-analysis gate. They establish local inference → native action → verified
evidence retrieval → persisted cited partial report. They do not establish
challenge recovery, I/O semantics, Ghidra use in this live run, or universal
autonomy. Incorrect numerical reasoning remains a demonstrated gap requiring
deterministic claim checks or counterevidence, not another citation-only check.

Final Windows controller regression passed in 3.52 seconds. No individual live
run exceeded one minute; no unknown target was executed. No Linux rebuild or
broader production qualification was performed in this serving-repair iteration.
The running server was confirmed bound to **127.0.0.1:1234**, not a LAN interface.
Current template profile hash:
`050533b4fe9a6f8f6bad5f404d3ee51c744777264b097cf9d65df47aac60aad0`.

Upstream context: [LM Studio tool-use documentation](https://lmstudio.ai/docs/developer/openai-compat/tools).
Observed local responses, not that documentation alone, establish the results above.
