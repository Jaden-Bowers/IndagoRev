# Built-in native model loop — bounded static scope

Current development uses the pinned OpenRouter DeepSeek profile and the
[general investigation policy](general-investigation.md). The local Qwen setup
and authorization statements below describe earlier development runs, not the
current model selection.

For controller-owned inventory, function workflows, a checked observation ledger,
and opt-in local structured responses, see [assisted static investigations](assisted-static-harness.md).

Implemented: one pinned local/OpenRouter provider, a durable tool-call loop,
bounded static analysis/retrieval, recipe guidance, board checkpoints, cited reports,
generation accounting and cancellation. **Local LM Studio inference was authorized
on 2026-09-07** for `huihui-qwen3.8-27b-abliterated` at
`http://127.0.0.1:1234/v1/chat/completions`. Cloud inference remains unconfigured
and unauthorized. Profiles are investigation-scoped, not a silent global default.
Earlier verification below was offline-only.
See [live local validation, serving repairs and semantic failures](local-harness-validation-2026-09-07.md).
Offline tests use scripted protocol responses and local mock HTTP servers; they
do not establish model quality or live OpenRouter interoperability.

The current operator-authorized LM Studio profile is saved in
`out/lmstudio-serving-profile.json` (12288 loaded context, 1024 output tokens,
60-second generations). The opt-in live driver accepts that file as its last
argument. It performs static-only native analysis; a matching format-label smoke
check is not a verified solve or general reasoning qualification.

The last generation offers only a finish decision, also enforced locally.
Retrieved primitive native values have a four-group / 1536-byte observation
memory with evidence IDs, hashes, revisions and JSON pointers; omitted detail
must be retrieved again. Native values remain untrusted data, not instructions.
Reports must use exact required-fact labels. Current citations do not prove
claims: live tests exposed fabricated formats and incorrect address arithmetic.
Optional [structured claim checks](claim-validation.md) now verify exact native
operands before publication; unstructured prose remains unverified. Read-only
`investigation/tools` exposes the bounded current backend guide, and
`validation/check` supplies counterexamples to explicit numerical assertions.
The `static_behavior` recipe targets separate Ghidra and XAIR/AIRECE views.

For local servers that mishandle object-valued tool parameters, an investigation
may explicitly pin `tool_payload_encoding: json_string`. The offered tool then
declares an encoded string, parsed strictly into one object after receipt of a
real structured tool call. The default remains `object`; no automatic protocol
fallback or reasoning-text scraping is performed. The opt-in behavior profile
is `out/lmstudio-behavior-profile.json`. See the
[reliability iteration record](reliability-iteration-2026-09-07.md) for actual
live results versus scripted native checks.

## Ownership and authorization

An investigation has exactly one declared reasoning owner: `external` or `builtin`.
Externally owned investigations reject `explore`; external callers cannot publish
reasoning decisions into a built-in investigation. Read APIs, lease renewal and
cancellation remain available. An active controller blocks another controller and
ownership transfer. Transfers settle/cancel actions, archive old controller state,
clear its lease and require a new explicit model profile when switching to built-in.

Neither creating an investigation nor inspecting/normalizing a profile contacts a
model. `explore` requires a live owner token, current revision, and explicit
`allow_inference: true`. The product does not silently enable or pay for inference.

Use `harness create --request FILE` with the ordinary objective/facts/budgets and:

```json
{
  "owner": {
    "mode": "builtin",
    "name": "selected-local-model",
    "profile": {
      "provider": "local",
      "endpoint": "http://127.0.0.1:8080/v1/chat/completions",
      "model": "EXACT_SERVER_MODEL_ID",
      "context_tokens": 16384,
      "output_tokens": 2048,
      "generation_ms": 60000,
      "weights_revision": "OPERATOR_SUPPLIED_REVISION",
      "quantization": "OPERATOR_SUPPLIED_QUANTIZATION",
      "tokenizer": "OPERATOR_SUPPLIED_TOKENIZER",
      "chat_template": "OPERATOR_SUPPLIED_TEMPLATE",
      "server_version": "OPERATOR_SUPPLIED_VERSION"
    }
  }
}
```

This is an owner fragment, not a complete creation request. Missing optional model
metadata is stored as `not_declared`, never inferred or called qualified. Inspect
canonical profiles with `harness profile --request FILE` containing `{ "profile": ... }`.

Once a model has deliberately been configured, the execution request is:

```json
{
  "project": "demo", "id": "inv_ID", "owner_token": "lease_TOKEN",
  "expected_revision": 1, "allow_inference": true,
  "max_generations": 8, "recipe": "input_validation"
}
```

Invoke `harness explore --request FILE`. `max_generations` (1–32) and recipe are
pinned for that controller run. Do not increase them implicitly on resume.
`harness controller --project demo --id inv_ID` retrieves durable controller state;
`harness events` includes generation provenance and tool history.

## Provider policy

Local profiles accept only literal `127.0.0.1` HTTP endpoints with an explicit port
and `/v1/chat/completions` path. No DNS alias, arbitrary LAN host, proxy setting,
cloud credential or automatic remote fallback is accepted. Loopback routing alone
does not attest that the serving process performs inference locally.

OpenRouter profiles use the fixed HTTPS endpoint and require:

```json
{
  "provider": "openrouter",
  "model": "EXACT_SELECTED_MODEL_ID",
  "credential_file": "CONTROLLER_ONLY_FILE_CONTAINING_KEY",
  "allow_target_context": true,
  "provider_order": ["EXPLICIT_PROVIDER_ID"]
}
```

The endpoint, selected model, routing order, sampling parameters and metadata are
hashed and pinned. Requests disable provider fallback, require requested parameters
and request no provider data collection. Responses from a different model ID are
rejected. Provider-reported identity and token usage are retained when returned;
missing metadata is not represented as measured zero. No automatic retry follows an
uncertain transport outcome or HTTP error, which could otherwise duplicate billing.

Credentials are read by the controller's in-process HTTP adapter, not passed on a
command line, placed in worker environment variables, embedded in prompts or saved
in controller transcripts. Credential **paths**, model declarations and other user
profile metadata remain visible in ordinary operator-owned records. This is not a
substitute for host/lab isolation: current parser workers share the operator OS.

Windows uses OS WinHTTP. Linux statically links OpenSSL and its declared private
archive dependencies; system trust roots are used for certificate/hostname checks.
No external curl process or Python HTTP dependency is introduced. Build prerequisites
on the current Ubuntu host include `libssl-dev`, `pkgconf`, `libjitterentropy3-dev`,
`zlib1g-dev` and `libzstd-dev`. Their notices are retained under `vendor/openssl/`
and included in the Linux payload. Other distributions may have different OpenSSL
private archive requirements, resolved from their `openssl.pc` static link metadata.

Both transports reject redirects, enforce response-size and total-time bounds, and
support cancellation. SSE tool-call fragments are reconstructed and checked after
the bounded response is collected; this is protocol streaming support, **not live
GUI/token rendering**. Incomplete streams or truncated tool calls never execute.

## Investigation loop and recovery

The model receives one small decision tool, `investigate`, with kinds:

- `analyze`: native static request plus gap/prediction/expected-evidence/fallback;
  opt-in [knowledge/finite-validation mutations](harness-mutations.md) reuse this path.
- `retrieve`: bounded graph, coverage, exact evidence or scoped knowledge lookup;
  investigation/scope pages the explicit component set.
  [Evidence JSON-pointer paging](evidence-paging.md) navigates large native
  documents and UTF-8 text while retaining a verified source hash.
- `checkpoint`: replace the bounded investigation board.
- `finish`: cited report or explicit terminal gap.

The controller applies the decision contract, explicit component scope and existing
static-action budgets. AIRECE/Ghidra semantics and partial results remain separate.
Unknown tools, shell/target execution, ungranted networking and cross-project or
out-of-scope component retrieval are rejected. The model cannot modify ownership or grants
through a tool argument or target-borne instruction.

`harness recipes` provides guidance for configuration recovery, input validation,
file formats, API effects, state machines, runtime-code recovery and component
interaction. These are investigation prompts/obligations, not implemented lab
capabilities or fixed-address scripts. A runtime/system request without the required
environment ends with a specific gap or capability-blocked result.

Before a provider request, the controller reserves one generation and its output/
time ceilings and persists input messages. Before executing a decision, it persists
that response. Native actions use generation-specific proposal keys and existing
backend idempotency keys. A response saved before a crash can therefore resume its
action without repeating a completed worker. A request interrupted before its response
was saved has an unknown outcome; resumption reports partial instead of reissuing it.
Still-running backend jobs return `waiting_for_job`; inspect/recover them through
the normal job API before resuming. Invalid responses/tool arguments get at most two
repair attempts before an explicit terminal report. Identical native actions retain
the existing three-proposal bound.

Inputs, prompt/tool/profile hashes, response hashes, provider-reported usage and
elapsed generation time are retained. Requests have a conservative UTF-8 **byte**
ceiling after reserving model output space; this is deliberately not presented as
exact tokenizer accounting. Context is rebuilt from the board plus recent tool
continuation, not an unbounded chat transcript. Payloads that do not fit are omitted
with a narrowing diagnostic, never silently clipped into apparently complete JSON.
An oversized request rejected locally before transport now gets at most two
bounded compactions without charging an inference generation: omit prior assistant
arguments first, then older observation groups/recent action summaries. Latest
feedback and authority constraints remain, omissions are disclosed, and the full
durable history is unchanged. This special handling never retries an uncertain
network outcome or relaxes the conservative context ceiling.

Portable bundles retain controller history but strip active leases and convert
built-in ownership to external ownership on import. Inference profiles, credential
locators and cloud grants inside an imported bundle are provenance, **not portable
authority**. Reconfigure explicitly to enable inference on another workspace.

## Verification and remaining completion gates

Windows offline controller and native HTTP tests cover single-model routing policy,
SSE assembly, malformed/truncated output, native XAIR tool feedback, repair bounds,
no uncertain transport replay, cancellation, imported-grant stripping, loopback HTTP,
redirect refusal and timeout. Every test is short and bounded; no live inference is
configured by the test suite. Sources: `tests/model_tests.cpp` and
`tests/model_http_tests.cpp`; Linux reuse driver: `tests/run_linux_model_checks.sh`.

Development verification on 2026-09-07 (no live inference):

- Windows native suite: **14/14 passed**, 165.64 seconds, under a 480-second
  watchdog. Logs: `out/qualification-native-e3f75d2f8bbd40349cbfd0fdb00df9d5/`.
- After the final capabilities-metadata rebuild, the controller, HTTP, external
  harness and knowledge tests passed again: **4/4**, 2.49 seconds, each bounded
  to 60 seconds. CLI capabilities also confirmed explicit inference policy.
- Linux native controller and HTTP tests: **2/2 passed**, each bounded to
  60 seconds. Summary: `out/model-linux-checks.log`.
- Linux bounded CLI regression: **6/6 passed** (knowledge, PE harness, ELF32/64
  harness and source-backed ELF32/64 runtime fixtures), approximately nine seconds
  overall. Summary: `out/model-linux-qualification.log`.
- Linux `ldd` lists only standard C/C++ system runtime libraries; no separate
  SSL, crypto or curl runtime is required. Five OpenSSL/private-dependency notice
  files are included in the embedded engine payload manifest.

These are bounded development checks, not production certification or live-provider
qualification. Unknown target binaries were not executed by this verification.

The full planned harness is **not complete yet**. Remaining gates include live
provider capability/model qualification, tokenizer-specific context measurement,
provider-attested disposable labs, unlinked filesystem-effect reconciliation,
task-specific behavioral validation, and runtime/helper grants tied to disposable
labs. Correct citations alone do not establish entailment; reports still set
`verified_solve: false`.

Bounded transformation publication and derived-target admission now use the same
controller with a separate explicit creation grant. The scripted offline chain
extracts a PE from a wrapper, admits it, obtains native XAIR evidence, retains a
counterexample and corrects the finite comparison. See [contract and limitations](harness-derived.md).

Per the requested ordering, full footprint/performance optimization still follows
harness completion and must preserve the analysis tools and engine payloads. A
small [build-churn fix](build-churn.md) already avoids rewriting unchanged generated
payload inputs during development; no payload has been removed by that fix.

Protocol references used during implementation: [OpenRouter client tool calling](https://openrouter.ai/docs/guides/features/tool-calling),
[provider routing](https://openrouter.ai/docs/guides/routing/provider-selection),
[llama.cpp tool calling](https://github.com/ggml-org/llama.cpp/blob/master/docs/function-calling.md),
[WinHTTP timeouts](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpsettimeouts),
and [OpenSSL hostname verification](https://docs.openssl.org/3.5/man3/SSL_set1_host/).
