# IndagoRev agent

A Pi coding session with the existing C/C++ analysis engines and program knowledge
store. The previous native controller remains available for comparisons.

The [context engineering revision](../docs/context-engineering.md) documents the
current retrieval and recovery behavior. Use `investigation_focus` to change the
current question; `analysis_tools` reveals additional tools, including bounded
`graph_context` neighborhood lookup. Request manifests and working state are
saved inside each session directory. Enhanced modes reserve the last generation
for synthesis and apply explicit shell deadlines. All modes have bounded recovery
from provider output-length stops.

The six-change revision enables environment resolution, direct artifact inspection,
compact investigation state, successful-call stagnation detection, final-markup
rejection, and on-demand [recipes](recipes.md). Java and archive executables are
resolved and probed before inference; their paths, versions and hashes are stored
in `environment.json`. Missing tools are explicitly unavailable, not implicitly
installed. The strings helper runs under the already configured Node runtime.

`artifact_inspect` lists archives, extracts one exact member to a new case-local
file (32 MiB/30-second limits), inspects Java bytecode, or returns located strings.
It never executes a target. Extraction preserves parent/child hashes. Native
decompilation, functions and xrefs are immediately visible for native-looking
targets. Other operations remain discoverable.

`investigation_update` maintains at most five cited facts, one candidate and one
unresolved obligation. These are model assertions, not independent verification.
Raw receipts remain on disk but are no longer automatically ingested/replayed by
the default compact-state mode. Two identical inspections cause the next unchanged
call to be blocked even if it exited successfully; editing a helper allows retry.
Tool markup is not a valid final response. Invalid endings record unresolved state
and can receive a repair request only within the existing generation budget.

For controlled comparisons, the JavaScript launcher accepts `features: []` for
the previous enhanced behavior or an explicit array of `environment`, `surface`,
`state`, `progress`, `final`, `recipes`. Omission enables all six. Run independent
Qwen-only arms with `node agent/ablate.mjs PREPARED_JSON NEW_OUTPUT_DIRECTORY`.
This copies only hash-checked original inputs, not prior helper outputs or answers.
It runs the baseline, each feature alone, and their combination on the same cases.
Single runs are diagnostic ablations, not statistical qualification.

Requires Node.js 22+, pnpm, a built IndagoRev CLI, and a configured local model
server. Install the pinned dependencies with:

```text
pnpm --dir agent install --frozen-lockfile --ignore-scripts
```

Start an interactive investigation:

```text
node agent/cli.mjs --exe PATH_TO_INDAGO --cwd CASE_DIRECTORY --target TARGET_FILE --state NEW_STATE_DIRECTORY --mode knowledge --authority host
```

`target` is relative to `cwd`; other paths are relative to your shell directory.
LM Studio defaults to its localhost port and the development Qwen model. Override
with `--model MODEL_ID` and `--endpoint OPENAI_COMPATIBLE_BASE_URL`. This launcher
currently configures a local OpenAI-compatible provider. Provider credentials are
not imported from the native controller. Pi configuration is private to the state
directory, leaving user-global Pi settings alone.

Remote OpenAI-compatible providers use an environment-variable reference so API
keys are never written into agent state. Pass `--provider NAME --endpoint URL
--api-key-env ENV_NAME`; the named variable must already exist in the launcher
process. Benchmark preparation accepts the same three options.

Modes:

- `plain`: normal Pi coding tools plus the native CLI location and usage context.
- `tools`: adds direct IndagoRev tool adapters.
- `knowledge`: uses compact investigation state by default and retains receipts
  and a compaction checkpoint. The former automatic retrieval behavior is available
  in ablations with the `state` feature disabled.

All modes use the same native executable and host environment. Pi reads complete
small source files and supports normal scripts, file editing and shell commands.
On Windows, Git Bash is selected when installed; PowerShell and the explicit WSL
tool support the other environments. WSL commands take Linux paths and an optional
distribution. Tools installed by a helper can change the shared host environment;
use identical preinstalled dependencies or reset hosts for stricter comparisons.

`--authority analysis` is the default: the prompt prohibits original-target
execution while allowing generated helpers. `host` explicitly permits original
target execution and exposes desktop capture. These are operating policies for a
trusted coding session, not a host sandbox. Generic shells and `native_command`
can access the host. Existing contained native helpers/guest profiles remain
available through the CLI. Windows screenshots return an image only when
`--vision true` declares a compatible model; otherwise they return a saved path.
The Qwen text profile does not establish vision support. Screenshot capture is
Windows-only in this frontend.

Direct tools: `program_open`, `analysis_tools`, `analyze`, `decompile`, `functions`,
`xrefs`, `runtime`, `run_experiment`, `native_command`, `program_search`, `knowledge_search`,
`remember`, and `wsl`. Addresses for decompile/xrefs are hexadecimal addresses
returned by native analysis. Select another program with `program_open`.
`native_command` accepts argv plus optional native JSON; this exposes existing
less-common operations without another controller protocol. `run_experiment`
provides named argument/stdin/file/environment cases through native runtime IO.
Debugger, Frida, DynamoRIO, capture and reanalysis use `runtime` or the CLI.

Native responses preserve status/backend/evidence IDs. Large responses remain in
receipts and receive readable previews. Model findings are native knowledge
assertions with dependencies and freshness. `remember` accepts an optional finding
ID to correct it without copying revision numbers; unfamiliar support references
are retained as unresolved. Shell receipt paths can be cited in finding text;
temporal proximity to a command is not treated as evidential support.
Generic shell receipts establish what
was requested/returned; they do not establish complete file lineage, semantic
correctness, or target acceptance. Repeated unchanged inspection is bounded as
described above; runtime experiment actions are exempt from that inspection rule.

Use the same state directory to reopen a Pi session and its native knowledge.
Pi handles conversation compaction; the extension saves active identity/recent
observations and retrieves native summaries. Knowledge records survive sessions.
Interrupted native dispatches retain a `dispatching` receipt and a job ID when
available. Reconcile uncertain side effects instead of blindly replaying them.
Host process-tree termination does not attest termination of remote/WSL services.

For noninteractive use, add `--prompt TEXT --timeout 540000 --max-generations 16`.
Logs are capped at 32 MiB per invocation. A final prose response is kept for review;
it is never automatically labeled a verified solve.

## Matched development benchmark

Preparation validates the frozen catalogue, extracts challenge files, verifies
hashes and creates independent directories for all three modes. It does not call
a model or execute a challenge. It requires at least 512 MiB free and refuses to
overwrite an existing output directory.

```text
node agent/benchmark.mjs prepare --exe PATH_TO_INDAGO --corpus CORPUS_ROOT --archive PATH_TO_7Z --output NEW_OUTPUT_DIRECTORY
node agent/preflight.mjs --prepared OUTPUT_DIRECTORY/prepared.json
node agent/benchmark.mjs run --prepared OUTPUT_DIRECTORY/prepared.json
```

The four selected 2014–2024 cases produce twelve trials. Each uses the same prompt,
model, temperature 0, declared 65,536-token context, 2,048 output-token maximum,
sixteen model turns and nine-minute process deadline. Model calls used internally
by compaction can add usage; session logs retain those separately. 2025 is excluded.
The benchmark resumes completed rows; an unsettled trial requires reconciliation.
Trial files and outcomes remain local. Public metrics omit answers and local paths.
`has_final_response` includes failure prose, so answer production requires review;
independent grading remains a separate operator step.

Verification:

```text
pnpm --dir agent test
```

Set `INDAGO_TEST_EXE` to enable real native integration tests. Those cover original
target identity after companion imports, knowledge persistence, XAIR/Pi dispatch,
and positive/negative IO on the repository's benign fixture. Mock provider tests
verify wiring, not reasoning quality. The executable's own build/capability checks
remain prerequisites for engine availability.
