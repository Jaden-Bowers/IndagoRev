# Long-running static investigations

The Pi frontend can supervise a persistent question queue. This is a bounded
static-investigation runner, not a kernel execution environment or a guarantee
of autonomous understanding. The ordinary interactive Pi launcher remains
available; this runner intentionally has a narrower tool surface.

## Start

Write an operator brief in a UTF-8 text file (maximum 65,536 characters). Include
the questions you care about, exclusions, expected evidence, and what would count
as a useful stopping point. The model can decompose it into smaller questions.
Use a dedicated case directory containing only the intended input files.

From the repository root, with dependencies installed and the native CLI built:

```powershell
node agent/long-run.mjs `
  --exe PATH_TO_INDAGO `
  --cwd CASE_DIRECTORY `
  --target TARGET_FILE `
  --state NEW_INVESTIGATION_DIRECTORY `
  --brief BRIEF_FILE `
  --model huihui-qwen3.8-27b-abliterated@iq3_xxs `
  --hours 4 `
  --max-batches 48 `
  --max-tokens 2000000 `
  --batch-ms 480000 `
  --max-generations 16
```

The LM Studio endpoint defaults to localhost port 1234. Each batch checks the
exact loaded model and its loaded context length through `/api/v0/models`;
unavailable context metadata pauses the run. The launcher requires exactly one
loaded model instance, avoiding duplicate-model VRAM contention. It never loads
or unloads models automatically. It uses the actual loaded window, reserves at
least 25% for compaction, and defaults to 2,048 output tokens.
Select **Stop at limit** in LM Studio. The runner does not claim to enforce that
server setting through the OpenAI-compatible API. Pi handles ordinary compaction;
a provider failure or interrupted response pauses for review. Fresh conversations
between batches prevent indefinite accumulation of raw logs.

The runner defaults to `--local-thinking off`, explicitly sending
`reasoning_effort: none` and `chat_template_kwargs.enable_thinking: false` to LM
Studio. This was checked against the local Qwen IQ3_XXS model; Pi's own thinking
toggle alone did not disable server-side reasoning. Use `--local-thinking server`
to leave that choice to the server and consider a larger `--output-tokens` budget.
Support for these request fields is provider/model dependent, not a universal API
guarantee. The ordinary interactive launcher is unchanged.

## Persisted state and evidence

- `questions.json`: immutable original brief/hash, target hash, parent/dependency
  relationships, attempts, statuses, summaries, failed approaches, next actions,
  and hash-pinned source receipt references.
- `native/`: shared native project, analysis, evidence and knowledge across batches.
- `batches/NNNN/`: separate Pi session, requests, tool results, receipts and logs.
- `supervisor.json`: identity, immutable budgets, batch outcomes and token totals.
- `report.json`: current question coverage and findings. These counts measure the
  question queue, **not** percentage of program semantics recovered.
- `inspection-progress.json`: repeated native inspections for each question across
  batches. Two unchanged calls require consulting the existing evidence.

The model calls `question_add`, `question_list` and `question_checkpoint`.
A successful decomposition or checkpoint ends the batch through the controller;
no additional final-prose generation is required. The checkpoint marker separates
this deliberate stop from an unexpected provider abort.
There are at most 128 questions, 12 new children per call and three attempts per
question. Dependencies refer to earlier IDs. An answered question must cite a
native receipt or stored tool-result file inside the investigation; its hash is
checked before subsequent scheduling. This is source provenance, **not semantic
verification**. Every checkpoint remains a model assessment. Backend omissions,
unsupported instructions and contradictory evidence must stay explicit.

## Stop, resume and budgets

Press Ctrl+C, or create a file named `STOP` in the investigation directory.
The supervisor checks the stop file and resource budgets every two seconds.
Rerun the same command to resume; remove `STOP` first. Unfinished questions are
retained. An interrupted batch requires reviewing native jobs and receipts, then
adding `--acknowledge-interruption true`. This acknowledgement does not terminate
or reconcile native workers for you. A crash leaves an exclusive
`supervisor.lock`; only remove it after confirming the previous supervisor and
workers have stopped. The acknowledgement also covers a crash-marked running
batch. Never run two supervisors against the same state.

Budgets are cumulative and immutable for the investigation. Defaults: four hours,
48 batches, two million reported input/output/cache tokens, 4 GiB investigation
storage, and a 1 GiB free-space floor. A batch is at most nine minutes and 128
generations. Budgets are watchdog thresholds, **not OS quotas**: storage can
overshoot between checks and token totals arrive at completed assistant messages.
Compaction/internal provider work may not be fully represented in those totals.
No automatic trace deletion is performed. Two batches without new cited evidence
or question disposition changes pause instead of consuming the remaining budget.
The native executable and frontend source/dependency lockfile identities are
pinned too. Changing them requires a new investigation rather than silently
resuming with a different implementation.

## Execution boundary

Restricted-static mode removes shell, PowerShell, WSL, arbitrary write/edit,
original-target execution, generic command dispatch, annotations and administrative
tools. A tool-call policy also rejects disallowed invocations. File reading is
limited to case/investigation roots, resolving symbolic links. Specialized static
tools remain available through `tools_search`. This is an application tool policy,
**not an OS sandbox**. Native parsers still process untrusted bytes on the host;
use an appropriately isolated analysis machine for unknown or hostile inputs.

Linux operators may explicitly pass `--contained-helpers true` to expose the
existing native contained helper workflow. Its isolation prerequisites must be
provisioned; failures do not fall back to a shell. Windows rejects that option.
This release does not provide a Windows-to-WSL contained-helper bridge. Driver
loading, kernel debugging, live anti-cheat experiments and guest provisioning are
not enabled by this runner.

## Verification scope

Tests cover loaded-window selection, queue persistence/dependencies, receipt
requirements, locks, identity changes, budgets, interruption and stagnation. A real
Pi SDK test uses a local deterministic provider to decompose a question, reject a
shell call and persist an evidence-backed checkpoint against the native CLI.
Live-model smoke results are development checks, not sustained-run qualification
or claims about protected-driver analysis.

### Local Qwen development smoke (2026-10-14)

With one IQ3_XXS instance loaded at 131,072 context, a source-built PE fixture
completed three batches in approximately 129 seconds: one decomposition and two
answered questions (XAIR inventory and a bounded entry-function CFG). Reported
input/output/cache usage totaled 76,879 tokens. The controller retained the native
partial-analysis status and two hash-pinned receipt references; it did not execute
the fixture or independently certify the model's interpretations. Reopening the
same investigation returned the completed report without another inference batch.
Local artifacts are under `out/long-run-qwen-smoke-v4/` and are not public corpus
results. The target SHA-256 is
`f8f3dd51279e15cbeb7c852040967a0f6d907c23c3b258c967ebce7cb88ec105`.

Earlier attempts usefully exposed duplicate-model VRAM contention, server-side
thinking despite Pi's thinking-off setting, and unnecessary post-checkpoint model
turns. The runner now checks single-instance readiness, explicitly controls local
thinking, and ends batches on controller checkpoints. The model initially supplied
a result ID where a receipt path was required; the validator rejected it and the
model corrected the citation. No silent relaxation of the evidence requirement
was needed.
