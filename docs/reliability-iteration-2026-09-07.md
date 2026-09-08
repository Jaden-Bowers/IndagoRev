# Harness reliability and native parity iteration

Scope: five requested priorities—explicit claim validation, deeper static
investigations, recovery, controlled dynamic feedback and Linux parity. GUI and
broad qualification remain deferred. Unknown targets were not executed.

## Changes

- Added [native claim checks](claim-validation.md), exposed through read-only
  retrieval and report publication. Prose is not silently declared verified.
- Added `investigation/tools`, a bounded guide derived from actual backend
  capabilities, with mutating operations removed. The `static_behavior` recipe
  guides function discovery, Ghidra decompilation/calls/xrefs and XAIR CFG/SSA or
  explicitly selected AIRECE flow. Native views retain separate evidence.
- Clarified evidence-page limits and index search filters in model instructions.
  Complete small text/scalar pages now survive tool continuation, alongside the
  prior primitive observation memory. Full text is retained only when its page
  is complete and at most 768 encoded bytes; grouped memory remains 1536 bytes.
- Retained a bounded recovery history and suppressed byte-identical native
  requests already known to have failed. Changed requests may proceed under the
  same scope and remaining budget. The model—not an untrusted backend message—
  selects any alternative. Unknown in-flight outcomes are still not replayed.
- AIRECE flow now reports missing source/target selectors before spawning a
  worker. It does not infer selectors from an address or create new semantics.
- Added an explicit local-only `tool_payload_encoding: json_string` profile
  option for compatible servers that mishandle nested object tool parameters.
  The offered schema declares a string, the strict decoder parses exactly one
  object from that genuine tool parameter, and the profile/schema hashes pin
  this choice. The default object profile still rejects unsolicited strings;
  reasoning text, malformed JSON and extra tool calls remain rejected.

## Development checks

`tests/static_behavior_smoke.cjs` exercises the external-owner harness using
scripted native queries and verified evidence pages. It is not model inference.
`tests/live_local_harness.cjs ... PROFILE behavior` separately attempts the same
depth with the authorized local model, with a maximum 12 generations and an
outer deadline below ten minutes. The driver fails when cross-backend work or
required cited metadata is missing; it never claims a verified solve.

The first live depth attempts did not pass: one returned only inventory after
discovery/argument errors, and another returned invalid encoded payloads before
native work. These failures remain in `out/live-local-harness-CnXAB0` and
`out/live-local-harness-Z0XtfQ`. A successful scripted gate must not be substituted
for successful autonomous reasoning.

Native source-backed debugger checks use the bundled DbgEng/GDB adapters, not a
new debugger. The Windows PE64 capture/reanalysis run passed with XAIR and Ghidra,
preserving distinct epochs and observation-to-artifact lineage:
`out/reliability-runtime-pe64.log`. The Linux driver compiles only the checked-in
benign runtime fixture for ELF32/ELF64 and runs scoped static and runtime checks.
Each test has a bounded deadline; no unknown challenge or malware was executed.

Windows claim/publication/recovery/provider regressions passed (2/2, 7.66 s):
`out/reliability-windows-tests.log`. The Linux build's first 480-second attempt
expired during CMake regeneration/glob checks, before compilation; it was resumed
with another bounded build command, not represented as a passed test.

## Completed native checks and remaining model-quality gap

- Scripted cross-backend harness passed in **80.44 s**:
  `out/static-behavior-1SQyLe/summary.json`. Ghidra functions, decompilation,
  calls and xrefs completed; XAIR inventory, CFG and SSA were partial and stayed
  labeled partial. Verified pages and an explicit address check reached the
  persisted report. This does not prove the two representations equivalent.
- A real Ghidra recovery failure was found during live inference: a timed-out
  import left `indago.gpr` but no saved Program. Later `-process` launches failed
  permanently. The adapter now recognizes the exact missing-Program diagnostic
  and permits a later bounded import **without overwrite**. The exact failed
  workspace subsequently returned `runtime_probe` at `0x140001000` successfully:
  `out/reliability-ghidra-import-recovery.log`.
- PE32 and PE64 DbgEng capture → XAIR/Ghidra reanalysis passed:
  `out/reliability-runtime-pe32.log`, `out/reliability-runtime-pe64.log`.
- Final Windows controller/harness tests passed **2/2 in 10.44 s**:
  `out/reliability-final-windows-tests.log`.
- Linux rebuilt with the latest controller, provider, claim checks and Ghidra
  recovery. Logs: `out/reliability-linux-final-build.log` and
  `out/reliability-linux-recovery-build.log`.
- Linux native controller/harness/HTTP tests passed **3/3**, each capped at 60 s:
  `out/reliability-linux-native-tests.log`. Generated test executables were
  removed by the existing bounded driver after each test; logs remain.
- Source-compiled ELF32/ELF64 static harness and GDB runtime-workbench checks
  passed **4/4**, about six seconds overall:
  `out/reliability-linux-matrix.log`, `out/reliability-linux.zGkXKp/`.
  Runtime checks cover capture/reanalysis plus existing bounded symbolic/witness
  operations. They execute only the benign checked-in fixture.

The pinned encoded local profile progressed further in
`out/live-local-harness-NK06h1/summary.json`: six generations, no parser repairs,
Ghidra function discovery/decompilation and two cited claims. Its explanation
matched the fixture's `input == 7 ? 42 : input + 3` behavior, with an explicit
single-backend limitation. It stopped before XAIR and exact format metadata,
so the deeper live smoke driver correctly returned failure. This is useful
progress, not a passing autonomous cross-backend or challenge-solving gate.

The next run (`out/live-local-harness-CqOGCh`) reached Ghidra decompilation **and**
XAIR CFG but then hit the local conservative context-byte ceiling. That exposed
a controller bookkeeping defect: pre-transport size errors consumed generation
reservations and were treated as model-format failures. A typed context error now
triggers up to two bounded compactions and refunds only that demonstrably unsent
reservation. First, prior assistant arguments are omitted while the full latest
tool result is retained as explicitly untrusted data. Second, older observation
groups and recent action summaries are omitted, with disclosure. Scope, envelope,
objective and the original durable history remain intact. Failure to fit after
both levels ends with an explicit partial result; uncertain transport outcomes
are never refunded/retried. The regression verifies two actual provider calls
remain two counted generations despite an intervening size rejection.
Windows context/controller tests passed in **5.69 s**:
`out/reliability-context-tests.log`.

The same updated controller rebuilt and passed on Linux:
`out/reliability-linux-context-build.log`, `out/reliability-linux-context-tests.log`.
The real CLI validation endpoint also reproduced the earlier FLARE-On arithmetic
contradiction from preserved static evidence, returning actual `4204544`
(`0x402800`) versus asserted `0x401800`:
`out/reliability-real-claim-check.log`. The challenge was not executed.

Final live depth rerun: `out/live-local-harness-AZ7k7k`, **111.69 s**. It reached
Ghidra function discovery/decompilation and XAIR CFG, used bounded context
compaction, then returned malformed JSON in the final encoded tool payload.
The strict parser rejected it and the driver correctly failed. Consequently,
the native five-priority implementation and bounded parity checks are available,
but reliable autonomous cross-backend final reports with this local model remain
an **open model/protocol-quality gate**, not a completed challenge-solving claim.
No further protocol loosening, guessed corrections to model JSON, cloud fallback
or unknown-target execution was used to turn that failure into a pass.
