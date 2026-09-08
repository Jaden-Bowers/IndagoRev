# Harness responsibility iteration — 2026-09-07

Implemented native controller-owned inventory, four-action function investigation,
verified observation storage/report assembly, bounded callee traversal, whole-workflow
budget preflight, and opt-in local schema-constrained response content.
See [contract and limits](assisted-static-harness.md).

## Live evidence

Same locally authorized model throughout: `huihui-qwen3.8-27b-abliterated`, IQ3_S,
LM Studio loopback server, 12,288 loaded context. No model replacement, downloads,
cloud inference, target execution, or access to challenge writeups.

Static target: 2014 FLARE-On C3 `such_evil`, SHA-256
`4ab2023b2f34c8c49ffd15a051b46b6be13cb84775142ec85403a08c0d846c72`.

The final FLARE-On run, `out/live-local-harness-9PHYiy/summary.json`, passed the
bounded workflow check in **41.581 seconds**:

- **Two actual model generations**, zero format/contract repairs.
- **Nine native actions**: XAIR inventory and four views each for entry
  `0x4024c0` and application callee `0x401000`.
- The model selected the application callee from controller-provided native call
  references; addresses were not hardcoded in the harness or test objective.
- **Seven checked snapshot observations** retained in a controller-assembled
  partial report. No model-authored metadata/permission interpretation was needed.
- Ghidra entry decompilation/calls/xrefs completed. XAIR CFGs, application
  decompilation and application xrefs retained their native partial status.
- The controller stopped when the remaining reservation could not fund a full
  workflow; it did not spend further model calls producing a final JSON report.

This is **not a challenge solve**. The acceptance predicate, correct input, and
validation of that input remain unresolved. The smoke checks assert native views,
traversal and snapshot checks, not prose entailment or a valid flag.

## Failures that drove fixes

- `1BZ2EJ`: schema mode removed tool-format failures, but the low-level recipe
  still stopped after inventory and emitted unsupported permission interpretation.
- `6ruFuC`: initial function/ledger pipeline passed; it stopped at startup code.
- `fiUg1Y`: the frontier exposed a conservative context-budget overflow. Context
  was reduced, and the smoke gate was tightened to require callee traversal.
- `JbeBEb`: reached application logic, then tried unfundable work and repeated an
  invalid pointer. Full-workflow preflight and controller-owned budget termination
  fixed this failure mode; it was not attributed solely to model weakness.

Earlier run reports are retained, including unsuccessful cases. No cherry-picked
run is presented as proof of general model reliability.

## Development checks

Windows final controller/HTTP/harness checks: **3/3 passed**, 9.79 seconds,
each capped at 60 seconds (`out/harness-assisted-final-tests.log`). Tests cover
structured content/SSE, pinned protocol mismatch rejection, source-copying and
deduplication, invalid pointers/fact indices, budget underflow, component pinning,
and preserving observations after provider failure, alongside existing tests.

Linux final rebuild completed. Final native controller/HTTP/harness checks:
**3/3 passed**, each capped at 60 seconds
(`out/harness-assisted-final-linux-tests.log`, detailed logs in
`out/qualification-linux-native/checks.vZmYUk`). This verifies native controller
parity; live LM Studio inference in this iteration was driven from Windows.

The same assisted traversal smoke check also passed on the source-backed PE/x64
runtime fixture, statically analyzed only: `out/live-local-harness-2jZ0rh/summary.json`,
**49.848 seconds**. This is a workflow check, not a solved acceptance predicate.

Native footprint remains approximately 1.160 GB decimal on Windows; no analysis
engines were removed. Only small static sample workspaces were added. Temporary
Linux test executables are deleted by their existing scoped test driver; existing
user caches, sample collections, and prior reports remain untouched.
