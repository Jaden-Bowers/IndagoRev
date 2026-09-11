# Solve verification and proof boundaries

The solve gate is question-bound. An investigation may declare one
`proof_requirements` entry for each `required_facts` entry. The harness derives a
stable question ID (`q0`, `q1`, ...), and every recovery, proof, selected answer,
and obligation retains the original fact index and question text. A proof for one
question is never copied to another question.

The supported proof kinds are deliberately separate rather than a strength
ladder:

| Proof kind | Sufficient evidence | What it does not establish | Static or execution |
|---|---|---|---|
| `recovered_candidate` | Deterministic reconstruction from hash-pinned native evidence, bound to one question and candidate-validation obligation | Correct decoder semantics, output, acceptance, or challenge correctness | Static; a lead only unless this exact proof kind was requested |
| `verified_transformation` | XAIR-decoded native stores reproduce the exact Ghidra byte range and transfer into that same buffer; bounded decoder templates check operands, counters, keys, reset, exit and exact back edges; a checked continuation connects stages; the final value construction cannot be bypassed or overwritten on the decoded sink path | Initializer invocation, environment-dependent resolver termination, actual sink invocation, indirect callee behavior, input acceptance, or grading | Conditional static transform and argument-byte proof; not a whole-program termination proof |
| `observed_output` | A planned `io_result` experiment and a hash-pinned observation from an explicitly granted runtime session, with the answer equal to the observed scalar | Other runs, accepted input, or independent grading | Execution is required because “observed” is an empirical claim |
| `accepted_input` | Exact stdin bytes and a complete native `io_result`; an external operator oracle bound to the artifact and question matches exact stdout/exit, while a distinct negative input does not | Universal input causality, internal acceptance-path semantics, different environments, or challenge grading | Two bounded executions against a declared I/O contract |
| `independently_graded_challenge_solve` | An operator-side benchmark submission checked by a disjoint evaluator whose hidden answer digest is bound to the catalogue, challenge, artifact, requested question, solver artifact, prepared inputs, and attempt number | Decoder behavior, observed output, accepted-input control flow, clean-room execution, or absence of training-data exposure | The grader must run; target execution is not inherently required |

`proof_requirements` uses exact kind matching. For example, an
`observed_output` record cannot satisfy an `accepted_input` question, and a
correct independent answer cannot silently resolve separate input, rejection,
constraint, or output obligations. Investigations without `proof_requirements`
retain the ordinary evidence-backed report path; that path still requires one
claim per requested fact and current complete citations. A typed report sets
`requirements_verified` when every declared question has its exact proof kind.
It sets `verified_solve` only when those requirements are complete and the report
contains an `independently_graded_challenge_solve` proof.

## Decoder validation

Initialized-x86 recovery has two explicit stages:

1. `recover_initialized_x86` creates a `recovered_candidate` for a supplied
   `fact_index`. It uses XAIR's public x86 decoder boundary to reject bytes that
   are not reachable instructions and records the exact sink representation.
2. `verify_transformation` reruns the recovery from its pinned Ghidra source and
   requires a same-artifact XAIR CFG plus the native entry/call reference that
   selected the function. It reloads the hash-checked original artifact through
   XAIR and verifies a straight-line EBP-frame initializer: constant definitions,
   byte stores, no holes/overwrites/branches/unknown calls, and the final pointer
   to that exact buffer. Unsupported initializer grammars fail closed. Only this operation can create a
   `verified_transformation` proof.

The final `solution` operation accepts a proof ID and answer. It copies the
proof's question, fact index, and obligation; the caller cannot substitute those
bindings. The terminal report is reconstructed from intact proof records, and
all declared questions must have an exact matching proof kind.

The decoder checks include negative controls for:

| Control | Required result |
|---|---|
| Decoy printable stack string after a terminating instruction | Ignored because its construction and sink are unreachable |
| Decoder placed after an entry `ret` | Rejected because the decoder call and loop are unreachable |
| Candidate bytes overwritten between construction and use | Rejected because the value-to-sink trace is interrupted |
| Decoder exit changed from the expected condition | Rejected because XAIR reports a different conditional edge |
| Changed compare immediate, back edge, or self-overlapping decoded range | Rejected despite unchanged mnemonic names |
| Native initializer byte differs from Ghidra text | Rejected by native store reconstruction |
| Native call points to an adjacent local | Rejected by buffer identity checking |
| Conditional initialization or repeated native store | Rejected by the supported straight-line grammar |

These controls are in `tests/reasoning_checks.hpp`. They protect the semantic
properties that the former exact-string comparison did not test.

## Static and dynamic boundary

Static analysis is enough when the claim is confined to decoded instruction
semantics, bounded control flow, and a value reaching a known use with no
unmodeled inputs. It is not enough to use the word “observed,” to claim a
particular environment-dependent callee produced output, or to claim that the
program accepted input in a real process. Those claims require a matching
runtime receipt. Independent challenge correctness is a separate evaluator
decision and cannot be inferred from either a recovered string or a local branch.

The fresh checker-version-2 `BrokenByte` evidence passes as a
`verified_transformation`: five reachable decoder stages reproduce the candidate
and carry it to an indirect-call argument. The indirect target was not executed
or independently resolved by that proof, so the record does not label it
`observed_output`, `accepted_input`, or
`independently_graded_challenge_solve`.

## Live validation — 2026-09-10

A fresh run against the pinned FLARE-On 2014 `such_evil` artifact exercised this
gate with LM Studio model `huihui-qwen3.8-27b-abliterated`. The controller ran 13
native actions across Ghidra, XAIR, and the symbolic engine. Qwen made two
provider generations, selected the hash-pinned `verified_transformation` proof for
question `q0`, and finished the investigation with answer `BrokenByte` in 77.267
seconds (6.446 seconds in model inference).

The result is preserved in
`out/live-local-harness-sDdO2c/summary.json`, with a compact review record in
`out/live-local-harness-sDdO2c/proof.json`. The report has
`requirements_verified: true`, `verified_solve: false`,
`behavior_verified: false`, and `independently_graded: false`, so this run
demonstrates the static transformation gate without promoting the recovered
string to either runtime behavior or independent challenge grading. A fresh
typed-proof audit checked all three evidence pins and reported
`citations_current` with zero issues.

That earlier run predates checker version 2. It remains historical evidence,
not a current proof of the strengthened gate. Legacy transformation proofs must
be regenerated before publication; their old digests are not grandfathered in.

## Gate closure — checker version 2

The final local-Qwen run is `out/live-local-harness-ijY4Ht/summary.json`
(compact record: `out/live-local-harness-ijY4Ht/proof.json`):
`BrokenByte`, 2 generations, 13 native actions, 5 stages, 65.302 seconds,
`requirements_verified: true`, `verified_solve: false`. XAIR reconstructed all
513 original native stores in function `0x401000`, with buffer displacement
`EBP-513` and transfer at function offset 5275. No challenge execution occurred.

Publication now rechecks analysis-head/Ghidra revision freshness, pinned revision
and status, complete object hashes, and the selected JSON pointers. A partial
backend envelope is usable only for a present exact field that the typed checker
validated. Runtime receipts and their negative-control records are reloaded and
hash-verified; primary-artifact and answer/question bindings are rechecked.
Audits perform these same integrity/freshness checks but do not rerun semantic
analysis. SHA-256 record digests are **not authentication signatures**: the local
database and operator are trusted, not hardened against a same-user attacker.

## Bounded native I/O receipts

`indago runtime io-run --request io.json` executes an explicitly trusted PE on
Windows or ELF on Linux. It is an operator-side action, not a new model execution
capability or debugger. This profile does **not** provide isolation: do not use
it for malware. It stages a hash-checked single executable in a fresh working
directory, supplies exact stdin from a bounded file, captures stdout/stderr bytes,
and persists `io_result`. It does not provision dependencies or target systems.

Example request (replace paths and digest):

```json
{
  "operation": "io-run",
  "project": "demo",
  "file": "C:/fixtures/benign.exe",
  "artifact": "<64 lowercase hex characters>",
  "input_hex": "4f50454e",
  "trusted_target_ack": true,
  "timeout_ms": 5000,
  "max_output_bytes": 4096,
  "acceptance_oracle": "C:/operator/io-oracle.json"
}
```

The optional acceptance oracle must be outside the model workspace and present
before execution. Its schema is:

```json
{
  "schema": "indago.io-oracle.v1",
  "artifact_sha256": "<same artifact digest>",
  "fact": "accepted input",
  "stdout_hex": "4f4b",
  "exit_code": 0,
  "negative_input_hex": "4e4f"
}
```

Without an oracle the receipt can support observed output, never acceptance.
Acceptance is scoped to this declared exact I/O contract and contrasting run;
neither it nor its negative control is independent FLARE-On grading. Runtime
session read access must be explicitly granted when creating the investigation.
The `experiment` → `feedback` → `prove_observation` → `solution` → `finish` path
consumes the receipt. Recording an experiment after a run is retrospective
verification, not a prospective prediction or causal experiment.

Limits: 64 MiB executable, 16 KiB stdin, 64 KiB per output stream, 60 seconds
total child-execution budget (split between candidate/control), and a 20 GiB
storage floor. An optional `cancel_file` cancels process-tree collection.
Timeout, cancellation, truncation, still-open inherited output pipes, or changed staged inputs produce incomplete
receipts that cannot prove output/acceptance. Non-UTF-8 output is retained as hex,
not replaced with fabricated text. Current textual answer proofs require UTF-8.

Focused checks: `tests/reasoning_checks.hpp`,
`tests/proof_publication_checks.hpp`, `tests/runtime_proof_checks.hpp`,
`tests/runtime_io_contract.cjs` (12 checks), and
`tests/benchmark_contract.cjs` (25 checks). The native I/O fixture is a generated
diagnostic, not part of the frozen FLARE-On denominator.

Final focused validation passed on both platforms:

- Windows harness/controller/HTTP: 3/3; final harness rerun also passed after the
  portable test-source fix. Logs: `out/task2-gate-final-windows-tests.log` and
  `out/task2-gate-final-harness-tests.log`.
- Linux native rebuild, model/controller, harness, and HTTP: passed. Model log:
  `out/qualification-linux-native/checks.UGSE87/model_tests.stdout.log`;
  harness/HTTP log: `out/task2-gate-linux-tests-final.log`. The Linux harness
  exercises real ELF input/output, incomplete receipts, inherited pipes, and
  both behavior proof kinds. All individual tests have a 60-second limit.
- Native I/O CLI contract: 12/12, `out/runtime-io-contract-8G9RuW`.
- Independent-grader contract: 25/25, `out/benchmark-contract-eJhvdV`.

The Linux test driver enables the actual XAIR header path and places receipt
workspaces on the native build filesystem: the host's `/tmp` is an 8 GiB tmpfs,
which correctly fails the unchanged 20 GiB execution-storage floor. Large
temporary test executables are removed by the existing bounded test driver.
No full-archive qualification, 2025 evaluation, or malware execution was done.
