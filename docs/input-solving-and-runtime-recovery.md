# Task 6: bounded input solving and runtime-code recovery

The core remains C/C++. XAIR owns x86 lifting, XAIR_SYM owns expressions, memory,
taint and solving; AIRECE owns its existing interprocedural directed-flow path.
No additional x86 semantic layer or debugger was introduced.

## Implemented

### Observed input-to-caller-branch loop

Frida `recipe:input` records completed synchronous stdin reads (`ReadFile` on
Windows, `read` on Linux), bounded `memcpy`/`memmove` propagation, and `memcmp`
comparisons. Only relevant input calls are retained. At most 64 spans, eight copy
links, 256 input bytes and 256 events are tracked. Concurrent stdin reads with
uncertain ordering invalidate automatic mappings. Inline copies, direct syscalls
and unrelated input APIs are not implicitly covered.

The native `runtime solve-input` operation checks delivery/comparison identities,
byte intervals, original experiment stdin, retained copy bytes and the observed
comparison sign before invoking XAIR_SYM's builtin call model. Experiments using
the input recipe do this automatically and return `input_solutions` with persisted
session/observation references. Equal and unequal native models can be passed to
`case.solver_candidate` for original-target replay; no answer needs to be copied by
the model.

When available, up to 64 observed caller code bytes, general registers and two
4096-byte writable regions seed existing XAIR lifting and XAIR_SYM execution.
The API's low 32-bit result is modeled; unspecified high return bits remain
symbolic. Up to 16 caller instructions connect the comparison to a local branch.
`caller_binding` and `caller_branch.entailed_by_comparison` distinguish successful
binding and conditional entailment from partial observations. This is not arbitrary
interprocedural reconstruction or a whole-program success proof. Original-target
positive/negative runs and an operator oracle establish the observed acceptance.

### Captured input bytes and branch candidates

`runtime symbolic` accepts the existing captured observation, selected `path`,
`symbolic_registers`/`symbolic_memory`, plus:

```json
{
  "input_ranges": [{"source":"stdin","address":"0x2000","size":2,"offset":0}],
  "byte_constraints": [
    {"address":"0x2000","allowed_hex":"41"},
    {"address":"0x2001","allowed_hex":"4243"}
  ]
}
```

Input mappings reference captured memory only. Sources may be stdin, argv or file;
file mappings use `name`, argv mappings may carry `index`. They are declared
mappings, NOT evidence that a particular API delivered those bytes. Actual input
arrival still requires concrete observations. Overlapping input mappings,
uncaptured bytes and oversized requests are rejected.

The existing native selected-path adapter carries register, flag and memory SSA
values across up to 16 selected blocks. Off-path states are excluded and preceding
branch conditions stay in the solver state. Up to 256 memory bytes become symbolic;
other captured general-purpose registers, flags and memory remain concrete seeds.
Byte alphabets are native constraints, not output filtering. Branch expression
dependencies expose the input symbols and the branch block address with a bounded
4096-node traversal. This is dependence evidence, not success/failure labeling.

SAT branches contain `input_candidates`. All memory candidates in a branch come
from a single native model batch; independent per-byte solver choices are not
combined. Each candidate retains channel mapping, address, offset, completeness
and the explicit requirement for original-target replay. UNSAT and UNKNOWN remain
native verdicts. No candidate is an acceptance or challenge-solve proof.

### Harness and replay

Debugger experiment steps now admit `symbolic` after `capture`. They forward the
bounded path, memory/input mappings and constraints to the native adapter. Existing
`experiment/read` paging exposes the resulting symbolic observation.

A subsequent experiment case can reference:

```json
{"solver_candidate":{"session":"run_ID","observation":"obs_ID",
 "terminal":0,"branch":1,"candidate":0},"input_hex":"00000a"}
```

The controller checks that the session was admitted to this investigation and
belongs to the selected original artifact. It reads a completed native symbolic
receipt, checks SAT/completeness and seals the receipt hash. Only the mapped interval
of the supplied baseline stdin/file bytes is replaced. Prefixes, suffixes and other
channels are retained. Missing baselines, wrong target/session, stale receipt and
out-of-range patches fail closed. Automatic argv patching is deliberately rejected
until an explicit text/encoding contract exists.

Run both a candidate and a contrasting branch/counterexample through the existing
experiment loop. Concrete output/exit observations and any operator-pinned oracle
remain separate from symbolic predictions. A contradiction is evidence to revisit
mapping, path, call model or environment—not a reason to promote a SAT answer.

### External calls

The existing AIRECE `source_to_sink`/`path_condition` directed-flow surface retains
its bounded predecessor/call propagation and function-depth/path limits. The
captured-block adapter does not invent unresolved call transitions.

XAIR_SYM's existing call-model library now supports bounded `memcmp` with concrete
pointers/length (up to 256 bytes) and symbolic memory contents. It constrains zero
and the sign according to the first differing unsigned byte; nonzero magnitude
stays symbolic, since it is not specified by the API contract. Memory taint reaches
the result. Symbolic pointers or unsupported signatures fall back to unknown-call
handling; unavailable memory does not imply equality.

`strlen` no longer chooses a length by sampling a solver model or mistaking a failed
read for a terminator. It requires a concrete NUL within a 256-byte bound; otherwise
the existing incomplete-call fallback applies. Call-model library identity is now
`0x00010001`; old builtin-environment snapshots are not silently upgraded.

These are native call-model changes, not a claim that arbitrary captured calls,
indirect calls, TLS or OS state have been reconstructed.

### Runtime-code recovery

Use `engine:frida, recipe:code, recover_code:true`, or the corresponding DynamoRIO
effects collection. The harness scans a bounded event prefix and feeds at most two
unique code captures/write-execute observations through existing `feedback` and
XAIR reanalysis. Frida code collection allows 256 events to leave room after loader
metadata. Duplicate captures at the same address with identical bytes are skipped.

Recovery depends on observed executable bytes, not an initialized-local XOR pattern.
Raw-byte hashes, native code epochs, source observation IDs, runtime addresses,
synthetic analysis-image mappings and backend results are persisted through existing
derivation machinery. The synthetic image is analysis-only, not a runnable unpacked
program. Captured bytes do not acquire execution authority. Existing investigation
derived-scope limits still apply; this action does not automatically broaden scope.

## Strategy and research conclusions

These are implementation choices, not claims of a universal solving algorithm:

- Bound the question before exploration: use observed or CFG-selected paths, native
  dependence slicing, small byte alphabets and explicit time/state budgets. Repeated
  loop blocks consume the same 16-block path budget; no unbounded unrolling.
- Preserve symbolic pointers when the native memory model can reason within known
  objects. Otherwise capture/concretize the relevant address in a new experiment;
  never silently choose a solver address and treat it as globally valid.
- Prefer native bit-vector constraints for short arithmetic/checksum branches. For
  long deterministic transforms, use the existing bounded helper workspace and
  validate its outputs against original evidence or execution. Do not replace an
  unknown function with an unconstrained output and call the path proved.
- For cryptographic transforms, obtain concrete inputs, keys/state and outputs when
  observable, then reconstruct and validate the algorithm. General cryptographic
  inversion is not assumed feasible; a helper implementation is still a hypothesis.
- On expensive queries, switch to another bounded path, concrete counterexample or
  validated helper; increasing every search bound is not the default response.

Primary references informing these choices: [KLEE search and external-call options](https://klee-se.org/docs/options/)
describe alternative search policies and explicit external-call handling;
[Programming Z3](https://z3prover.github.io/papers/programmingz3.html) explains
solver/tactic composition. They inform orchestration, not a new dependency.

## Validation and remaining scope

Tests cover x86/x64 predecessor constraints, exact constrained input candidates,
infeasible predecessors, native `memcmp` equality constraints, receipt-bound
baseline patching, foreign-session rejection and original-target replay plumbing.
The replay-plumbing test uses a synthetic capture and does not claim its instruction
bytes originated from that executable.

A trusted subtraction-decoder fixture allocates writable memory, reconstructs
return-42 machine code, changes protection and calls it. The live recovery test
checks the exact expected 4096-byte region hash and persisted XAIR derivation. No
challenge/malware execution or long qualification test is required.

The source-backed input fixture reads eight bytes, copies them and compares them
through an actual external call. The test observes that original executable, solves
the native comparison, binds its caller branch and replays both candidate and
counterexample. The oracle contains only expected stdout/exit and a negative seed,
not the answer. Windows evidence: `out/task6-input-loop-TGM5mi/summary.json`;
Linux evidence: `out/task6-input-loop-THl28S/summary.json`. Both accepted the derived
candidate and rejected the counterexample. These are trusted synthetic fixtures,
not FLARE-On coverage claims. The selected-path tests also solve a bounded two-byte
additive checksum loop and reject contradictory predecessors.

The latest Windows code-recovery demonstration is
`out/task6-recovery-aolAjh/summary.json`: one deduplicated region, exact fixture
byte hash, completed native reanalysis. Ten affected Windows suites passed in
23.47 seconds (`out/task6-final-all-tests.log`). Ten affected Linux suites passed
in 38.72 seconds (build-cache `task6-final-disk-tests.log`). Linux uses disk-backed
`TMPDIR`; its 7.6 GiB tmpfs correctly triggers the existing storage floor. Each
regression has a 90-second timeout. Final added input-provenance negative controls
and the final controller rebuild were also checked separately on Windows.

LM Studio Qwen (`huihui-qwen3.8-27b-abliterated`) completed the same guided smoke
workflow in five generations and three native actions (96.190 seconds of model
time). It selected the input recipe, replayed native equality/counterexample
references, and finished with cited original-target PASS/FAIL observations.
`out/task6-input-loop-ebmEop/proof.json` is audited directly against persisted
native receipts by `tests/task6_model_audit.cjs`; the full report is beside it.
The oracle and prompt did not provide the answer. This is a guided tool-orchestration
test, not autonomous discovery of an unknown challenge strategy. Earlier bounded
model attempts failed on argument placement/recipe selection; the controller now
normalizes unambiguous shared inputs, advertises granted workbench operations and
explains recipe placement. It rejects conflicting shared inputs. The successful
report intentionally retains `verified_solve:false` and `requirements_verified:false`.

The small XAIR_SYM change is committed and published as `c9569b3` on the
`indagorev-integration-20260911` branch; the parent pins that exact revision.

The bounded Task 6 implementation covers observed input mapping, comparison and
caller-branch solving, constrained selected paths, native call models, candidate
replay, and live non-XOR code recovery. Remaining broader-autonomy research includes
arbitrary interprocedural state reconstruction, additional input/call APIs, automatic
loop summaries, general checksum/crypto recognition, validated algorithm recovery,
and catalogue-wide qualification. None is implied by the synthetic completion gate.
