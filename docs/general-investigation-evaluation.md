# Autonomous investigation development evaluation

## Scope and current qualification

These are development attempts for issue #4, using only
`deepseek/deepseek-v4-flash-0731` through OpenRouter. No local Qwen inference was
performed. Provider routing was explicitly pinned per attempt, with fallbacks
disabled. Changes between attempts make this a debugging record, not a controlled
comparison of providers or context sizes.

The driver supplies the binary, a general challenge-answer objective, and the
required report facts. It supplies no function addresses, algorithm, decoder, or
expected answer. The controller selects functions and analysis operations. No
challenge binary was executed on the host. Public challenge use does not establish
that the model has never encountered related material during training.

The selected development artifacts are:

| Challenge | Artifact | SHA-256 |
| --- | --- | --- |
| 2015 C2 | very_success | `9852afb172bc03a50d291c70faa724c69a10af9e6ee88457185ce5e0705216f0` |
| 2016 C3 | unknown | `143f41667d3b7ab0a22324a0ec6b42191e54db1fb20ffffa025b279c80b3e54b` |

Run `i2MBy2` is an independently graded static solve of 2015 C2. The model chose
the functions, reconstructed the algorithm, located the encoded bytes, declared a
bounded calculation, and reported `a_Little_b1t_harder_plez@flare-on.com`. A
separate operator-side decoder produced the same 37 bytes and forward-encoded the
candidate back to the reversed target table. The official FireEye solution PDF
(SHA-256 `78ca51d7e77b5ef5251d4adcdfc021f80fb83dc553f93ee9528edd7ff6275175`)
independently confirms the same algorithm. The target was not executed.

The controller report status is `partial`, because its first `answered` report
cited three partial Ghidra results alongside complete evidence. The publication
gate rejected that claim, and the model conservatively resubmitted it as partial.
This is a successful independently graded development solve, but it is not a
controller `verified_solve`, a behavioral execution, or a pass entered into the
frozen 116-challenge benchmark. The gate diagnostic now identifies each offending
citation so a future model can remove or replace it without downgrading a resolved
fact.

## Development attempts retained

Run suffixes identify local `out/openrouter-investigation-SUFFIX` directories.
Cancelled and failed attempts remain in the record.

| Run | Outcome | Main development finding |
| --- | --- | --- |
| B9VEZM | partial | Explicit tool-payload encoding needed |
| 4Mz2lc | capability_blocked | Discovery context and Ghidra request limits |
| lbgdEe | capability_blocked | Planning interface mismatch |
| RfO2Re | capability_blocked | Repeated protocol/context failures |
| VdeOuw | capability_blocked | Planning revision copying failed |
| Hopgp4 | cancelled | Stopped for controller diagnosis |
| CjTfBE | cancelled | Partial budgets inherited excessive output reservation |
| jc8YUB | environment_unavailable | HTTP 429 was terminal before pause support |
| TWZ5M1 | partial | Response-contract repair exhausted |
| j8FQFw | cancelled | Stopped to repair conversation retention |
| 5TfIOM | partial after resume | Malformed action stranded the checkpoint; later JSON whitespace parsing failed |
| 7ZcWQY | capability_blocked | Repeated oversized evidence-page requests |
| gNReKM | environment_unavailable | Progressed through input/check analysis, then HTTP 429 |
| XFXUHX | environment_unavailable | Rate-limit resume succeeded; later inference timed out |
| kOszKX | partial | Reached validator reconstruction; repeated response truncation at 8,192 output tokens |
| i2MBy2 | independently graded static solve | Correct answer and algorithm; final native report remained partial due citation completeness |

## Completion demonstration

`i2MBy2` used the pinned DeepInfra endpoint, a 524,288-token context allowance,
16,384 output tokens, high reasoning effort, and a 48-generation ceiling. It used
19 reserved generations, 17 logged valid responses, and seven native actions:
XAIR inventory plus Ghidra functions, decompilation and assembly. Logged usage was
317,539 prompt tokens, 21,145 completion tokens and $0.02270868. Rejected or
rate-limited requests may add provider usage not present in these totals.

The model first saved the five required goals. It selected the input and validator
functions, switched from decompilation to assembly when control flow was obscured,
confirmed that the initial call leaves `0x4010e4` as the key base, and read the
37-byte table. It then declared a finite calculator program that reads the table
backward, derives the rotate from the rolling sum, subtracts the rotate and carry,
and XORs with `0xc7`. The calculator returned the correct printable candidate.
No operator-supplied prompt contained a function address, algorithm, decoder, or
answer.

The local `independent-grade.json` receipt beside the ignored run checkpoint pins
the artifact, official solution, encoded table, model answer, decoder result, and
forward re-encoding result. It reports `independently_graded:true` and
`behavior_executed:false`.

## Action-selection findings

The general policy permits a goal decomposition to serve as the initial queue,
then ranks model-declared tasks using priority and unresolved dependents. It
exposes exact available operations and bounded native previews. The latest trace
independently selected input and validation functions, switched from decompilation
to assembly and p-code, and used artifact-byte reads after native analysis
reservations ran out. This demonstrates tool selection and fallback behavior;
it does not yet demonstrate a correct solution.

Several failures were interface failures rather than evidence of weak reasoning:
malformed nested requests, stale copied plan revisions, discarded provider
reasoning blocks, legal leading JSON whitespace, and incompatible page sizes.
The corresponding fixes have deterministic regression coverage. Unknown provider
outcomes remain non-replayable; explicit HTTP 429 responses retain a restartable
checkpoint and honor the retry deadline.

Native time is conservatively reserved, not charged by actual elapsed work. Ten
60-second Ghidra reservations exhausted XFXUHX's ten-minute analysis
budget even though some warm operations completed sooner. Reads of saved evidence
and artifact bytes remain possible. New driver runs explicitly reserve up to one hour, and conversation retention
now scales with the pinned context allowance rather than eight exchanges. These
changes still need qualification on larger investigations; exhausting a reservation is not evidence that every
available analysis approach has been tried.

## Compression findings and limits

The original tiny working set was replaced with bounded persistent state and
pages. Prompt context includes recent exchanges and a compact queue; older
summaries, tasks, hypotheses, native values and turn records remain retrievable.
The recent conversation window retains complete provider reasoning messages;
truncating opaque blocks would violate the provider continuation contract.

Descriptor-only pages hid instruction text and forced extra retrievals. Scalar
projections now expose small primitive fields with explicit omission markers and
original pointers. Nested values and large fields still require another page.
The controller narrows requested page sizes to native bounds instead of repeatedly
rejecting otherwise valid queries. Neither projection nor a smaller prompt is
proof that all solution-critical semantics were retained.

Request-byte and provider-token measurements are recorded per valid generation.
The earlier 65,536-token and later 131,072-token profile runs changed other code
and provider settings as well; they cannot establish a lossless compression ratio
or a minimum reliable context size. A useful next experiment freezes the code,
artifact, provider, prompts and budgets, varying only the context/retention limit,
and grades answers independently over repeated attempts.

## Verification and reproduction

The Windows native suite passes 14/14 after the current changes (28.45 seconds).
Regression coverage includes
malformed-action recovery, rate-limit pause/resume, bounded scalar pages, a
checkpoint above the old 256 KiB ceiling, contradiction reopening, and recovery
of an already-completed native action after its reservation exhausts the budget.

Use the opt-in run and resume commands in [the controller guide](general-investigation.md).
`tools/summarize-investigations.py` produces local metrics without copying prompts
or credentials. `out/investigation-metrics-all.json` aggregates retained attempts.
Logged cost and token totals exclude usage unavailable from rejected or interrupted
responses. Report correctness, native proof status, independent grading, and
behavioral execution must be reported separately.
