# Qwen six-change investigation ablation

## Implementation

The Pi frontend now has independently selectable changes:

| Feature | Behavior |
| --- | --- |
| environment | Resolve and probe Java, 7-Zip and Python before inference; expose exact paths and the Node strings helper; retain versions and executable hashes privately. |
| surface | Direct strings, archive listing/member extraction and Java bytecode inspection; native decompile/functions/xrefs visible for native-looking filenames. |
| state | Replace automatic receipt replay with bounded artifact-specific facts, candidate, obligation and failures. Reset on active-artifact change. |
| progress | Block a third unchanged inspection even when earlier executions succeeded; retain repeated-output warnings. Helper edits invalidate the repeat counter. |
| final | Remove tool definitions on the reserved synthesis turn; reject textual tool markup as a final response; preserve unresolved candidate/obligation and permit bounded repair. |
| recipes | On-demand wrapper, JAR and escaped/indexed-data instructions with tested literal-decoding examples. |

Complete raw tool receipts remain available on disk. Compact state is explicitly
model-authored, not automatically verified evidence. `remember` and native
knowledge remain available on demand. Neither these changes nor the generic
shell tools constitute a host sandbox.

## Evaluation design

Run `node agent/ablate.mjs PREPARED_JSON NEW_OUTPUT_DIRECTORY` using a prepared
local-Qwen development selection. The runner rejects remote-provider trials.
It copies only the original hash-checked challenge inputs, never prior solutions,
derived artifacts, scripts or conversations. The frontend fingerprint is checked
before every trial. Output directories must be fresh.

Eight arms use the same four cases: previous enhanced baseline with no feature
switches, each of the six changes alone, and their combination. Each trial has
16 model generations and at most nine minutes; trials run sequentially against
the local model. This is a single-run diagnostic ablation, not a robust estimate
of solve probability or a production qualification gate. Paths and backend
timing can still affect otherwise temperature-zero model trajectories.

Review actual final answers and supporting traces. `has_final_response` is not
solve verification. An unresolved report is a valid final response but not a
correct answer; textual tool syntax is neither. Do not count a candidate appearing
only inside a helper or tool output as a submitted solve.

## Checks

Offline and real-Pi/mock-provider checks cover feature isolation, plain-reference
behavior, byte-located strings, PHP literal semantics, bounded artifact-scoped
state, repeated successful calls, repair of malformed final responses, native
dispatch and shell deadlines. A separate extraction smoke check used the existing
archive engine to recover an embedded executable without launching the target.

Live results are retained in the run's `prepared.json`, `metrics.json`, per-trial
sessions, environment manifests and raw observations. Machine metrics are left
ungraded; reviewed correctness must be reported separately.

## Follow-up revision

The first frozen 32-trial run exposed a recipe dependency: its extraction and JAR
instructions assumed the optional direct interface was enabled. The follow-up
adds ordinary 7-Zip/javap CLI alternatives and a generic PNG trailing-data helper.
The helper walks chunk framing rather than searching for an IEND byte substring;
it rejects truncated framing, bounds input/chunk count, writes new files only,
and records parent hash, offset and child hash. CRC and pixel validity are
explicitly not certified. Synthetic tests include an IEND string inside chunk
data and malformed lengths, with no challenge-specific answer material.

The changed recipe and combined arms are rerun from fresh case directories, then
plain Pi is rerun as a reference. Earlier recipe/combined results remain retained
as first-version results rather than being silently replaced. All other individual
feature implementations are unchanged. Interpret differences cautiously: each arm
has one run per case, the host is not snapshotted, and generated shell scratch files
outside the fresh case directory are not a controlled isolation boundary.

## Completed results

All 52 local-Qwen trials completed: 32 original ablations, 12 follow-up trials,
and eight final environment/combined retests. No remote-model inference was used.
The final revision explicitly explains Windows executable versus Git Bash paths
and recommends case-relative helper paths. Times below sum four solver trials,
excluding environment preparation. Tokens are input plus output, not unique
context bytes. Correctness means reviewed submitted answers, not independent
challenge certification or runtime acceptance.

| Revision / arm | Correct / 4 | Seconds | Input tokens | Output tokens |
| --- | ---: | ---: | ---: | ---: |
| Original baseline | 1 | 668 | 504293 | 13003 |
| Original environment | 2 | 484 | 465231 | 8314 |
| Original direct surface | 2 | 542 | 414156 | 9696 |
| Original compact state | 2 | 388 | 383797 | 8593 |
| Original progress guard | 2 | 570 | 463640 | 9515 |
| Original final handling | 1 | 987 | 673780 | 18102 |
| Original recipes | 1 | 628 | 467675 | 12307 |
| Original combined | 2 | 532 | 400040 | 10122 |
| Follow-up recipes | 2 | 872 | 567198 | 13910 |
| Follow-up combined | 2 | 459 | 635201 | 6157 |
| Fresh plain Pi reference | 2 | 486 | 562518 | 9881 |
| Final environment | 2 | 562 | 413290 | 12029 |
| Final combined | 2 | 518 | 550729 | 10725 |

The final combined arm matched plain Pi at two correct answers, took about 6.7%
longer, and used about 1.9% fewer total tokens. This is not an established overall
improvement. Compact state alone was the strongest observed efficiency result
(388 seconds, 392390 total tokens), but one trial per case on an unsnapshotted
host is insufficient to establish a repeatable causal gain.

Both the final combined arm and plain Pi submitted correct answers for the Java
invitation validator and the source-available frog challenge. Neither solved the
2014 executable wrapper or HTML/PNG challenge. The final combined Java answer
identified the correct constant but reversed the explanation of the conditional
jump in one bullet: correct answers do not imply entirely correct explanations.

The final combined wrapper run spent its budget on shell/PE resource inspection
and ended with textual tool markup. The HTML/PNG run followed pixel analysis and
submitted an unsupported branding email, which was rejected during review. It did
not use the supplied trailing-data recipe to finish the embedded PHP analysis.
No new solve of either difficult case was demonstrated.

Direct bytecode inspection was used successfully on the Java case. Recipe and
tool availability did not ensure their selection on difficult cases. The exact
repeat guard passed controlled checks but did not trigger in its live standalone
arm; varied unproductive commands remain a gap. Final-response validation rejects
tool markup, but cannot guarantee that Qwen produces valid synthesis: the final
combined arm still had one malformed ending. These are reporting/enforcement
improvements, not evidence that every reasoning failure has been fixed.

Private run evidence is retained under `out/qwen-six-change-ablation-v3`,
`out/qwen-six-change-followup`, and `out/qwen-six-change-final`, including metrics,
review files, sessions and frontend fingerprints. Interrupted exploratory starts
are excluded. Follow-ups remain separately reported rather than replacing less
favorable earlier results.
