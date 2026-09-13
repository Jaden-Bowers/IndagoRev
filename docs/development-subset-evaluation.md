# Diverse development subset

Selection: [subset manifest](../config/flare-on-development-subset.v1.json), from
the unchanged 116-entry frozen catalogue. This is an intentionally small,
static-first diagnostic set, not representative archive difficulty or a held-out
benchmark. No 2025 material is accessed.

| Challenge | Selection basis |
|---|---|
| 2014 C1 | Native PE entry |
| 2014 C2 | Web source and companion resource |
| 2018 C1 | JVM archive requiring container/bytecode handling |
| 2024 frog | Python game source and assets |

The runner verifies preparation receipts, hashes every imported component, scopes
companions and allows four derived artifacts. No challenge execution, shell,
generated helper execution, remote inference or solution lookup is granted.
Consequently this measures the Windows static investigation profile, not the
complete Linux helper/dynamic capability ceiling.

Use the full Windows build and a local model already served through LM Studio:

```text
node tools/evaluate-local-subset.cjs EXE CORPUS_ROOT SEVEN_ZIP config/flare-on-development-subset.v1.json EXACT_LOCAL_MODEL
node tools/summarize-subset.cjs RUN_DIRECTORY PUBLIC_SUMMARY.json
```

Each final-profile investigation has at most sixteen generations, 32 native actions,
nine minutes of native reservation and a 30-second generation limit. The outer
per-challenge deadline is 570 seconds, with at most ten more seconds for cancellation.
Model sampling is temperature zero; no exact seed,
weights hash or server version is attested. Each run starts with fresh state.
The same generic objective contains no answers, addresses or algorithm hints.

Raw reports remain under ignored `out/`, including native revisions, controller
decisions, errors and model usage. The public summarizer excludes answer text,
local paths and owner leases. A budget-exhaustion message in `report.answer` is
explicitly not counted as an answer. Candidate reports require separate grading.
No authoritative external answer oracles were supplied for this subset; no
independent solve-rate claim is made from citation audits or report status.

## Preliminary runs retained

The first preparation attempt exposed a runner path-resolution error before any
model inference. The corrected path handling uses the exact native receipt rather
than assuming extraction-directory layout.

An initial eight-generation run scoped only primary entries and lacked derived
artifact permission. It is retained as an integration diagnostic, not the final
profile. The subsequent profile expands scope and budget together; differences
are not a matched causal measurement of either change alone.

## September 13 static-profile result

The answer-free combined record is
[`evaluation-subset.corrected-v1.json`](../config/evaluation-subset.corrected-v1.json).
It selects attempt one for the unaffected native/JVM cases and attempt two for the
web/Python cases rerun after fixing primary-target normalization. All four retained
runs used the same final declared model, generation/action/time budget, fresh state
and static-only authority. Target execution remained disabled.

| Challenge | Attempt | Terminal status | Generations | Native actions | Elapsed |
|---|---:|---|---:|---:|---:|
| 2014 C1 | 1 | `capability_blocked` | 12 | 5 | 182.659 s |
| 2014 C2 | 2 | `budget_exhausted` | 16 | 3 | 224.665 s |
| 2018 C1 | 1 | `budget_exhausted` | 16 | 5 | 199.686 s |
| 2024 frog | 2 | `budget_exhausted` | 16 | 4 | 239.133 s |

Result: **zero answered reports from four attempted challenges**. Because there
were no candidate submissions, no challenge answer oracle was invoked. This is a
measured answer-production result, not an independently graded solve-rate estimate,
archive qualification or proof that none is solvable with other profiles/models.
No solution material was consulted and no candidate answer is committed.

Observed failure categories:

- 2014 C1 reached useful Ghidra decompilation, then repeated the same partial
  function query until the progress guard stopped it.
- 2014 C2 ignored artifact routing, tried incompatible binary analyzers and paged
  raw HTML without reconstructing its logic.
- 2018 C1 did not extract and analyze the class in the JAR; it tried incompatible
  loaders and raw container paging.
- 2024 frog, correctly bound to `frog.py` after the fix, still tried four binary
  analyzers and exhausted raw-source pages without producing the transformation.

Every run's first planning response omitted a required task summary and spent one
repair generation. The failures demonstrate controller/model interaction gaps in
format-directed routing, container/source access, partial-result strategy changes
and compact source reconstruction. They do not indicate missing raw source bytes.
The full raw reports remain local and ignored.

The original final-profile web/Python records are also preserved in
[`evaluation-subset.static-v1.json`](../config/evaluation-subset.static-v1.json).
The public summarizer identified their omitted-selector requests being rebound to
later companion imports. A red/green controller regression now binds omitted
selectors to the investigation primary before standalone service normalization.
[`evaluation-subset.binding-followup.json`](../config/evaluation-subset.binding-followup.json)
contains the two corrected reruns and reports no binding mismatch.
