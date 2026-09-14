# Context engineering revision

Implemented for the next matched benchmark:

- Request manifests record section sizes, hashes, duplicate content, selected tool
  schemas and actual reasoning controls. Token estimates are characters/4, not
  provider usage. Headers and source content are not stored in these manifests.
- A persistent bounded working index stores observations, failed attempts and
  hypotheses by artifact. `investigation_focus` selects a concrete question.
  Lexical retrieval ranks local evidence and suppresses already visible text;
  `knowledge_search` also queries the existing native store. Native assertion
  freshness is refreshed when selected. Complete receipts remain on disk.
- Recent tool history is no longer re-injected wholesale. Older large tool
  results receive bounded head/tail views retaining diagnostics. Small source
  reads remain complete. This is conservative text compaction, not a semantic
  proof or universal code slicer.
- `analysis_tools` reveals optional tools; `graph_context` traverses the existing
  native graph with two-hop, 24-node and 16-KiB bounds. It retains backend-native
  relationship semantics. No second graph is extracted by an LLM.
- Concise artifact-specific investigation guidance covers source, JVM, native
  wrappers, decoder stages and helper debugging. It contains no challenge answers.
- Enhanced modes bound ordinary shell commands to 30 seconds by default and at
  most 120 seconds, block a third unchanged failed call, and reserve the last
  generation for an answer or unresolved blocker. Write/edit actions invalidate
  the repeat cache. Runtime experiments are exempt from failed-call blocking.
- All modes allow at most two response-length continuations within the existing
  generation/deadline budgets. OpenRouter requests explicitly disable reasoning.
  Actual provider compliance must be checked in live usage; historical DeepSeek
  runs emitted reasoning despite the old launcher setting.

The working index retains up to 512 records and retrieves at most five. Larger
investigations can query the native evidence store and graph explicitly. Embeddings
and corpus-wide graph summaries remain conditional on demonstrated lexical-search
failures; neither is required to rerun this benchmark.

Evaluation: prepare fresh Qwen and DeepSeek directories after every frontend change.
Historical results are preserved. Compare completion, supported answers, request
size, repeats, helper latency, provider reasoning and length stops. A faster run
with equal accuracy is an improvement; extra time or tokens with equal accuracy
is a regression. These fresh runs also change provider reasoning control, so they
must not be described as isolating memory alone. All three modes still use the
same per-model inference budgets. Fine-grained component ablations remain useful
after this readiness gate.
