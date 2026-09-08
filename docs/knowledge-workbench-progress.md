# Knowledge workbench implementation ledger

Scope: eight CLI/core workstreams requested after the analysis-depth increment.
No model harness, GUI, new lab/backend integrations or production qualification.

1. Implemented: revisioned behavior, hypothesis, question, summary, assumption and
   product records with explicit assertions, scope, dependencies and counterevidence.
2. Implemented: transitive freshness/impact, optimistic updates and conservative
   Ghidra Program-revision invalidation. Stale never silently becomes false.
3. Implemented: directional bounded graph neighborhoods, evidence packets,
   disagreement preservation, native function membership and runtime-event packets.
4. Implemented: bounded gap reports with backend counts, unresolved relationships,
   semantic limitations and observer-scope reminders. No completeness percentage.
5. Implemented: runtime/compiler marker and symbol-family hints plus caller-owned
   exact byte-range signatures. No general library fingerprint database.
6. Implemented: native slice/XOR/hex/base64 transformations, immutable derived
   artifacts, method/assumption records and byte-range mappings.
7. Implemented: generic product records and deterministic finite byte/transform
   validators with counterexamples. No arbitrary helper execution or automatic
   algorithm/protocol synthesis; these can later use the same records.
8. Implemented: normalized read-analysis DAG batches, budgets, leased recovery,
   explicit retries/cancellation, portable evidence bundles, recoverable retention,
   storage leases, schema 5, workbench schema/capabilities/error categories and
   conservative runtime packaging profile.

Focused static checks will use the documented synthetic corpus at
`C:/Users/Jaden/Desktop/Projects/IR/xair/tests/corpus/phase3`.
Those files are analysis inputs, not host-execution samples.

## Focused results

- Windows native knowledge tests passed, including an interrupted reservation
  resumed without duplicate work or double charging at the budget ceiling.
- Existing core contracts and static-model checks passed.
- Windows and Linux CLI workflows passed against all five documented IR PE64
  fixtures; inventory, CFG, batches/resume and graph/coverage checks produced evidence.
- Linux also passed transformations, validators, recognition, dependency freshness,
  bundle export/import and retention planning through the CLI.
- Windows runtime observation dependencies, event packets and raw-telemetry/evidence
  export/import passed using the benign generated-code fixture.
- Existing Ghidra PE exception/TLS/dispatch checks and generated-code
  write/execute/reanalysis checks passed with the runtime packaging profile.
- Runtime profile removed 14,205,599 embedded payload bytes on Windows and
  14,130,449 on Linux. Full profile remains selectable; source archives/notices,
  compiler and platform-native runtime files are retained.

See [usage, contracts and limitations](knowledge-workbench.md). GUI, harness,
extensive qualification, disposable labs, additional analysis engines, kernel
profiles and general symbolic/deobfuscation research remain separate workstreams.
