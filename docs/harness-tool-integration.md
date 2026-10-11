# Harness tool integration

The Pi frontend now calls existing native operations through a typed registry.
The C/C++ core, backend semantics and native proof gates remain authoritative.
No debugger, instruction semantics, symbolic executor or emulator was replaced.

## Contract

| Surface | Integration |
|---|---|
| Static analysis | Named Ghidra, AIRECE, XAIR/CFG/SYM, ILSpy, capa/FLOSS, LIEF and Wireshark calls |
| Evidence and knowledge | Project/artifact-bound queries, distinct function views, indexed entities/relations/claims, paged results |
| Runtime | Explicit session calls for DbgEng/GDB, Frida, DynamoRIO, input solving, capture/reanalysis and supported Linux rr |
| Workbench | Typed transforms, validation, graph queries, system manifests, batches and explicitly granted administration |
| Controlled workflows | External-owner native helpers, experiments, algorithm reconstruction, service contracts and granted QEMU guests |
| Proof reasoning | Revision-checked native reasoning updates; no independent grading authority |

Common artifact-specific tools are available immediately. Specialized discovery
activates at most twelve additional registry tools; it does not dump every schema
or replay historical logs. The on-demand [field guide](../agent/tool-recipes.md)
describes when to use each workflow and its limits. Ordinary coding tools remain.

Inputs reject unknown transport fields and apply operation-specific bounds.
Runtime calls require explicit session identities. GUI locations are checked
against hashes and native revisions. Generic compatibility adapters use the same
dispatch grants. Host shells remain unrestricted host access, not a sandbox.

Results retain complete native receipts and bounded JSON previews. Native
pagination and adapter result paging are distinct. Backend-native verdicts and
partial/unknown outcomes remain visible. Ownership tokens are not model arguments
and are redacted from receipts. Interrupted mutations retain pending identities;
an uncertain operation is not silently retried.

Native runtime/workbench transport schemas are snapshotted for portable packages.
`generate-tool-contracts.mjs --check` detects contract drift. `tool-audit.mjs`
compares the configured executable with the registry and rejects unmapped
advertised analysis/runtime/workbench/read operations. Lifecycle operations are
classified as controller-managed or operator-only instead of granting the model
arbitrary controller ownership, independent grading or installation privileges.

## Validation record — 2026-10-14

- Full Windows native executable rebuilt; capability manifest passed.
- Final serialized agent suite: **49/49 passed**, including real Pi SDK and
  native runtime/workflow integration. Native version/capability smoke: **2/2**.
- Registry audit: **194 registered tools**, **180 advertised operation rows**,
  **zero unmapped**. This counts mappings, not qualified engine/environment support.
- Real native integration exercised artifact transformation and byte reads,
  finite calculation, external ownership, helper capability reads, reasoning
  reads, bounded I/O and a two-case controller-owned experiment.
- Negative tests cover unknown fields, authority escalation through compatibility
  calls, stale/ambiguous GUI references, altered target files, interrupted outcomes,
  and owner-token redaction.
- Two short SDK tests timed out during concurrent execution and passed with their
  original deadlines when serialized. The default agent test command now
  serializes SDK tests to avoid competing environment/startup probes.

Local Qwen (`huihui-qwen3.8-27b-abliterated`, 23,552-token loaded context) smoke runs:

| Synthetic task | Calls | Generations | Session elapsed | Outcome |
|---|---|---:|---:|---|
| Native control-flow fixture | `xair_inventory`, `xair_cfg`, `decompile` | 4 | 85.4 s | All calls succeeded; final answer cited native evidence |
| Original I/O fixture comparison | `tools_search`, `experiment_run`, `read`, `investigation_update` | 5 | 56.7 s | Both inputs produced the observed `NO` output; model did not claim acceptance/solve |

These are usability smoke tests, not a challenge benchmark, causal-equivalence
proof, or measurement of reasoning improvement. The static response still needs
human scrutiny of its cross-backend interpretation. The runtime response's use
of “isolated processes” must not be read as sandbox isolation: these were trusted
host executions. No remote model was used. Loopback mock-provider protocol tests
are separate from these live Qwen runs.

## Deliberate limits

Controlled helper execution requires supported Linux confinement prerequisites;
Windows-native helper execution remains fail-closed. rr needs a supported Linux
environment. QEMU profiles must be provisioned and granted by an operator.
The registry does not install missing engines, emulate unsupported platforms,
qualify all backend operations, or certify FLARE-On coverage. Benchmark grading,
environment provisioning and builtin-model inference remain operator-side.

See the [agent README](../agent/README.md) for flags, profile configuration,
audit commands, evidence paging and recovery procedures.
