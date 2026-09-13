# Autonomy additions 5–8: bounded verification record

Verified locally September 12–13, 2026. Implementation scope is documented in
[reconstruction/services/evaluation](reconstruction-services-evaluation.md) and
[QEMU guests](qemu-guests.md). No archive challenge was executed, no guest OS was
downloaded, and the 2014–2024 catalogue/2025 holdout were unchanged.

| Gate | Result | Local evidence |
|---|---|---|
| Reconstruction, immutable revisions, counterexamples, forged/mismatched receipt rejection, dependency staleness, service provenance/falsification, evaluation tampering/confounds, recipe export | Passed | `out/research-workflow-sUuXjN/summary.json` |
| QEMU KVM lifecycle, checkpoint/restore, GDB registers, cold reset, selected TCG record/replay | Passed | `out/guest-lifecycle-JogLIY/summary.json` |
| Optional bundled QEMU, denied/granted harness execution and exported artifact lineage | Passed | `out/guest-harness-jVkG9Z/summary.json` |
| Scoped read-only fw_cfg input transfer, attempted guest write, denied unadmitted input | Passed | `out/guest-transfer-4cQDdD/summary.json` |
| Forced controller interruption, deadline reconciliation and owned staging pruning | Passed | `out/guest-interruption-2JF8lz/summary.json` |
| Windows/Linux builds | Passed | `out/task89-final-guest-windows-build.log`; Linux cache `out/task89-final-guest-build.log` |
| Windows controller/workbench | 2/2 passed | `out/task89-delivery-windows-tests.log` |
| Linux controller/workbench | 2/2 passed | Linux cache `out/task89-delivery-tests.log` |
| Linux helper regression | 18 actions passed | Linux cache `out/task89-helper-tests.log` |
| Original-target experiment regressions | Windows/Linux passed | Linux cache `out/task89-experiment-tests.log`; Windows native fixture invocation |
| Capability-to-challenge matrix | 116 rows; explicitly incomplete filename-derived requirement assessment | `out/task89-capability-matrix.json` |

The Linux cache is `<INDAGO_BUILD_CACHE>/clone-build-check-20260911`.
Each test/worker was bounded well below ten minutes. The optional distribution
QEMU staging payload is approximately 61 MiB, not a multi-OS image collection.
Pruning tests removed only generated guest overlays/staging; receipts remain.
Those removed temporary binary outputs are not recoverable through Indago.

## Live local model comparisons

Model: `huihui-qwen3.8-27b-abliterated`, existing LM Studio configuration. These
used the external-owner harness API; they are not a claim of a separate Linux
provider connection or a full unattended challenge solve. One generation per
variant, matching declared model/settings/seed/budget, same development fixture.

| Exposed feature | Without | With | Evidence |
|---|---|---|---|
| Native helper diagnostic | Agreement | Agreement | `out/research-live-v8aaae/summary.json` |
| Generated discriminating inputs | Agreement | Failed helper | `out/research-live-nVaYwF/summary.json` |
| Retained counterexample context | Agreement | Failed helper | `out/research-live-MqXSGr/summary.json` |
| Reviewed validated recipe | Agreement | Agreement | `out/research-live-lH92aW/summary.json` |

All successful outcomes are native agreement on the model-selected input, not
universal equivalence or independently graded solves. Both failed variants
repeated an invalid bytes-XOR expression. Their source, request, model response,
diagnostics and outcomes are retained. Extra context did not uniformly help this
model in these pairs. No superiority, held-out transfer or causal conclusion is
claimed from this small development measurement.

The diagnostics pair predates the configurable runner's larger action ceiling;
its two variants share the same eight-action ceiling. Subsequent pairs each share
a twelve-action ceiling. They are separate matched pairs, not one pooled causal
comparison with identical budgets across all four features.
