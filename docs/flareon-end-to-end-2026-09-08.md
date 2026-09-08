# FLARE-On end-to-end harness demonstration — 2026-09-08

This iteration closes the first end-to-end FLARE-On milestone for the native
built-in harness. It does not close the full archive or general autonomous-RE
goals in `kb/IndagoRev_Final_Development_Plan.md`.

## Result

The harness solved FLARE-On 2014 challenge 3, `such_evil`, using the local
LM Studio model `huihui-qwen3.8-27b-abliterated` (IQ3_S) and the pinned structured
profile `dd05ec9d457264c598c1b973fc4c83f963faedd1cd2c706e6598008d1eee215e`.
The imported target SHA-256 was
`4ab2023b2f34c8c49ffd15a051b46b6be13cb84775142ec85403a08c0d846c72`.

The successful run is preserved at `out/flareon-solve-success/summary.json`, with
a compact extract at `out/flareon-solve-success/proof.json`. The run completed in
51.870 seconds with 13 native actions and two model generations. It returned:

- status: `answered`
- answer: `BrokenByte`
- reasoning state: `verified_solve: true`
- decoder stages: 5
- target execution: disabled

The controller first collected a verified XAIR inventory, analyzed the native
entry `0x4024c0`, ranked the bounded call frontier, and followed application
callee `0x401000`. It then loaded the complete hash-pinned Ghidra decompilation
field internally and reconstructed the 513 initialized local bytes. The bounded
decoder recognized and replayed these nested XOR stages:

| Stage | Output offset | Bytes | Key hex |
|---:|---:|---:|---|
| 1 | 33 | 479 | `66` |
| 2 | 116 | 396 | `6e6f7061736175727573` |
| 3 | 200 | 312 | `624f6c47` |
| 4 | 298 | 214 | `6f6d6720697320697420616c6d6f7374206f7665723f213f` |
| 5 | 399 | 113 | `6161616161616e642069276d207370656e74` |

The final decoded code constructs a printable stack argument. The recovery
record extracted `BrokenByte`. Qwen then selected that exact value with reasoning
operation `solution`, naming recovery `recoveries_1` at revision 1. The native
validator compared the selection to the recovered argument and published
`solutions_2` as `verified_static_output`. Qwen's next decision was
`finish {solved:true}`; only that verified state allowed an answered report.

## Harness changes

- Reasoning state now persists recovery and solution records alongside
  obligations, hypotheses, candidates, experiments, and audit history.
- The controller selects the verified entry automatically for the named
  challenge-answer workflow and follows a bounded application callee when entry
  recovery yields no answer. Function workflow identity is tied to the pinned
  artifact and address rather than the model generation number.
- The initialized-x86 recovery recognizes byte, DWORD, and stack-key XOR loops,
  including computed end bounds and loop-local key-pointer resets. Every stage is
  bounded to the reconstructed byte array and recorded with offsets, sizes, keys,
  and before/after hashes.
- Solution publication requires an exact model-selected answer match. The report
  gate accepts a current hash-pinned recovery source even when unrelated auxiliary
  collections in the enclosing native result were paginated; the complete source
  field is reloaded and verified from immutable evidence before recovery.
- Post-recovery context is reduced to the recovery record, reasoning revision,
  and required next action so it fits the conservative local-model byte ceiling.
- The live driver has a `solve` mode that requires `answered`, the recovered
  answer, at least one decoder stage, and `verified_solve: true`.

## Verification

- Live LM Studio solve: passed, `out/flareon-solve-success/summary.json`.
- Windows Release test suite: 14/14 passed in 166.10 seconds.
- Linux native rebuild: passed, `out/flareon-solve-linux-build.log`.
- Linux bounded `model_tests`, `harness_tests`, and `model_http_tests`: 3/3
  passed with 60-second per-test caps,
  `out/flareon-solve-linux-tests.log` and
  `out/qualification-linux-native/checks.cDCM3g/`.
- Synthetic regressions cover a single immediate XOR decoder and a nested
  stack-key decoder with a computed bound and nearer loop-local key reset.

## Scope that remains open

This proves one static output-recovery challenge under one pinned local model
profile. The recognizer intentionally covers a bounded family of initialized x86
XOR decoder stubs. It is not a general emulator, unpacker, or acceptance-input
solver. Input-to-comparison tracing, runtime experiment dispatch, retry/revision
orchestration, disposable execution profiles for unknown targets, broader
decoder families, private-target evaluation, and the complete FLARE-On catalogue
remain roadmap work.
