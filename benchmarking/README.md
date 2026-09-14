# Development benchmark

This directory contains the exact four challenge input sets used for the current
Qwen comparison, a SHA-256 manifest, and all 52 completed trial metrics. It is a
small development sample, not representative all-FLARE-On qualification. No 2025
challenges are included. Results and answers must not be supplied to the model.

## Inputs and provenance

- `flare-2014-01`: executable wrapper, `C1.exe`.
- `flare-2014-02`: HTML and companion PNG.
- `flare-2018-01`: Java invitation-validator JAR.
- `flare-2024-frog`: Python game source, assets and companion executable.

Inputs came from the local copy of the
[FLARE-On challenge archive](https://github.com/fareedfauzi/Flare-On-Challenges).
The local archive checkout was at `7103e44c3f6aafae6f94549ea3e0990c15e2f2ff`;
the manifest hashes identify the actual tested bytes.
They are third-party FLARE-On/FireEye/Mandiant challenge material, not IndagoRev
source, and are not relicensed under IndagoRev's MIT license. Original included
notices, including the font license, are preserved. No blanket upstream license
for the challenge collection has been established here.

Treat executables and scripts as untrusted. Inclusion is not a safety assessment.
Do not run them merely to inspect this benchmark. These trials prohibited target
execution but permitted generated analysis helpers. Pi shell access is not a
sandbox; use an appropriately isolated host for untrusted work.

## Reproduce

Build the native CLI using the root README, install the pinned `agent/`
dependencies, and serve the manifest's Qwen model in LM Studio on localhost port
1234. Install the tools needed by the cases (Java JDK, 7-Zip and Python). Then:

```text
node benchmarking/prepare.mjs PATH_TO_INDAGO out/benchmark-plan
node agent/ablate.mjs out/benchmark-plan/prepared.json out/benchmark-ablation
```

The prepare command only checks inputs and writes a local plan. The ablation
command runs eight arms (32 trials), copying original inputs to fresh case
directories. Every trial is capped at 16 generations and nine minutes. Do not
give the model this repository as its investigation directory: the results are
public development material and would contaminate answer-blind evaluation.
Prompt-level restrictions do not enforce filesystem isolation.

## Results

See [the full report](../docs/qwen-six-change-ablation.md) and `results.json`.
The final combined arm and plain Pi both submitted two correct answers out of
four. Combined took 518 seconds and 561454 total tokens; plain Pi took 486
seconds and 572399 tokens. Neither 2014 case was solved. All 24 frontend tests
passed after the changes.

Metrics preserve each run's frontend fingerprint and distinguish the original
32-trial ablation, 12-trial follow-up, and eight final retests. Reviewed correct
answers are not independently certified solves. Raw sessions, credentials,
machine paths, generated helpers and private investigation state are excluded.
One run per case and an unsnapshotted host do not establish statistical causality.
