# IndagoRev native static and runtime stages

The [deterministic knowledge workbench](docs/knowledge-workbench.md) adds behavior
contracts/hypotheses, dependency freshness, graph packets, coverage gaps, recognition,
derived artifacts, finite validators, resumable batches and portable evidence bundles.
It is native CLI/core functionality, not a model harness or execution sandbox.

The [native external-owner harness](docs/harness.md) now adds durable investigation
boards, single-owner leases, bounded static actions, recovery and citation-checked
reports. A [built-in local/OpenRouter loop](docs/builtin-harness.md) now supports
bounded native static investigations. A local LM Studio Qwen profile has completed
the [first static FLARE-On recovery demonstration](docs/flareon-end-to-end-2026-09-08.md).
Inference credentials and machine-local serving profiles are not shipped.

Stage 2 now includes the AIRECE native worker, directly linked XAIR semantic/CFG
queries, bounded XAIR_SYM queries, persistent Ghidra DecompInterface sessions,
and SQLite-backed jobs and evidence. See [static stage usage](docs/static-stage.md).
The executable is native. AIRECE, XAIR_SYM and Z3 are integrated into it;
Ghidra and its private OpenJDK are embedded when staged with `tools/bundle-ghidra.*`.
DbgEng and source-built DynamoRIO are embedded payloads, extracted into a private
hash-verified cache on use. See [engine integration](docs/runtime-engines.md).

[Managed static analysis](docs/managed-analysis.md) adds a bundled ILSpy/.NET
worker for bounded assembly inventory, types, methods, C# decompilation and IL
reference mappings. It does not execute target assemblies or require a system
.NET runtime. Managed metadata/IL locations remain separate from native addresses.

[Capability/string enrichment](docs/enrichment.md) integrates bundled upstream
capa and FLOSS workers, preserving their native reports and distinguishing
capability leads, file strings and emulated recovery sites.

[Native format metadata](docs/format-metadata.md) directly links LIEF's C++ library
for bounded PE/ELF metadata, byte-verified PE resource ranges and ELF notes.

[Offline network evidence](docs/offline-network.md) adds bundled Windows and Linux
Wireshark/TShark adapters for imported PCAP/PCAPNG, native stream groups and bounded
TCP reassembly/ACK frame links. It does not capture traffic or install a capture
driver. Dissector verdicts, source pointers and platform feature limits are retained.

Native Windows PE and Linux/WSL ELF debugging now supports x86/x64 launch/attach,
breakpoints, stepping, bounded captures/traces, persisted runtime observations,
and captured-state XAIR_SYM queries. See [runtime CLI usage](docs/runtime-stage.md).
Windows control uses DbgEng; `runtime instrument` provides bounded DynamoRIO
basic-block collection for PE/ELF x86/x64, separately from debugger stepping.
Execution is explicit and is **not sandboxed**. Bounded development qualification
is documented in [the qualification report](docs/bounded-qualification.md);
this is not production certification.

IndagoRev is a C17/C++20 project producing one primary executable: `indago`.
There is no Python application or runtime dependency in the platform core.
Optional [lossless payload compression](docs/payload-compression.md) reduces the
embedded worker footprint while preserving original files, hashes and tools.

The first non-GUI vertical slice provides:

- persistent projects and immutable SHA-256-addressed target artifacts;
- append-only target/evidence records and immutable analysis revisions;
- XAIR and XAIR_CFG linked directly into the executable;
- a native Ghidra adapter with a private persistent analysis engine and saved programs;
- one native CLI/service boundary for future GUI, SDK, and MCP frontends.

Backend outputs remain separate and retain their producer and completeness.
This prevents Ghidra and XAIR disagreements from being silently merged.

## Quick start

For clone setup, Git LFS build inputs, and preserved local data, see
[repository layout](docs/repository-layout.md). Initialize the pinned XAIR
checkouts with `pwsh tools/bootstrap-xair.ps1` before configuring a fresh clone.

```powershell
./tools/build-runtime-engines.ps1
cmake -S . -B out/build -G "Visual Studio 17 2022" -A x64
cmake --build out/build --config Release

out\build\Release\indago.exe --workspace .indago project create --name demo
out\build\Release\indago.exe --workspace .indago target import --project demo --file sample.exe
out\build\Release\indago.exe --workspace .indago analyze --project demo
```

Bundled builds need no installed Ghidra or Java. See the
[Ghidra workbench](docs/ghidra-workbench.md) for staging and new operations.
Development builds without a staged payload can use these environment variables:

- `INDAGO_GHIDRA_HEADLESS`: full path to `analyzeHeadless.bat`/`analyzeHeadless`;
- `GHIDRA_HOME`: a Ghidra installation directory.

`indago capabilities` reports compiled and external capabilities. XAIR is a
static library dependency of `indago.exe`, not a worker executable.

## Development

Runtime byte identity, capture-to-static feedback and bundled Frida recipes are
documented in [runtime feedback](docs/runtime-feedback.md).

The expanded static/dynamic CLI is documented in the
[runtime workbench](docs/runtime-workbench-progress.md), including bundled GDB,
watchpoints/stack inspection, child identities, effects telemetry, Frida attach,
multi-region captures and native selected-path witness experiments.

The [analysis-depth increment](docs/analysis-depth.md) adds module/transfer feedback
to the static index, completed-store write/execute evidence, and Ghidra unwind,
TLS and virtual-dispatch recovery.

The checked-out repositories under `xair/` remain independent upstream
components. `config/toolchain.lock.json` records the composition seen by this
prototype and marks it unqualified until the development-plan pin discrepancy
is reconciled and clean cross-platform tests are recorded.

## Ghidra native-core boundary

The [autonomy roadmap](docs/autonomy-roadmap.md) tracks remaining harness/lab,
network-debugging and behavioral-validation work, with bounded low-storage testing
and static-only handling of the local FLARE-On archive.

Ghidra's transformation and C-printing engine is native C++ and exposes a
`libdecomp` build. Ghidra's normal decompilation pipeline, however, supplies the
native engine with loader bytes, symbols, types, context, and p-code through its
Java program database and private process protocol. Linking `libdecomp` alone
does not reproduce Ghidra PE/ELF analysis.

The first implementation therefore keeps Ghidra behind a native C++ adapter and
uses the supported headless pipeline. Direct `libdecomp` integration remains a
separate backend experiment requiring a native loader/program-database bridge.
