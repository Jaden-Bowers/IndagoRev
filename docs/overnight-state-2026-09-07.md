# Overnight/continued-run wrap-up — 2026-09-07

## Verified product state

Native C/C++ Windows and Linux CLI builds remain available in
`out/build/Release/indago.exe` and `out/linux/indago`. They include the prior
static/dynamic foundation and the verified enrichment, network, evidence and
compression increments below. They **predate the latest rr adapter source**.

- Static: integrated AIRECE/XAIR/CFG/SYM, persistent bundled Ghidra, indexed
  native evidence and backend-specific semantics. Added bounded managed ILSpy
  inventory/decompilation/IL references, capa capability leads, FLOSS string
  recovery and native LIEF executable metadata/resources.
- Dynamic: existing DbgEng/GDB sessions, Frida/DynamoRIO instrumentation,
  capture/reanalysis and runtime identity/evidence. Frida network observations
  now preserve socket generations, native API outcomes and bounded byte windows.
- Offline network: bundled Windows and source-built Linux TShark decode
  PCAP/PCAPNG, retain native JSON/bytes and timestamps, and index packet/stream
  membership plus native TCP reassembly references. No live capture or host
  traffic interception was added.
- Harness: scoped multi-component investigations, durable proposals and
  publication receipts, bounded reads, explicitly granted mutations/derived
  artifacts, killable workbench children, finite validators, counterexample-led
  revision and citation-freshness audits. Offline/model-mock checks passed;
  live inference remains unconfigured.
- Evidence: publication completeness is distinct from native verdict and
  projection completeness. Failed retries cannot replace analysis heads or
  poison later address-layout interpretation; reindex preserves this behavior.
- Footprint: stable generated files, independent content-addressed tool-group
  caches and verified lossless Zstd payload packing. No tool was removed.

## Size and focused verification

Current Windows executable: 1,159,504,384 bytes (about 1.08 GiB).
Current Linux executable: 1,239,105,480 bytes (about 1.15 GiB).
Embedded worker storage savings: 436,538,256 bytes Windows and 545,937,838 bytes
Linux. Expanded worker bytes are identical; old caches were not deleted.
C: free-space snapshot at wrap-up: about 37.2 GiB, above the 20 GiB floor.

Latest compressed-build regression: Windows native 4/4, Linux
knowledge/model/harness 3/3; both platforms' payload inventory, offline packet
and Frida checks pass. Additional native reassembly checks pass. See
`out/compressed-payload-*-checks.log`, `docs/payload-compression.md`,
`docs/offline-network.md`, `docs/managed-analysis.md`, `docs/enrichment.md`
and `docs/format-metadata.md` for exact scopes and earlier checks.
These are bounded development checks, not comprehensive production qualification.
No unknown challenge/malware binary was executed. FLARE-On was catalogued
read-only with bounded hashing; no bulk archive extraction or challenge solve run.

## Last work: rr, explicitly unfinished at product level

Built pinned rr 5.9.0 from source with static non-system dependencies and both
x86/x64 helpers. The native rr binary requires only libc/libm/the ELF loader.
A narrow, documented glibc 2.43 header compatibility fix retains the upstream ABI
assertion. Native Linux temporary scratch fixes the observed failure of rr shared
memory on a Windows-mounted temporary directory; traces persist in the project.

Both source-built fixture probes passed record → pack → autopilot replay:
`out/rr-source-x64-probe.log` and `out/rr-source-x86-probe.log`, each trace around
3 MiB. No kernel policy changes or CPU overrides were used.

Initial `runtime record/replay` source now uses existing session/observation and
cancellation infrastructure, fixed upstream operations, bounded output, disk/file
guards and hashed packed-trace manifests. Linux enabled-branch adapter and CLI
syntax checks pass. `out/rr-trace-manifest-check.log` verifies stable identity,
mutation detection, size limits and symbolic/hard-link/directory refusal.

Still required before advertising rr through the product: stage the source-built
payload with reconciled dependency notices, rebuild the main binaries, and exercise
real CLI record/replay, cancellation, timeout, partial output, tampering and crash
recovery. The adapter is not interactive reverse debugging. Polling disk guards
are not OS aggregate quotas; existing descendant cancellation is not a hostile
process containment boundary. Current shipped binaries do not expose this work.

## Major remaining autonomy gaps

1. Real disposable-lab allocation/reset/attestation; system manifests and static
   preflight exist, but declarations alone do not authorize safe hostile execution.
2. Lab-bound reproducible multi-process/system experiments, fuller IPC identity,
   independent verification and broader environment/coverage handling.
3. Finish rr product integration and later bounded reverse-debugging controls.
4. Network stream-derived artifacts and lab-bound API/packet correlation; optional
   controlled capture/replay requires the lab, not ambient host traffic access.
5. Deeper targeted symbolic/runtime-code recovery and managed dependency handling.
6. Selected whole-system/kernel profiles and demonstrated-need PANDA, DRAKVUF,
   Triton or Intel PT integration. These are not implemented by the rr work.
7. Release source/license/SBOM closure, broad qualification and the deferred GUI.

The result is a substantially more capable CLI workbench with an offline-tested
harness, not guaranteed fully automatic analysis of arbitrary programs/systems.
