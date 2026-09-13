# Current capability contract

This is the current status entry point. Dated records describe their own increments,
not every later build. `indago capabilities` reports the executable actually used;
availability is not correctness, host compatibility or challenge qualification.

| Profile | Required capabilities | Not promised |
|---|---|---|
| `windows-native`, `linux-native` | Linked AIRECE/XAIR/CFG/SYM, knowledge store, CLI and harness; Windows DbgEng | Optional engine bundles |
| `windows-full`, `linux-full` | Core plus bundled Ghidra/JDK, ILSpy, capa/FLOSS, TShark, Frida, DynamoRIO, emulation worker and LIEF; Linux private GDB | Host-compatible rr, QEMU, helper prerequisites or inference configuration |

Full profiles require prior staging. Configuration rejects missing engine
directories/LIEF; build completion checks executable capabilities and writes
`capabilities.full.json` with the executable hash and no local file paths.
Staging checks and functional smoke tests remain necessary. Node is a build/check
tool, not the application runtime. See [building](building.md).

## Implemented scope

- Static queries, separate Ghidra/XAIR views, indexed revisions and lineage.
- Single-owner built-in/external harness, bounded actions and typed proof gates.
- Explicit trusted-host debugger/instrumentation experiments and capture/reanalysis.
- Linux contained generated helpers, finite algorithm reconstruction and revisions.
- Managed/artifact parsing, CoreCLR observation, offline packets and service contracts.
- Selected Linux QEMU boot-disk profiles, not general guest OS provisioning.
- Failure records, reproductions, matched comparisons and reviewed recipes.

See [autonomy status](autonomy-expansion-status.md) and
[verification](autonomy-5-8-verification.md) for measured limits. Host execution is
not sandboxed. Windows generated helpers fail closed. System manifests declare
dependencies and bind static scope; they are not a general execution provider.
JSON is supported; protobuf is not implemented.

## Remaining gates

General protection recovery, complete protocol experiments, catalogue adapters,
disposable OS provisioning, independently graded corpus performance, hostile-input
qualification and redistribution qualification remain open. The frozen catalogue
has 116 entries; 2025 stays held out. Fixture passes are not challenge solves.

Use repository-relative documentation paths. Evidence in `out/` is local and not
shipped. Run `node tools/check-doc-portability.cjs` before publication. Public
reports must omit credentials, home directories and raw local logs.
