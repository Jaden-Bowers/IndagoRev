# Component boundaries

The directories below are independent Git repositories and are intentionally
ignored by the parent integration repository:

- `xair/AIRECE` (original reference only; no longer used by the build)
- `xair/XAIR`
- `xair/XAIR_CFG`
- `xair/XAIR_SYM`
- `ghidra` (source checkout; not a compiled distribution)

Do not run a broad parent `git add` that flattens their contents. The parent
records observed and expected revisions in `config/toolchain.lock.json` until a
deliberate submodule or manifest-based dependency workflow is selected.

The owned AIRECE implementation is integrated under `components/airece` and
compiled with XAIR_SYM and static Z3 into the native IndagoRev executable.
The C++ adapter launches an internal mode of that same binary to retain process
cancellation; there is no Python adapter or separate AIRECE executable.
Zydis is vendored under `vendor/zydis` with its license notices.
The Ghidra adapter launches `analyzeHeadless` and maintains a persistent
DecompInterface session through `workers/ghidra/scripts`.
