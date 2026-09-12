# Building IndagoRev

The [README](../README.md) contains the supported fresh-clone native build commands.
The `windows-native` and `linux-native` presets require no private tool staging.
They compile XAIR, XAIR_CFG, XAIR_SYM, integrated AIRECE, Z3, SQLite, and zstd.
Python is used to generate Z3 sources during the build, not to run IndagoRev.
The first configure needs network access to fetch the pinned Z3 commit.

## Dependencies and checkout

Initialize the three pinned Git submodules with `git submodule update --init --recursive`.
Do not use `--remote`: the parent commit records the tested engine revisions.
The historical patches in `components/patches` are already incorporated in those
revisions. They must not be applied again. See [repository layout](repository-layout.md).

Windows requires Visual Studio 2022 C++ tools and a Windows SDK. Linux requires
a C++20 compiler, Ninja, Python 3, and OpenSSL development/static libraries plus
pkg-config. Ubuntu prerequisites are listed in the README. Build on WSL's Linux
filesystem for better performance. The native presets disable test executables
and cap compilation parallelism at four jobs; override with `--parallel 2` on
memory-constrained machines.

## Optional embedded tool bundles

The minimal native executable is not the complete development bundle. Missing
engines are reported by `capabilities` and `runtime capabilities`; they are not
silently supplied by a fresh clone. Windows native builds include the checked-in
DbgEng distribution. Linux native builds explicitly allow GDB to be unstaged.

To build a richer bundle, follow the relevant staging instructions first:

- [Runtime engines](runtime-engines.md): GDB, DynamoRIO, Frida, and replay.
- [Ghidra workbench](ghidra-workbench.md): stage a Ghidra distribution and JDK.
- [Managed analysis](managed-analysis.md): ILSpy and its self-contained runtime.
- [Enrichment](enrichment.md): capa and FLOSS.
- [Format metadata](format-metadata.md): optional static LIEF SDK.
- [Offline network analysis](offline-network.md): TShark.

Frida's two development libraries use Git LFS. Install Git LFS and run
`git lfs pull` before building its worker. Other tracked source snapshots retain
upstream licenses; Ghidra, JDKs, generated workers, and SDK staging remain outside
Git. These advanced staging scripts have platform-specific prerequisites; inspect
their documented paths before running them on a different machine.

Use a separate build directory after staging, for example:

```sh
cmake -S . -B out/full -DCMAKE_BUILD_TYPE=Release -DINDAGO_BUILD_TESTS=OFF
cmake --build out/full --config Release --parallel 4
```

That configuration discovers the platform's `out/runtime-payload` and `out/lief-sdk`
staging directories. Unlike the native preset, the default Linux configuration
requires staged GDB. `INDAGO_BUNDLE_PROFILE` controls payload trimming, not which
engines are installed. Do not assume all engines are present: inspect capabilities
on the finished executable. The native presets deliberately use empty dedicated
staging paths so local development payloads cannot mask clone/build defects.

## Native clone smoke check

Run the native presets locally from recursively initialized checkouts without
optional SDK staging. GitHub Actions workflows are not enabled during early
development. `tests/native_clone_smoke.ps1 -Executable PATH` (PowerShell
7) checks CLI startup, import, XAIR inventory/CFG/semantics, and persisted AIRECE
evidence. It uses the pinned engine's synthetic control-flow PE and never executes
the target. The fixture intentionally contains unresolved flow: partial native
verdicts are expected, not promoted to complete analysis. This is a build smoke
check, not full engine or challenge qualification.

## Local data

Build outputs, investigation workspaces, model credentials, and the FLARE-On corpus
are ignored. None is required to compile. Do not use `git clean -fdx` to clean a
working installation: it would remove those local assets.
