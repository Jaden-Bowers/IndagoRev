# IndagoRev

A native C17/C++20 reverse-engineering CLI for x86/x64 PE and ELF files.

IndagoRev combines static analysis, explicit runtime analysis, persistent evidence,
and a model-assisted investigation harness. XAIR, XAIR_CFG, XAIR_SYM, and AIRECE
are linked into the native executable. Backend evidence stays separate; a
recovered string is not automatically a verified solve.

**Development software. Target execution is not sandboxed.**

## Clone and build

Install Git, CMake 3.25+, Python 3 (Z3's **build-time** generator), and a C/C++
compiler. Install Git LFS if you also want the vendored Frida development libraries.

```sh
git clone --recurse-submodules https://github.com/Jaden-Bowers/IndagoRev.git
cd IndagoRev
```

Already cloned? Run `git submodule update --init --recursive`.
The first configure fetches the pinned Z3 source; subsequent builds use its cache.
No hand-applied patches or machine-local SDK paths are needed for these presets.

### Windows x64

Install Visual Studio 2022 or Build Tools with **Desktop development with C++**
and a Windows SDK. Run from PowerShell:

```powershell
cmake --preset windows-native
cmake --build --preset windows-native
.\out\native-Windows\Release\indago.exe version
```

### Linux x86-64 / WSL

On Ubuntu 24.04, install the native build prerequisites:

```sh
sudo apt-get update
sudo apt-get install build-essential cmake ninja-build python3 git libssl-dev pkg-config
cmake --preset linux-native
cmake --build --preset linux-native
./out/native-Linux/indago version
```

Allow several minutes and a few GiB for the first Z3/native build. Reduce
parallelism with `cmake --build --preset linux-native --parallel 2` if needed.

## Try it

Use the executable path above in place of `indago`:

```sh
indago --workspace .indago project create --name demo
indago --workspace .indago target import --project demo --file sample.exe
indago --workspace .indago analyze --project demo --backend xair
indago capabilities
indago runtime capabilities
```

The native presets build the static engines, evidence store, CLI, and harness.
They deliberately do not pick up locally staged tool bundles. Windows also
embeds the checked-in DbgEng payload. Ghidra/JDK, Linux GDB, DynamoRIO, Frida,
ILSpy, capa/FLOSS, LIEF, and TShark require the
[documented engine staging steps](docs/building.md); they have not been removed.
Inference is optional and requires your own configured provider.

## Documentation

- [Build profiles and dependencies](docs/building.md)
- [Static analysis](docs/static-stage.md) · [Runtime analysis](docs/runtime-stage.md)
- [Harness](docs/harness.md) · [Built-in model loop](docs/builtin-harness.md)
- [Proof boundaries](docs/solve-verification.md) · [Benchmark](docs/flare-on-benchmark.md)
- [Repository layout](docs/repository-layout.md) · [Development plan](kb/IndagoRev_Final_Development_Plan.md)

## License

IndagoRev's authored code is [MIT licensed](LICENSE). Vendored and bundled
components retain their own licenses and redistribution requirements.
See the license and provenance files under [vendor](vendor) and
[components](components). CMake generates `THIRD_PARTY_NOTICES.md` in the build
directory for the linked analysis engines.
