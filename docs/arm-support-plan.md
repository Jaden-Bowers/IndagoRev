# macOS ARM64 integration plan

Status: the first useful GUI milestone is implemented in `macBuild/` and tested
on the development Apple Silicon Mac on 2026-10-20. The wider core integration,
runtime and symbolic roadmap below remains proposed.
Scope updated to reflect the user's decisions: the ARM edition is built for
macOS only and handles ARM programs; the separately developed x64 edition handles
x64 programs. Linux and Windows ARM builds are deferred.

## Delivered first milestone

The [macBuild application](../macBuild/README.md) imports real ARM64/arm64e
Mach-O programs (including a selected `.app`'s main executable), runs pinned
native Ghidra, and shows functions, assembly,
pseudocode and evidence in both existing GUI layouts. Notes and immutable analysis
reports persist across reopening. Analysis runs off the UI thread and supports
cancellation; the selected program is never executed.

This first slice uses a small independent file-based project store and a dedicated
CMake build. It reuses the GUI and JSON library without building the x86 analysis
stack. It is not a port of the complete root CLI, SQLite store or capability
contract. A minimal Mach-O validator selects supported slices; broader LIEF
metadata and exact pseudocode-line mappings remain later work. AI responses and
decompiler edits remain unavailable in live mode.

Ghidra 12.0.3 already ships a native macOS ARM64 decompiler, so this pinned release
does not need a separate native-helper build. `macBuild/setup.sh` verifies Ghidra
and the matching ARM64 JDK archives before staging them in ignored `out/`.

Validation completed: both new CTest suites passed with real Ghidra analysis;
all eight original GUI suites passed; a native Cocoa/Metal run completed 195
frames and loaded three fixture functions. Tests cover both layouts, notes,
reopening evidence, invalid inputs, universal slices, missing tools and
cancellation. This qualifies the tested development workflow, not older macOS
versions, a standalone signed distribution, or runtime/symbolic parity.

## Recommended direction

Keep the existing GUI, command interface, evidence store, and tools wherever they
can be built for ARM. Add platform adapters and target-aware routing around them.
Use Ghidra for the first real analysis workflow on Apple Silicon, then introduce
native debugging and tracing. Evaluate Triton separately for ARM symbolic work.

The ARM edition runs natively on Apple Silicon Macs and analyzes ARM programs. It needs
ARM decoding, register handling, calling conventions, and semantics. Static x86/x64
analysis, x64 execution workers, and x64 compatibility/emulation are outside this
edition's scope. The existing x64 edition continues to develop independently.

Keep the editions as separate build/capability profiles in the shared codebase
initially. Share architecture-independent GUI, storage and request code while
selecting architecture-specific analysis tools at build time. Separate editions
do not require duplicating the entire application or creating a second repository.
The ARM build must not depend on compiling or packaging the x86-only analysis stack.

Start with 64-bit, little-endian ARM (AArch64, also called ARM64) on macOS.
The current roadmap includes one host platform, one desktop window backend
(Cocoa/Metal), and one native debugger adapter (LLDB). Linux/Windows ARM builds,
ARM32/Thumb, Android/iOS device control, ARM64EC mixed-code binaries, and kernel
debugging are deferred.

The first useful milestone is: **open a real ARM64 Mach-O program on a Mac,
view its functions, assembly and pseudocode in either existing layout, and retain
notes and evidence.** Native execution is limited to supported macOS ARM64 programs.
Building for macOS does not inherently prevent static inspection of ARM64 ELF/PE
files, but those formats are optional later static-analysis extensions, not initial
acceptance requirements. They must not be launched as native macOS programs.

## What the repository actually needs

| Location | Current assumption | Required change |
|---|---|---|
| [GUI build](../gui/CMakeLists.txt), [Mac entry point](../gui/main_macos.mm), [Windows entry point](../gui/main.cpp) | Cocoa/Metal already renders the shared mock GUI. Live Windows integration uses Windows process APIs. | Keep both layouts and Cocoa/Metal. Extract a small shared data-provider boundary and add a macOS CLI launcher. |
| [Root build](../CMakeLists.txt), [presets](../CMakePresets.json) | Windows uses x64; non-Windows dependencies and runtime compilation assume Linux. Some symbolic tests require XAIR even when it is disabled. | Separate Windows, Linux and macOS branches; select sources and tests by enabled capabilities and actual CPU architecture. |
| [Payload packaging](../cmake/BundledEngines.cmake), [LIEF packaging](../cmake/IntegratedLief.cmake) | Non-Windows becomes Linux; Ghidra native paths are x86_64; DynamoRIO packaging expects both x86 bitnesses. | Key packages by OS and CPU, validate their executable architecture, and require only the helpers promised by that profile. |
| [XAIR](../xair/XAIR/README.md), [query adapter](../src/xair_query.cpp), [symbolic adapter](../src/runtime_symbolic.cpp) | XAIR lifts x86 instructions; register/flag handling is x86-specific. | Keep the existing stack in the x64 edition. Exclude it from the ARM build and route ARM operations to Ghidra and, once qualified, Triton. |
| [Runtime image reader](../src/runtime_image.cpp) | Accepts only x86/x64 PE and ELF. Mach-O is absent. | Add explicit architecture recognition and Mach-O metadata, preferably through LIEF for the new format. |
| [GDB adapter](../src/runtime_gdb.cpp), [runtime orchestration](../src/runtime.cpp) | Uses `/proc`, Linux `pipe2`, an x86 boolean, and `eip`/`rip` selection. | Keep Linux-specific process inspection in Linux code. Use explicit architecture/register descriptions; add a macOS debugger adapter. |
| [Capture reanalysis](../src/runtime_capture.cpp), [input solving](../src/runtime_input_solver.cpp) | Captured code is wrapped as x86 ELF; comparison solving lifts x86 caller instructions. | Carry the target architecture through captures, image generation, solver dispatch and witness validation. |
| [Unicorn worker](../workers/emulation/CMakeLists.txt), [worker code](../workers/emulation/main.cpp) | Builds only x86 and opens `UC_ARCH_X86`. | Select the ARM64 engine for the ARM edition, with architecture-specific register initialization and explicit request routing. Keep the x86 engine in the x64 edition. |
| [DynamoRIO build](../workers/dynamorio/CMakeLists.txt), [collector](../workers/dynamorio/client.c) | Pointer width selects X86_64; effect collection uses x86 store classification and 15-byte decoding assumptions. | Exclude this collector from the macOS ARM package; use Frida/Stalker for supported ARM observations. |
| [Frida build](../workers/frida/CMakeLists.txt), [recipes](../workers/frida/recipes.js) | Non-Windows links Linux libraries/options; comparison capture recognizes x86/x64 only. | Add macOS linking and ARM devkits, then port each recipe's ABI/register/OS assumptions. |
| [ILSpy worker](../workers/ilspy/Indago.Ilspy.Worker.csproj) | Publishes only `win-x64` and `linux-x64`. | Publish/test `osx-arm64`; distinguish static decompilation from OS-dependent tracing. |
| [Guest manager](../src/guest.cpp), [guest documentation](qemu-guests.md) | Linux-only, bounded x86 boot disks, fixed machine and GDB architecture. | Exclude the existing x86 guest profile from the ARM edition. ARM guest provisioning is deferred and is not required for this plan. |

The present [capability contract](current-capabilities.md) defines x64 native/full
profiles. It must not report an ARM profile as equivalent just because its tools
are installed. Availability, supported target, and tested operation are distinct.

## Tool choices

These are integration recommendations. Upstream support does not establish that
IndagoRev's pinned version, worker, package, or result conversion works on ARM.

| Function | Existing tool | ARM recommendation and limits |
|---|---|---|
| Decompilation, functions, CFG, assembly, cross-references | Ghidra and AIRECE/XAIR | **Use Ghidra for ARM.** Build its native components for macOS ARM64 and stage a matching JDK. Upstream explicitly documents that build. Keep AIRECE in the x64 edition; preserve Ghidra's own evidence and operation meanings in the ARM edition. [Ghidra platform and native build guide](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md#building-native-components). |
| Lightweight ARM instruction decoding | No separate ARM frontend | **Use Ghidra assembly initially; add Capstone only for a measured need**, such as decoding a captured byte range without a Ghidra session. Capstone supports ARM64, but does not replace XAIR's SSA, full instruction semantics or symbolic analysis. [Capstone features](https://www.capstone-engine.org/). |
| ARM symbolic execution and taint | XAIR_SYM with Z3 | **Evaluate Triton's C++ API in a bounded worker.** It supports AArch64 semantics, symbolic execution, taint and Z3. Start with captured blocks. This is an alternate backend, not a compatible replacement for XAIR result structures or whole-program reasoning. [Triton](https://github.com/JonathanSalwan/Triton), [instruction coverage](https://triton-library.github.io/documentation/doxygen/SMT_aarch64_Semantics_Supported_page.html). |
| Native macOS debugging | No Mac adapter | **Add LLDB through its public C++ SB API.** Reuse the existing `RuntimeBackend` interface for launch, breakpoints, registers, memory, stepping and detach. LLDB documents macOS AArch64 support. [LLDB platform/API support](https://lldb.llvm.org/). |
| API hooks and executed-block tracing | Frida, DynamoRIO | **Use Frida + Stalker on macOS ARM64.** Stalker has an AArch64 implementation. Port recipes and compare event meaning; Frida hooks alone are not a replacement for executed-block events. DynamoRIO integration is outside this macOS plan. [Stalker](https://frida.re/docs/stalker/). |
| Bounded CPU emulation | Unicorn | **Keep Unicorn and enable ARM64.** Supply captured registers/memory and stop at unsupported calls, instructions or limits. It emulates CPU instructions, not a Windows/Linux/macOS installation. [Unicorn architectures](https://www.unicorn-engine.org/). |
| File headers, sections, imports | LIEF | **Keep LIEF; extend the adapter to Mach-O and universal-file slices.** The library already supports PE, ELF and Mach-O, but IndagoRev's worker currently accepts only PE/ELF. [LIEF formats](https://lief.re/), [Mach-O API](https://lief.re/doc/latest/formats/macho/index.html). |
| Managed code | ILSpy worker + .NET | **Rebuild the existing worker** for `osx-arm64`. Verify every native dependency and managed trace feature separately. The runtime identifier describes the worker's host, not the assembly's CPU requirements. [Microsoft RID catalog](https://learn.microsoft.com/en-us/dotnet/core/rid-catalog). |
| Capability rules and decoded strings | capa, FLOSS | **Include only operations qualified for ARM targets.** capa documents ARM64 host binaries, which does not prove ARM instruction/rule coverage in the currently fixed Vivisect extractor. Test FLOSS static strings separately from stack/tight/decoded modes. For unsupported ARM decoding, offer Ghidra strings and explicit bounded Unicorn experiments as narrower capabilities, not equivalent FLOSS results. [capa ARM host releases](https://mandiant.github.io/capa/), [current extractor policy](enrichment.md). |
| Offline packet analysis | TShark | **Keep TShark and package its macOS ARM dependencies.** Packet interpretation is not tied to the analyzed program's CPU. Qualify the macOS distribution and bundled libraries. [Wireshark downloads](https://www.wireshark.org/download.html). |
| Native process record/replay | rr on Linux | **Leave deterministic replay unavailable in the initial macOS edition.** rr requires Linux; ordinary tracing and persisted captures do not provide equivalent replay. No replacement is selected in this plan. [rr requirements](https://github.com/rr-debugger/rr#system-requirements). |

SQLite, JSON contracts, zstd, Z3, and the ordinary C++ application logic should
remain. Rebuild native dependencies for the host architecture and test them;
replacing the solver does not supply missing ARM instruction semantics.

Source links may describe newer development versions than the repository pins.
Select a stable version, record its source revision/archive hash and matching
JDK/SDK dependencies, and verify it before changing any pin. In particular, do
not blindly adopt the JDK version from Ghidra's development-branch documentation.
Ghidra's [AArch64 language definitions](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/AARCH64/data/languages/AARCH64.ldefs)
also describe target variants and instruction-coverage limits; supporting an ARM
host does not establish coverage of every ARM target extension.

## Expected macOS capabilities

This table describes the wider intended capabilities. The delivered subset is
recorded above; the remaining rows do not imply available support.

| Workflow | macOS ARM64 implementation |
|---|---|
| Existing GUI layouts | Keep Cocoa/Metal and both layouts; add live data |
| Static ARM64 analysis | Ghidra + LIEF; thin Mach-O and ARM64 slices of universal binaries first |
| Native ARM64 debugging | New LLDB adapter for supported macOS processes |
| ARM64 instrumentation | Frida/Stalker, with each recipe qualified on macOS |
| ARM64 symbolic/taint | Bounded Triton prototype |
| Record/replay | Unavailable in the initial profile |

Parity means comparable analysis workflows for ARM programs: navigation,
decompilation, annotations, debugging, tracing and supported symbolic operations.
It does not require identical engine output or executing the x64 edition's targets.
An unavailable ARM capability must remain explicit rather than falling back to an
x64 worker. No remote-execution transport or QEMU guest integration is required.

## Keep the integration small

Reuse the current CLI/JSON worker boundaries and
[`RuntimeBackend`](../include/indago/runtime.hpp). Avoid a generic plugin system
or a rewrite of the GUI. Introduce only the following shared concepts initially:

1. **Host description:** OS and CPU of the running IndagoRev process, plus the
   execution location. Do not infer ISA from pointer size; ARM64 and x64 are both
   64-bit. Verify that the ARM package and its helpers are native ARM64 builds.
2. **Target description:** binary format, ISA, address width, endianness, ABI and
   selected slice. Normalize `aarch64`/`arm64` at adapter boundaries. Shared
   contracts retain x86/x64 values for the x64 edition and historical evidence,
   but ARM analysis requests must reject unsupported target architectures.
3. **Operation support:** backend, operation, supported host/target combinations,
   enabled/available state, and a reason when unavailable. GUI buttons and AI
   action validation must consult the same capability result.
4. **Register description:** explicit PC/SP/flags aliases and typed register
   widths. ARM64 has `pc`, `sp`, `x0`–`x30`, and `w` aliases; it must not fall
   through to `rip`. Preserve raw debugger names and unavailable register state.
5. **Evidence identity:** include backend/version, target description, bytes,
   module/slice identity and execution location. Keep static addresses, file
   offsets and runtime addresses distinct. Preserve existing hashes rather than
   rewriting historical records to add fields.

Use a small host-platform module for executable paths, child processes,
cancellation and dependency discovery. Keep Linux `/proc` behavior in Linux
adapters. On macOS, use the appropriate system APIs and debugger module inventory.
Audit page-size assumptions: several collectors use 4096-byte constants, while
the host or target may use a different size. File-format alignment and OS page
size must not be treated as the same property.

Mach-O universal binaries need a selected architecture slice recorded alongside
the original file hash, slice offset/size, and derived-byte identity. Select the
ARM64 slice; reject files without a supported ARM slice. Include the selected
slice in decompiler cache keys. Preserve ASLR slide and module UUID information
for static/runtime navigation.

Keep analysis-engine calls off the UI thread. A live provider should return the
same small view models used by the existing panels, with explicit loading,
failure, cancellation, partial-result and unsupported states. Retain a selectable
mock provider for development and the current headless GUI tests.

## Implementation sequence and acceptance checks

Each numbered increment should be independently reviewable. Larger increments
can be split by feature. Follow the existing preference for meaningful, commented
code and small commits. For this milestone, commit each complete functional slice
once it exceeds roughly 200 meaningful lines; do not pad changes or split a
working feature merely to reach a line count.

### 1. Describe host, target and capabilities

Add the shared descriptions and routing tests. Extend
[`src/service.cpp`](../src/service.cpp), runtime capabilities, and
[`tools/capability-matrix.cjs`](../tools/capability-matrix.cjs) without claiming new
support. Update strict JSON schema enums only when their backend is implemented.

Acceptance: unknown architectures never become x64; ARM64/x64 have different
identities despite equal pointer width; ARM requests reject x86/x64 targets before
analysis or execution; installed-but-incompatible tools return an explicit
unsupported result. Existing x64 requests remain valid in the x64 edition.

### 2. Build a native ARM core with optional tools

Add a proposed `macos-arm64-core` preset with dedicated build and payload
directories. Make runtime sources conditional and provide explicit
unavailable operations until each adapter exists. Fix optional-XAIR test linkage,
non-Windows Linux assumptions, OpenSSL discovery, and payload architecture checks.
Keep current x64 presets. Disable XAIR/AIRECE/Zydis in the ARM profile and remove
unconditional dependencies on their headers, symbols and test targets from that
build. Do not remove their implementation from the x64 edition. Stage Z3 for the
ARM symbolic worker independently of the existing XAIR_SYM build when needed.

Acceptance: a native ARM executable reports capabilities, creates a project,
imports bytes, and persists/reopens evidence. A clean build does not pick up an
x64 SDK or a developer's unrelated payload directory. Core tests run on an Apple
Silicon Mac; compiling them on another platform is not the acceptance gate.

### 3. Deliver real static analysis on the Mac

Build/stage Ghidra native helpers and a matching ARM JDK. Reuse the existing Java
worker for functions, assembly, decompilation, tokens and annotations. Extend
LIEF/image metadata for ARM64 thin/universal Mach-O. Static ARM requests
use the ARM profile's backends, with no XAIR dependency or x86 fallback.

Acceptance: known functions, calls, data references and address mappings are
recovered from source-built macOS ARM64 Mach-O fixtures. Importing/decompiling never launches the
sample. Truncated headers and invalid slice bounds fail clearly. Cached results
remain separate by artifact, slice, backend and revision. Include x64-only files
as rejection tests and universal files as ARM-slice selection tests.

### 4. Connect the current GUI to the portable core

Extract the minimal provider and process-launch code from the Windows live path.
Connect real project/function/code/evidence data to the shared workbench and
keep both standard and compare layouts. Retain the mock console and add explicit
live analysis commands; mock output must remain visibly identified as mock.
Recheck AI source references and revision identity before enabling live chat
actions. A platform/backend swap must not silently mix stale pane contents.

Acceptance: navigate a real fixture in both layouts, switch views without losing
selection/notes, cancel a slow query, and surface a missing backend. Extend the
existing GUI tests with delayed/error/partial live-provider responses. Run a
native window smoke check as well as headless tests.

### 5. Add native macOS ARM64 debugging

Implement `src/runtime_lldb.cpp` against the existing runtime interface for
macOS. Choose a pinned LLVM SDK for packaging; use a configured local SDK for
development rather than assuming every machine has the same Xcode path. Preserve
the single-owner debugger-thread model. Compile the LLDB adapter for this profile
and leave GDB/DbgEng with their existing editions. Use macOS process and module
discovery instead of carrying over Linux `/proc` assumptions.

Acceptance on macOS: launch a source-built fixture, resolve ASLR, break, read
registers/memory, step, capture, continue, detach and cancel. Test attach denial
as an explicit diagnostic. The application must remain responsive while waiting
for the debugger. Unsupported register/PAC/vector state stays explicit; missing
state cannot be represented as known zeroes.

### 6. Add ARM64 instrumentation and emulation

Stage matching Frida devkits and add an executed-block Stalker recipe. Normalize
thread/module events and address links to the existing observation contract.
Port argument capture to the macOS ARM64 ABI; hooks for similarly named Unix
functions still need macOS checks. Add ARM64 Unicorn requests and register mappings.
Defer memory effects until ARM
load/store, conditional/exclusive writes and page-size behavior are tested.

Acceptance: a fixture executes a known branch and loop; observe expected blocks
and call arguments, preserve event caps/partial status, and cancel cleanly.
Unicorn reproduces known integer and memory results from supplied state and stops
at missing memory, external calls and instruction/time limits. Tracing is not
reported as deterministic replay or full taint analysis.

### 7. Prototype ARM symbolic analysis before promising parity

Add a separate optional Triton worker using its C++ API and a pinned compatible
Capstone/Z3 combination. A separate process avoids introducing conflicting Z3
versions into the existing executable. Feed persisted captured bytes/registers/
memory, then implement one branch predicate and one taint example first. Return
backend-specific evidence; do not manufacture XAIR expressions or verdicts.

Acceptance: validate arithmetic, flags, `w`/`x` aliasing, branches and memory
loads/stores against native fixtures and Unicorn. Reject unsupported semantics
or mark the bounded result partial. Re-run a proposed input in the appropriate
execution environment before labeling it verified. PAC/BTI, SIMD/SVE, atomics,
OS calls and missing captured state each need explicit coverage decisions.

If this prototype passes, expand bounded branch/slice/taint coverage incrementally.
If it fails, keep ARM symbolic operations unavailable while investigating an
ARM-capable alternative. A later ARM frontend for XAIR could
preserve more of its internal behavior, but that is a separate semantics project.

### 8. Qualify auxiliary features for ARM

Publish the managed worker for `osx-arm64`, stage macOS TShark, and qualify capa/FLOSS per
operation and target. Split their availability flags if one worker is missing.
Keep deterministic replay explicitly unavailable. Keep optional failures out
of the minimal static-analysis build's dependency requirements.

Acceptance: managed decompilation and offline packet fixtures retain the expected
normalized facts on the supported Macs. Managed execution, when enabled, uses a
compatible macOS ARM runtime. Unsupported enrichment is visible and never falls back
to x64 execution. The ARM package contains only its selected dependencies.

### 9. Qualify macOS ARM64 profiles

Maintain fixtures for supported macOS ARM64 targets. Where useful, compile the same
fixture source for the x64 edition and compare stable facts and semantics using
each edition on its own supported platform, not exact decompiler text.
Require tests for import, address mapping, annotations, captures, cancellation,
invalid inputs and unsupported architecture/OS rejection. Run existing x64
regressions separately when shared code changes. Measure startup, first decompile,
cached navigation, tracing throughput and memory on the actual supported devices.

Choose and document the minimum supported macOS version during the build prototype;
test that version and the development Mac's version before qualifying a package.
Publish a capability report for each tested macOS/CPU/backend version. Define
separate static and runtime profiles rather than weakening the existing x64
`full` profile. Verify fresh-machine startup, packaged helper architectures,
dynamic-library resolution and required macOS signing before calling a bundle
ready. Keep generated binaries, SDK staging and test output under ignored `out/`.

## Original first development task and next integration work

The original core-first sequence was to implement increments 1 and 2 in small
slices, starting with host/target identity
and capability routing tests. Then make one native Mac CLI import-and-capabilities
workflow. The delivered `macBuild/` slice instead completes the first useful GUI
milestone with independent import, capabilities and evidence storage. Full root
service integration remains open. Preserve the current visual design and live
console while connecting those wider services; avoid replacing every analysis
engine at once.

The original review inspected source/build configuration and upstream
documentation. Subsequent implementation installed the pinned Ghidra/JDK tools
and tested the native static GUI workflow described above. It did not build the
full ARM core, execute analyzed programs, or verify runtime/symbolic parity.
Those remain explicit acceptance gates for later milestones.
