# IndagoRev for macOS ARM64

This is the first live analysis milestone for Apple Silicon. It uses the existing
Dear ImGui standard and compare layouts with real Ghidra analysis. The separate
x64 application and its analysis engines remain in the original build.

## Run the application

Double-click **Run ARM GUI.command** in this folder. It sets up the pinned tools,
builds the app, and opens it. You need Apple's Command Line Tools and CMake.
The first setup downloads approximately 680 MB of official Ghidra/JDK archives;
later launches reuse them. Nothing is installed into system directories.

In the application:

1. Click **Open app or ARM64 file...** and select an application such as
   `/System/Applications/Books.app`, or an ARM64 executable/dynamic library.
   Select the `.app` itself; there is no need to browse its package contents.
   Opening a new file starts static analysis automatically.
2. Select a function to see its pseudocode and ARM assembly.
3. Click **Compare layout** to place those panes side by side. **Stacked layout**
   returns to the original view without resetting the selected function.
4. Open **notes.md**, edit your notes and click **Save notes**. Saved notes and
   evidence return when you reopen the same file or restart the application.
5. Use **Analyze again** to refresh results, or **Cancel analysis** to stop the
   tool. Previous successful evidence remains readable after a failed/cancelled run.

The selected program is never executed. The app launches only the analysis tools.
AI replies and decompiler edits are explicitly unavailable in this milestone.
**Add reference** captures real pseudocode for navigation, without generating a
scripted explanation. Assembly navigation identifies the containing function;
exact pseudocode-line mappings are not claimed.

For `.app` inputs, the importer reads `Contents/Info.plist` and uses its
`CFBundleExecutable` entry to find the main executable in `Contents/MacOS`.
Both XML and binary property lists work, including renamed application bundles.
The project records the application name and executable path. It snapshots the
main executable only; bundled frameworks, helpers and resources are not analyzed
as part of that import. Opening the executable directly and then its bundle
retains the same project, notes and evidence.

Books was checked on the development Mac: its universal executable has baseline
arm64e and arm64e.x1 slices. The importer selected baseline arm64e, and Ghidra
returned assembly and pseudocode for 256 functions. That run hit the 60-second
analysis and 256-function export limits, so the GUI explicitly reports partial
results. This is useful static inspection, not a complete reconstruction of Books
or a guarantee that every Objective-C/Swift construct decompiles correctly.

## Build and test from Terminal

Run these commands from the repository root:

```sh
bash macBuild/setup.sh
cmake -S macBuild -B out/macBuild/build -DCMAKE_BUILD_TYPE=Release
cmake --build out/macBuild/build --parallel 4
ctest --test-dir out/macBuild/build --output-on-failure
open out/macBuild/build/IndagoRev-ARM64.app
```

The build also produces `out/macBuild/build/mac-analysis-fixture`, a small ARM64
Mach-O program compiled from [tests/fixture.c](tests/fixture.c). Select that file
in the app to explore a known XOR decoder without needing your own sample.

The live test runs Ghidra on that compiled fixture and exercises actual ImGui
panels without a GPU. It checks the two layouts, real pseudocode/assembly,
navigation, reference retention, persistent notes, missing tools, cancellation,
timeouts, corrupt evidence, and universal-file validation. The project test
checks import, input identity and storage. The original mock GUI tests still run
from their original `gui` build.

The large-file suite imports and analyzes a 320 MiB padded ARM64 fixture, reopens
its saved project, checks large universal containers, and detects corruption past
the old 64 MiB boundary. A sparse FAT64 fixture also checks offsets above 4 GiB.
These cases validate file handling; padding a small program does not simulate
the analysis complexity of a large production application.

The bundle suite covers XML/binary plists, renamed applications, missing or
malformed metadata, internal/external symlinks, saved notes, and deterministic
arm64/arm64e slice selection. Real Books analysis is a manual integration check;
the automated tests do not depend on which system applications are installed.

For a native window/rendering smoke check, launch the executable with
`--smoke-test --workspace ABSOLUTE_TEST_FOLDER --file ABSOLUTE_FIXTURE_PATH`.
It waits for real analysis and completed Metal frames, writes `native-smoke.json`
in that test workspace, and exits. A successful receipt has `"passed": true`.
This checks native rendering, not visual/pixel accuracy or OS file-dialog input.

## Files and storage

Read these implementation files in this order:

| File | Responsibility |
|---|---|
| [project.hpp](project.hpp), [project.cpp](project.cpp) | Validate Mach-O headers, select an ARM64 slice, hash inputs, save/reopen projects. |
| [file_io.hpp](file_io.hpp), [file_io.cpp](file_io.cpp) | Read binary headers and hash/copy large files in bounded chunks. |
| [bundle.hpp](bundle.hpp), [bundle.mm](bundle.mm) | Resolve a `.app` to its declared main executable using macOS property-list parsing. |
| [analysis.hpp](analysis.hpp), [analysis.cpp](analysis.cpp) | Launch Ghidra with an argument array, enforce time/cancellation limits, persist verified results. |
| [ghidra/MacExport.java](ghidra/MacExport.java) | Ask Ghidra for functions, pseudocode and assembly; record incomplete results. |
| [controller.cpp](controller.cpp) | Connect background analysis and persistent notes to the shared panel model. |
| [desktop.mm](desktop.mm) | Present the native file chooser and restore the last project. |
| [../gui/workbench.cpp](../gui/workbench.cpp) | Draw the existing two layouts using the optional live integration. |

The `mock` namespace currently contains the shared selection/view model as well
as the older demonstrations. Live mode clears all synthetic data, supplies real
functions, and uses its own analysis, console and note-saving callbacks. It never
calls the mock analysis or chat implementation.

This milestone's small file-based project store is independent of the original
x64 core's SQLite database. It does not claim to port the full harness or all
existing CLI contracts. Reusing those wider services is later integration work.

- `out/macBuild/build/`: generated CMake files, executables, and test fixture.
- `out/macBuild/downloads/` and `out/macBuild/deps/`: downloaded archives and tools.
- `.indago/mac-arm64/<original-sha256>/`: default persistent project directory.
  It contains the original bytes, selected ARM64 slice, `project.json`, `notes.md`,
  immutable `analysis-<hash>.json` reports, and a `latest.json` pointer.
- Per-run tool logs are retained inside the project for diagnosis. Failed runs
  can retain temporary Ghidra files; these are not analysis results.

Both `out/` and `.indago/` are ignored by Git. Source and tests belong in
`macBuild/`; generated output does not. Use `--workspace ABSOLUTE_FOLDER` to
choose another workspace and `--file ABSOLUTE_FILE` to open a file at startup.

This is a **development app bundle**. It resolves its tool/script locations from
the repository path used by CMake. Keep the checkout in place; rebuild after
moving it. Standalone redistribution, signing/notarization and dependency
packaging are later work.

## Supported scope and limits

- Native Apple Silicon macOS; CMake deployment target is macOS 13. The oldest
  target OS is not qualified merely by setting that compiler option.
- Little-endian ARM64 and baseline arm64e Mach-O executables, dynamic libraries
  and bundles. Universal files prefer generic arm64, otherwise baseline arm64e.
  The original CPU subtype/ABI flags are preserved in project metadata/evidence.
  Standalone arm64e.x1, ARM32, x64-only files, ELF, PE and object files remain
  unsupported. This adds static arm64e inspection, not pointer-authentication
  emulation or native execution support.
- There is no fixed application input-size cap. Import and reopen use a 64 KiB
  header cache and 1 MiB hash/copy buffers, rather than whole-file memory copies.
  Allow disk space for both the original file and its extracted ARM64 slice,
  plus Ghidra's temporary analysis data. Opening still waits for the import and
  integrity checks; Ghidra analysis runs in the background.
- Export limits: 256 functions, 2,048 instructions per
  function, 32,768 pseudocode characters per function. Truncation is explicit.
- Ghidra automatic analysis: 60-second limit; decompilation: 10 seconds per
  function; total worker: 180 seconds. Java heap: 2 GiB. Successful report files
  are limited to 16 MiB; these bounds do not guarantee complete binary analysis.
- Notes: 1 MiB, saved explicitly. Function references are session-local and
  expire when analysis is refreshed. UI theme/layout preferences are session-local.
- Console commands: `help`, `functions`, `goto NAME_OR_ADDRESS`, `analyze`,
  `cancel`, `notes`, `save`, `status`, `clear`, `history`. It is not a shell.
- No program execution, debugger, instrumentation, symbolic solver or replay yet.

## Dependency provenance

[setup.sh](setup.sh) checks pinned SHA-256 values before extracting downloads.
It uses the official [Ghidra 12.0.3 release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.0.3_build)
and [Temurin 21.0.12.1+1 ARM64 JDK release](https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1).
This Ghidra release includes a native macOS ARM64 decompiler; no x64 translation
or separate native-component build is needed for this pin. Upstream license and
notice files remain in the extracted distributions. Nothing is fetched at analysis
time. The repository's existing vendored Dear ImGui and JSON library are reused.

Bundle resolution follows Apple's [CFBundleExecutable documentation](https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleexecutable).
The file picker uses [treatsFilePackagesAsDirectories](https://developer.apple.com/documentation/appkit/nssavepanel/treatsfilepackagesasdirectories)
to keep applications selectable as single packages.
