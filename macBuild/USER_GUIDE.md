# Using IndagoRev on an Apple Silicon Mac

This guide is for the native app built from `macBuild/`. Its header says **REAL
STATIC ANALYSIS**: functions, assembly and pseudocode come from Ghidra, not the
older mock demonstration. The separate x64 build has different capabilities and
commands; its instructions do not apply to this app.

## Contents

- [Install and launch](#install-and-launch)
- [Analyze your first application](#analyze-your-first-application)
- [Read and navigate results](#read-and-navigate-results)
- [Save notes and references](#save-notes-and-references)
- [Try the offline chat](#try-the-offline-chat)
- [Adjust time and memory](#adjust-time-and-memory)
- [Use the in-app console](#use-the-in-app-console)
- [Keep and recover your work](#keep-and-recover-your-work)
- [Use the command-line tool](#use-the-command-line-tool)
- [Troubleshooting](#troubleshooting)
- [Current boundaries](#current-boundaries)

## Install and launch

You need an Apple Silicon Mac, Apple's Command Line Tools, CMake 3.25 or newer,
and a checkout of this repository with its required vendored sources. The build
sets macOS 13 as its deployment target; that does not mean every older macOS
release has been tested.

If Apple's development tools are missing, run `xcode-select --install` in Terminal
and finish the installer. Check that `cmake --version` works before continuing;
CMake must be installed separately if it is missing.

**Easiest launch:** double-click `Run ARM GUI.command` inside `macBuild/`.
It prepares the dependencies, builds the application, and opens it. Leave its
Terminal window open while setup and compilation finish; errors appear there.

Alternatively, run these commands from the repository root:

```sh
bash macBuild/setup.sh
cmake -S macBuild -B out/macBuild/build -DCMAKE_BUILD_TYPE=Release
cmake --build out/macBuild/build --parallel 4
open out/macBuild/build/IndagoRev-ARM64.app
```

First setup downloads approximately 680 MB of pinned Ghidra and Java archives,
verifies their checksums, and extracts them below `out/macBuild/`. It does not
install Java or Ghidra system-wide. Later setup runs reuse the downloaded files;
analysis itself does not download tools. Allow additional space for the extracted
tools, build, imported binaries and analysis databases.

After a successful build, open `out/macBuild/build/IndagoRev-ARM64.app` directly
for subsequent use. Run the launcher again after source changes to rebuild it.
This is a development app tied to its checkout: moving just the app bundle to
another machine is insufficient. Reconfigure and rebuild after moving the checkout.

## Analyze your first application

1. Launch the ARM64 application and click **Open app or ARM64 file...**.
2. Select an application, for example `/System/Applications/Books.app`, and click
   **Analyze** in the file picker. Select the app itself, not its package contents.
3. Wait for import and then background analysis. Import copies and verifies the
   executable and can briefly pause the interface for a large file.
4. Select a function in the left-hand list. Its pseudocode and assembly appear in
   the central panes; functions outside the initial preview load in the background.
5. Read **Evidence** and the status messages before treating the results as complete.
6. Open **notes.md**, record your findings, and click **Save notes**.

For a smaller first example, select `out/macBuild/build/mac-analysis-fixture`,
which the build creates from a small XOR-decoder example.

Opening a new input starts analysis automatically. Opening an already analyzed
input restores its saved results; click **Analyze again** when you want a fresh
run. **Cancel analysis** stops the current run and keeps previously saved results.

An app package is a folder containing code and resources. IndagoRev reads its
`Contents/Info.plist` to locate the declared main executable and imports that file
only. Frameworks, helper programs and resources inside the package are not
included automatically; open a supported helper or library separately to inspect it.
The selected application is never launched by analysis.

## Read and navigate results

| Area or control | How to use it |
|---|---|
| Project | Shows the imported target and `notes.md`. |
| Functions | Filter by function name or address, then select a result. The count shows the filtered and total entries. |
| Go to address or name | Enter a known function name or address and press Enter or **Go**. |
| Pseudocode | Ghidra's C-like interpretation of the function; it is reconstructed code, not the original source. |
| Assembly | The machine instructions Ghidra decoded for the selected function. |
| Evidence | Read the analysis identity, settings and diagnostics behind the displayed results. |
| Console | Read operation messages or enter the commands listed below. |
| Compare layout | Places pseudocode and assembly beside each other. **Stacked layout** places pseudocode above assembly. |
| Settings | Adjust analysis resources, theme and text size. |

Both layouts show the same selected function; compare mode is not a comparison
of two different binaries. Navigation identifies the containing function, without
claiming an exact mapping between every pseudocode line and assembly instruction.

The list contains all functions Ghidra discovered, including external imports.
An external import names code supplied by another library; its implementation is
not present in this executable, so it has no local pseudocode or assembly to fetch.
Names may be generated when symbols were removed from the original program.

The first 256 internal functions receive detailed preview code during analysis.
Selecting another internal function reopens the saved Ghidra database and fetches
its code. Results are cached for later visits and restarts. Changing selection
cancels an obsolete request; **Cancel code loading** stops a request manually, and
**Retry code loading** retries a failed or cancelled request.

An older project without a retained database may run analysis once before loading
the requested code. This preserves notes. A fresh analysis creates a new revision,
so cached code from an older revision is not reused as if it were current.

A full discovered-function list does not guarantee complete analysis: Ghidra may
reach its time limit before finding every function. Individual functions can also
fail to decompile or have truncated output. Check diagnostics; unavailable
pseudocode is not evidence that the function does nothing.

## Save notes and references

Click **notes.md** to edit project notes. **Save notes** writes them to disk;
**Discard changes** restores the last saved text, and **Copy notes** copies the
current text to the clipboard. Notes are limited to 1 MiB and are not auto-saved.
Save or discard changes before changing functions, opening another input or
starting another analysis when those actions are blocked by an unsaved draft.

Select a pseudocode line, or Shift-click to extend a selection, then use **Add
reference** to retain a navigation reference. References last for the session and
expire when analysis is refreshed; they are not a substitute for saved notes.
The chat area can prepare questions and context locally; see below. Rename/type
edits are not connected to the real analysis database.

## Try the offline chat

The right-hand chat panel now works without credentials in **Offline preview**
mode. It prepares a request and displays a local receipt showing what was
included. It does not generate an AI explanation or contact any service.

1. Select a function, optionally select code lines and click **Add reference**.
2. Type a question in the chat box. The selected function's pseudocode and
   diagnostics are included automatically; attached quotes can refer to other functions.
3. Choose **Include assembly** or **Include saved notes** when those are relevant.
   Both start disabled, and unsaved note drafts are never included.
4. Click **Preview context** to inspect the exact prepared JSON snapshot. **Copy
   context** copies it to the clipboard; **Close context** returns to the chat.
5. Click **Send** to add the question and an **Offline preview** receipt to the
   conversation. **Last context** reopens the snapshot even after the draft clears.
6. Use **Stop reply** while a response is pending, or **Clear chat** to remove the
   conversation and its saved last request from this project's chat file.

The snapshot includes the target name and fingerprint, analysis identity and
partial-result status, function name/address/signature, numbered pseudocode,
diagnostics, attached quotes, optional assembly and optional saved notes. It does
not read the binary bytes, entire function list, workspace files or tool logs.
Included diagnostic text and opted-in notes can themselves contain paths or other
project details; review the snapshot before copying or sharing it.
The last six user/assistant messages can accompany a follow-up; earlier code
attachments are not automatically included again. Local receipts and failures are
excluded from model conversation context. Reattach quotes when they are needed.

Context has a 64 KiB serialized limit. Individual budgets are 12 KiB of pseudocode,
128 assembly rows within 8 KiB, eight quotes of up to 2 KiB each, 4 KiB of saved
notes, and 2 KiB per history message. Shortened sections are marked explicitly;
JSON escaping can make a request exceed the overall limit, in which case preparation
fails with an explanation. Questions accept up to 4,096 bytes. These are byte
budgets, not model token counts or a promise that a future model accepts that size.

Chat history and the last request are saved locally in the project's `chat.json`.
Up to 40 messages are retained, with older messages removed to keep the saved file
within its size budget. History survives restart and reanalysis; the last context
still describes its captured analysis revision. Navigation links in old messages
expire when analysis changes and are omitted on reopening; quotes attached to the
last sent request remain in its context snapshot. A new input has its own history. Unsent drafts,
unsent previews and inclusion preferences are session-local. Backups may retain
older chat content even after **Clear chat**.

A provider connection point is implemented for a later local or hosted model.
Credentials, provider selection, networking, streaming and real AI answers are
future work. The current chat has no project-editing or command-execution tools.

## Adjust time and memory

Open **Settings**, enter positive whole numbers, and close the settings window.
Use **Analyze again** to apply them to a new full analysis. Resource controls are
locked while a worker is active. Preferences reset on restart; saved evidence
records the settings that produced that report, not a newly entered preference.

| Setting | Default | Meaning |
|---|---|---|
| Analysis time (seconds) | 60 | Time allowed for Ghidra's automatic analysis. For example, 300 allows five minutes. |
| Analysis memory (GiB) | 2 | Maximum Java heap for the next analysis or function-code request. It is not total application memory. |

The GUI, Java's other allocations and native decompiler require additional memory.
Increasing the heap can help a memory-limited analysis, but requesting more than
available memory does not guarantee success. Leave capacity for macOS and other
applications. The recorded JVM maximum is a ceiling, not a measurement of usage.

A full worker gets the chosen analysis time plus 120 seconds for startup and
export. A single-function request has its own 120-second deadline. Decompilation
has a 10-second limit per function; changing the analysis-time setting does not
raise these separate limits. Detailed output is limited to 2,048 assembly
instructions and 32,768 pseudocode characters per function. The discovered-function
index is separate from these limits and the 16 MiB detailed-report limit.

## Use the in-app console

Click **Console**, type a command, and press Enter. Up/Down recalls commands;
Tab completes command names. This console operates on the open project and is
not a system terminal: shell commands such as `ls` do not run here.

| Command | Action |
|---|---|
| `help` | List supported commands. |
| `functions` | Print discovered function names and addresses to the console. |
| `goto NAME_OR_ADDRESS` | Select a function, for example `goto main` if that name exists. |
| `analyze` | Start analysis with the current GUI settings. |
| `cancel` | Request cancellation of the active analysis or code load. |
| `notes` | Open the notes editor. |
| `save` | Save the current notes. |
| `status` | Print the target and whether a worker is active. |
| `clear` | Clear displayed console messages. |
| `history` | Print recent commands. |

Use **Copy log** to copy the retained console messages. The console retains only
300 entries and command history retains 100 commands; neither is a permanent
analysis log. In a large project, `functions` can exceed the console's capacity,
so use the function list and its filter to browse the complete index.

## Keep and recover your work

The default workspace is `.indago/mac-arm64/` inside the checkout. The app restores
the last project in that workspace on startup. Each project directory is named
with the SHA-256 fingerprint of the original executable bytes. Identical bytes
reuse a project; an application update that changes those bytes creates a new one
and does not automatically transfer notes from the old project.

| Stored item | Purpose |
|---|---|
| `original.bin`, `arm64.macho`, `project.json` | Original executable snapshot, selected ARM64 slice and import metadata. |
| `notes.md` | Explicitly saved project notes. |
| `chat.json` | Recent conversation and the last sent context snapshot, stored locally. |
| `analysis-<hash>.json`, `functions-<hash>.json`, `latest.json` | Verified reports, full function indexes and the pointer to the latest report. |
| `run-*/projects/` | Ghidra databases used to fetch function code later. |
| `function-cache/` | Cached code results for individual functions. |
| Per-run directories and logs | Analysis diagnostics, including files retained after unsuccessful runs. |

Close the app before backing up or relocating workspace files. Copy the entire
workspace to preserve inputs, notes, reports and databases together; do not hand-edit
hashes or report pointers to bypass an integrity error. Keep the checkout and its
tools available when reopening the backup.

To select a different workspace and input, quit the running app first, then run
this from the repository root (replace the workspace path with your own):

```sh
open out/macBuild/build/IndagoRev-ARM64.app --args \
  --workspace "$HOME/IndagoRev-workspace" \
  --file /System/Applications/Books.app
```

There is no automatic cleanup of old analysis revisions. Workspace deletion removes
saved work, including notes. `out/macBuild/build/` contains rebuildable output;
`out/macBuild/downloads/` and `out/macBuild/deps/` contain replaceable dependencies.
Neither `out/` nor `.indago/` belongs in commits. Keep backups before cleaning up
project data; imported originals and extracted slices can consume substantial space.

## Use the command-line tool

The build also creates `out/macBuild/build/indago-mac`. It is separate from the
in-app console and the root x64 `indago` executable. Run it from Terminal:

```sh
out/macBuild/build/indago-mac capabilities
out/macBuild/build/indago-mac import /System/Applications/Books.app "$HOME/IndagoRev-workspace"
```

Import prints JSON metadata including `sha256`. The project path is the workspace
folder followed by that hash. Set `project` to the resulting directory, then use:

```sh
# Replace HASH_FROM_IMPORT with the sha256 printed by import.
project="$HOME/IndagoRev-workspace/HASH_FROM_IMPORT"
out/macBuild/build/indago-mac show "$project"
out/macBuild/build/indago-mac analyze "$project"
# Replace ADDRESS_FROM_INDEX with an internal function's hexadecimal address.
out/macBuild/build/indago-mac function "$project" ADDRESS_FROM_INDEX
```

`show` prints import metadata; `analyze` saves and prints a new analysis report.
Use the report's `function_index_sha256` value to locate
`functions-<that-hash>.json` inside the project directory. Choose an internal
function's `address`, including its `0x` prefix. `function` prints fetched code
and whether the result came from cache.
It requires a saved analysis database; run `analyze` first for an older project.
`capabilities` reports tool availability, not proof that an analysis will succeed.

The CLI uses the default 60-second automatic-analysis limit and 2 GiB heap; it
has no resource-setting flags and does not inherit GUI preferences. Exit codes
are 0 for success, 1 for an operation error and 2 for incorrect arguments. Avoid
running CLI analysis against a project currently being analyzed in the GUI.

## Troubleshooting

| Symptom | What to check or do |
|---|---|
| Launcher cannot find CMake or a compiler | Check `cmake --version` and `xcode-select -p`; install the missing prerequisite, then rerun the launcher. |
| Setup reports a checksum mismatch | Remove only the archive named in the error from `out/macBuild/downloads/` and rerun setup to download it again. Do not disable verification. |
| Tools are missing, or the checkout moved | Rerun setup, configure and build using the commands above. The app uses the configured checkout paths. |
| An app or file is rejected | Confirm it contains a supported ARM64 Mach-O executable. An ordinary folder is not an app; a valid app needs its declared main executable. See supported formats below. |
| Opening a large input appears slow | Import and integrity checks read the executable before background analysis begins. Check free disk space and allow time for the copy. |
| Functions are missing or results say partial | Increase analysis time and run **Analyze again**. A complete discovered index cannot include functions the tool has not identified. |
| Memory-related analysis failure | Review the run log, increase the Java heap if the Mac has capacity, close other heavy applications and retry. |
| Function code fails to load | Read Evidence/Console diagnostics, use **Retry code loading**, or **Analyze again** if the database is missing. External imports have no local body to load. |
| Open or analysis controls are disabled | Save/discard notes and wait for or cancel the active worker. Resource settings must be positive integers. |
| Evidence or input integrity error | Preserve the workspace and notes, then restore a known-good backup. Import the original input into a new workspace for a clean analysis if necessary. |
| Chat returns an offline receipt | Expected until a real provider is connected. Use **Preview context** to review the prepared data. Annotation edits remain unavailable. |
| Chat preparation fails | Finish active analysis, select a discovered function and enter a question within 4,096 bytes. Shorten quotes or omit optional data if the context exceeds its limit. |

For a useful issue report, include what you opened, the displayed error, macOS
version, time/memory settings, and the relevant console or per-run tool log.
Review logs before sharing: paths, function names and binary details may be private.
Build verification commands and the native rendering smoke check are documented
in the [build README](README.md#build-and-test-from-terminal).

## Current boundaries

Supported inputs are little-endian ARM64 and baseline arm64e Mach-O executables,
dynamic libraries and bundles. Universal files select generic arm64 when available,
otherwise baseline arm64e. ARM32, x64-only files, standalone arm64e.x1, Windows PE,
Linux ELF and object files are not supported by this build.

There is no fixed input-file size cap. Disk capacity, available memory, analysis
time and output bounds still affect practical use. Large-file tests cover a
320 MiB padded fixture, not every complex application of that size.

This build performs static inspection only. It does not run the target, attach a
debugger, trace execution, emulate pointer authentication, solve program inputs,
or replay execution. Objective-C and Swift reconstruction may be incomplete.
For implementation details, test coverage and dependency provenance, see the
[build README](README.md); the [ARM support plan](../docs/arm-support-plan.md)
describes broader integration work rather than a promise of current features.
