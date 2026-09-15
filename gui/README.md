# Pair-reversing workbench

A small C++20 / Dear ImGui desktop frontend. The first platform backend is
Windows 10+ Win32/D3D11. Linux/macOS desktop backends are not implemented yet;
the existing CLI and Pi harness remain independently usable.

## Build and run

For a double-click folder package, build the GUI/native CLI and run
`./tools/package-gui.ps1`. It creates `out/IndagoRev-Desktop` with its own Node
runtime and lock-pinned Pi installation. Double-click `IndagoRev.exe` there and
use **Choose folder**. Keep the whole package together. The packager requires
pnpm and never overwrites an existing destination; use `-Destination` for a new
build. The default local LM Studio server must still be running for chat.

```powershell
cmake -S gui -B out/gui -G "Visual Studio 17 2022" -A x64
cmake --build out/gui --config Release --parallel 4
./tools/run-gui.ps1 -Project C:/path/to/investigation
```

Build the native CLI and install `agent/` dependencies as described in the root
and agent READMEs. The launcher defaults to `out/build/Release/indago.exe` and
Node on PATH; `-Executable` and `-Node` override those locations. Ghidra views
require a native build with the existing Ghidra worker available. Alternatively,
enable `INDAGO_BUILD_GUI` in a root CMake build and build `indago-gui`.

The GUI also accepts `--project`, `--exe`, `--node`, and `--agent` (the absolute
path to `agent/desktop.mjs`). Its default portable layout is `indago-gui.exe`,
`indago.exe`, `runtime/node.exe`, and `agent/` with installed pinned dependencies.
The GUI executable is small, but that is not the total distribution size: analysis
workers, Node, and Pi remain separate required components. The local folder
packager is implemented; cross-machine qualification, signing and release
distribution remain future work. No runtime downloads are performed by the GUI.

## Workflow

1. Open a project directory. Browse subdirectories with the Project panel.
2. Click a PE/ELF and confirm **Analyze**. Selection alone does not import or
   analyze it. Ghidra standard analysis is followed by a checkpointed decompile
   pass over all discovered functions. Continuous, virtualized code panes show
   function pseudocode and the address-ordered instruction listing (including
   instructions outside functions). Main is selected when identified, otherwise
   the native entry. Click a line to synchronize using Ghidra address mappings;
   unmapped instructions explicitly fall back to the containing function.
   Decompilation is inherently per-function, not one fabricated global C function.
3. Click a UTF-8 source file to edit it instead (1 MiB limit). Save explicitly;
   external file changes reject stale saves. Unsaved edits block file navigation
   and AI references; closing the window asks before discarding them.
4. Select code lines (Shift-click for a range), or highlight source text, and
   click **AI reference**. Native quotes stay within a saved listing segment.
   The pending quote includes original
   text, artifact hash, file, byte/line range, backend/function, program revision,
   evidence IDs and overlapping native token/address/symbol mappings. Up to eight
   references of 16 KiB each are accepted. Ghidra UTF-16 token offsets are mapped
   to the editor's UTF-8 selection offsets, not assumed interchangeable.
5. Ask a focused question in Agent Chat. Sessions reuse Pi and the existing native
   knowledge store, not a separate model/controller. Replies stream; cancellation
   stops the current request. Persisted sessions reopen with chat history.

**Evidence / Edits** exposes function rename, C function signature changes, and
retyping a recovered variable using its symbol ID and an existing Ghidra type
path. List variables / List types provide those identifiers. Edits use existing
revision-checked Ghidra transactions, save the Program, and invalidate displayed
code/references. They are user assertions, not backend-inferred facts. This first
UI does not include local-variable renaming or an interactive type constructor.
The raw evidence view preserves partial/error status, pagination and backend
semantics; unsupported or incomplete analysis is not rendered as a verified result.
Native XAIR/AIRECE analysis remains available through the agent tools; the initial
dedicated code panes use Ghidra.

## Agent settings

Choose LM Studio, OpenRouter or another OpenAI-compatible provider. Set endpoint,
model ID, output-token cap and an API-key environment-variable
name. Keys themselves are not stored in UI settings or sent on command lines.
Remote endpoints must use HTTPS; HTTP is accepted for loopback only. A remote
provider receives quoted evidence and any additional context the agent retrieves.
Provider selection is explicit: there is no automatic remote fallback.

Settings persist on chat submission in the project's ignored `.indago-desktop/`
directory. Token counts come from provider usage events. The context bar is last
request input including cache reads divided by provider-reported capacity, not an exact
live tokenizer count. Effective output tok/s includes tool time and prefill; it
must not be confused with server-only decode throughput. Context is read-only and
refreshed before chat. LM Studio's loaded-instance context is used, not the model's
maximum training capacity. Providers without context metadata display unknown;
chat asks for a usable provider configuration rather than inventing a capacity.

## Saved analysis

The default `.indago-desktop/` contains native workspace metadata, evidence,
chat, and hash/revision-bound listing checkpoints. An optional **Analysis folder**
can be chosen before opening the project; a local `.indago-desktop-location.json`
remembers it. Use a dedicated folder per project. Reopening reuses saved analysis;
only missing checkpoints or changed artifact/Program revisions need new listings.

Ghidra rejects dot-prefixed path components, so in that case its durable Program
database lives under `IndagoRev-GhidraProjects/` at the nearest non-dot ancestor.
The native worker's `program-location.json` records the actual database location.
Keep that directory with the analysis workspace. A quiescent legacy temporary
database is copied into durable storage on next worker startup, retaining the
original for recovery.

Cancel preserves completed functions. Failed decompilations and scan/output limits
remain explicitly incomplete; **Reload saved analysis** does not silently retry
expensive failures or rerun standard analysis. Each native request is bounded;
the backend currently limits a collection scan to 100,000 items.

## Boundaries

The policy prohibits target execution and asks the agent to obtain approval before
changing original files/program annotations. This is **not a sandbox or a hard
authorization boundary**: existing Pi shell tools retain host access. Use trusted
inputs or an appropriate lab. Cancellation/exit can leave uncertain tool effects;
inspect receipts before retrying writes. Worker lifetime is tied to the Windows
GUI job object; persistent project data remains on disk. Pipe transport is local
to child processes and does not expose a GUI network listener.

The initial editor is plain text (no syntax coloring, debugger controls, terminal
emulation, graph canvas or rich Markdown renderer). These are deliberately outside
this first pair-reversing interface.

## Checks

`node --test agent/tests/*.test.mjs` includes selection/Unicode, artifact freshness,
source-save conflicts, project-boundary checks, revision forwarding, cancellation
and provider-error reporting. Existing real-Pi/mock-provider tests cover native
dispatch, session budgeting, context and final handling. Development smoke checks
also exercised native functions/decompile/assembly, saved function rename/signature,
variable retyping from int to uint, stale revision rejection, and two real
local-Qwen conversational turns. Desktop interaction checks exercised source
navigation, selection attachment, chat and the provider/settings panel.
