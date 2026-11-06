# Terminal workbench

`indago-tui` is an interactive ncursesw front end for IndagoRev. It reads and
writes the same workspace store as the native CLI, so projects, targets,
evidence, jobs, and harness records created in one are visible in the other.
Analysis and harness work run through the same `StaticService` paths the CLI
uses; the workbench adds no separate execution model. As with the CLI, a runtime
backend selected through the Query form can execute the host target without a
sandbox.

Requires at least 48 columns by 8 rows. Anything smaller is replaced by a size
warning until the terminal is resized.

## Build and launch

The target is built when ncursesw (found through pkg-config) is available and
`INDAGO_BUILD_TUI` is on (the default). The native presets list only the
`indago` target, so build the workbench explicitly:

```sh
cmake --preset linux-native
cmake --build --preset linux-native --target indago-tui
./out/native-Linux/tui/indago-tui --workspace .indago
```

If ncursesw is not found, CMake prints "ncursesw not found - skipping
indago-tui build" and the target is not produced.

Options:

```text
indago-tui [--workspace DIR] [--project NAME]

  --workspace DIR   Workspace store directory. Defaults to .indago.
  --project NAME    Open NAME directly on the Targets page instead of Projects.
  --help            Print the usage line and exit.
```

If `--project` names a missing project, the workbench falls back to the Projects
page and shows the error on the status line.

## Screen layout

Each page uses four bands:

- A banner with the product name, the workspace path, a running spinner while a
  background task is active, and the current `project :: target` on the right.
- A page title with a `selected/total` position note for list pages.
- A list or form body.
- A per-page help line and a status line. Errors are shown in the error style;
  the error is cleared when the next action begins, so a later success is not
  masked.

## Common keys

These work on most pages unless a page overrides them.

| Key | Action |
| --- | --- |
| `Up` / `Down` or `k` / `j` | Move the selection one row. |
| `PgUp` / `PgDn` or `-` / `space` | Move the selection one page (10 rows). |
| `Home` / `End` or `G` | Jump to the first or last row. |
| `Enter` | Open, select, or run the highlighted item. |
| `Esc` / `b` / `Left` | Go back to the previous page. |
| `r` or `F5` | Refresh the current list. |
| `q` | On Projects, ask to quit. On the Targets, Functions, Evidence, Jobs, and Harness lists, open the Query form. |

Prompts accept typed text and require `Enter`; `Esc` cancels and leaves the value
unchanged. Confirmation dialogs such as quit and cancel require `y` or `n` and
then `Enter`; `Esc` cancels.

## Pages

### Projects

Lists each project with its target and function counts and creation time.

| Key | Action |
| --- | --- |
| `Enter` / `Right` | Open the project and switch to Targets. |
| `n` | Create a project (prompts for a name). |
| `i` | Open the selected project and switch to Targets to import, or import directly if a project is already open. |
| `c` | Show the capabilities view as a static detail page. |
| `r` / `F5` | Reload the project list. |
| `q` | Ask to quit. |

### Targets

Lists the targets imported into the current project, marking the active one with
`[active]`.

| Key | Action |
| --- | --- |
| `Enter` / `Right` | Make the highlighted target the active target. |
| `a` | Run the analysis profile in the background: XAIR inventory, AIRECE inspect and functions, and XAIR CFG. Results open on the detail page. |
| `i` | Import a file (prompts for a path, `~` is expanded). |
| `g` | Open Functions. |
| `e` | Open Evidence. |
| `J` | Open Jobs. |
| `h` | Open Harness. |
| `q` | Open the Query form. |
| `p` | Show project info as a static detail page. |
| `c` | Show capabilities as a static detail page. |

### Functions

Lists functions for the active target with the view name, block count, and
coverage when available.

| Key | Action |
| --- | --- |
| `Enter` / `d` | Show AIRECE disassembly for the selected address. |
| `p` | Show AIRECE pseudocode for the selected address. |
| `x` | Run XAIR CFG for the selected address. |
| `f` | Set an address-substring filter (prompts; the current filter is pre-filled). |
| `F` | Clear the filter. |
| `t` / `e` / `J` / `q` | Cross-navigate to Targets, Evidence, Jobs, or Query. |

### Evidence

Lists evidence records with backend, status, and creation time.

| Key | Action |
| --- | --- |
| `Enter` | Open the record. The detail page reads the content-store blob and verifies its SHA-256 before showing it. |
| `r` / `F5` | Reload the list. |
| `t` / `g` / `J` / `q` | Cross-navigate to Targets, Functions, Jobs, or Query. |

### Jobs

Lists analysis jobs with status, backend/operation, optional address, and
creation time.

| Key | Action |
| --- | --- |
| `Enter` | Open the job detail. |
| `k` | Cancel the selected job (asks for confirmation). |
| `r` / `F5` | Reload the list. |
| `t` / `g` / `e` / `q` | Cross-navigate to Targets, Functions, Evidence, or Query. |

### Query

Runs a single analysis operation without leaving the workbench. The form has
these fields, with defaults:

| Field | Default |
| --- | --- |
| backend | `airece` |
| operation | `function` |
| address | empty |
| view | `disassembly` |

| Key | Action |
| --- | --- |
| `Up` / `Down` or `k` / `j` | Move between fields and the run row. |
| `Enter` | Edit the selected field, or run when the run row is selected. |
| `r` / `R` | Run the query with the current field values. |
| `Esc` / `b` | Go back. |

The result opens on the detail page. `J` toggles between the text body and the
raw JSON envelope.

### Harness

Lists the harness investigations for the current project.

| Key | Action |
| --- | --- |
| `Enter` | Show the investigation record (`show`) as a detail page. |
| `n` | Create an investigation (see the prompt sequence below). |
| `r` | Run `explore` on the selected investigation. Requires an owner lease acquired by creating it from this page in the current session. |
| `a` | Show recorded actions. |
| `e` | Show recorded events. |
| `R` / `F5` | Reload the list. |
| `t` / `g` / `J` / `q` | Cross-navigate to Targets, Functions, Jobs, or Query. |

Creating an investigation prompts, in order, for:

1. `objective` (required; an empty objective aborts).
2. `owner mode` (`builtin` or `external`; defaults to `builtin`).
3. `model` and `endpoint` when the owner is `builtin`.
4. `required facts` as a comma-separated list.
5. `max actions` (defaults to 8).

On success the response stores the owner token and investigation id, and the
status line reports that the lease was acquired. `explore` refuses with
"no owner lease" for investigations opened from a previous session or created by
another process. An `external` owner records a model declaration and does not use
inference.

`explore` runs the `assisted_static` recipe with inference enabled. It requires a
reachable provider when the owner is `builtin`; without one the harness records
the unavailable status instead of hanging, and the run still appears as a detail
page.

### Detail

The detail page is used for static views (capabilities, project info, actions,
events), analysis results, evidence blobs, and investigation records.

| Key | Action |
| --- | --- |
| `Up` / `Down` or `k` / `j` | Scroll one line. |
| `PgUp` / `PgDn` or `-` / `space` | Scroll one page (20 lines). |
| `Home` / `End` | Jump to the first or last line. |
| `Left` / `Right` or `h` / `l` | Pan horizontally. |
| `/` | Find (prompts for a needle; the title shows the match count). |
| `n` | Jump to the next match, wrapping at the end. |
| `J` | Toggle between the text body and the raw JSON, when the page came from a background task. |
| `Esc` / `b` / `Left` | Go back. |

The title note always shows `line N/total  col M`, clamped to the actual content.

## Harness workflow

A typical sequence from the Projects page:

1. `Enter` to open a project, then `i` to import a target.
2. `a` to run the static analysis profile.
3. `g` to browse functions, or `e`/`J` for evidence and jobs.
4. `h` to open Harness, `n` to create an investigation, then `r` to explore.

The harness page reads investigations directly from the workspace and is
independent of the CLI harness process. Actions and events reflect the records
written by `harness_action`; they are not a live log stream.

## Terminal workbench tests

`tests/tui_tests.cpp` drives the built binary through a real pseudo-terminal and
reconstructs the screen with a small terminal emulator, so assertions check what
the program actually paints rather than a raw byte buffer. The suite seeds a
temporary workspace with a project, an imported target, functions and views,
evidence backed by a real content-store blob, queued jobs, and investigations,
then runs 19 independent scenarios.

Build and run under Linux or another Unix with `forkpty`:

```sh
cmake --preset linux-native -DINDAGO_BUILD_TESTS=ON
cmake --build --preset linux-native --target indago_tui_tests
./out/native-Linux/tui/indago_tui_tests ./out/native-Linux/tui/indago-tui
```

Or through CTest:

```sh
ctest --test-dir out/native-Linux -R indago_tui --output-on-failure
```

The runner prints `tui_tests: N passed, M failed` and exits non-zero on any
failure. On Windows the test binary reports that it is skipped, because `forkpty`
is unavailable.

To enable the test when configuring a custom build directory, pass
`-DINDAGO_BUILD_TESTS=ON`; the `linux-native` and `windows-native` presets
otherwise disable test executables.

## Limits

- The workbench requires ncursesw; the test binary requires a Unix pty.
- Inference is optional. A builtin-owner explore needs a reachable provider;
  otherwise it records the unavailable status.
- The Harness page does not cross-navigate to Evidence; `e` opens the
  investigation events.
- Analysis and explore run on a background thread while the banner shows a
  spinner. `Esc` while busy requests cancellation of the current job.
