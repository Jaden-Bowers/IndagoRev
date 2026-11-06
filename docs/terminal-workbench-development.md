# Terminal workbench internals

This is the developer guide for `tui/`, the ncursesw front end. For the user
guide, key bindings, and build/run commands, see
[terminal workbench](terminal-workbench.md).

## Source layout

| File | Responsibility |
| --- | --- |
| `tui/ui.hpp`, `tui/ui.cpp` | Drawing primitives, terminal init, modal prompts. Knows nothing about IndagoRev. |
| `tui/app.hpp`, `tui/app.cpp` | `App` state and the `StaticService` calls behind every page. |
| `tui/main.cpp` | Argument parsing, the input/render loop, page dispatch, and detail/find logic. |
| `tests/tui_tests.cpp` | Pty-driven integration tests with a small terminal emulator. |

`tui/CMakeLists.txt` builds `indago-tui`, links `indago_core` and ncursesw, and
adds the test target when `INDAGO_BUILD_TESTS` is on.

## Startup

`main()` parses `--workspace`, `--project`, and `--help`, then:

1. `tui::ui_init()` sets the locale, enters cbreak/noecho mode, enables keypad,
   hides the cursor, sets `set_escdelay(50)`, and initializes color pairs.
2. Constructs `App(workspace)`, which creates the `StaticService` and loads the
   project list.
3. If `--project` was given, opens it and pushes the Targets page.
4. Runs the loop until the user confirms quit or a fatal error occurs, then
   `ui_end()`.

The 50 ms escape delay is what lets a lone `Esc` act as "back" without also
waiting for a full escape sequence.

## State model

`App` (in `tui/app.hpp`) holds everything the loop renders:

- `page` is the current `Page`; `history` is the back stack used by
  `push_page()` / `go_back()`.
- One vector per list page (`projects`, `targets`, `functions`, `evidence_rows`,
  `job_rows`, `harness_rows`), each with a selection index (`*_sel`) and a
  scroll offset (`*_top`). `draw_list()` maintains `*_top` from the selection.
- The active target fields (`target_id`, `artifact_sha`, `target_name`) are set
  by `pick_target()` and reused by every analysis request.
- Detail state: `detail_row`, `detail_col`, `detail_show_raw`, `detail_needle`.
- Task state: `task` is the running `BackgroundTask` (or null); `show_task` is the
  last finished task whose result is displayed on the Detail page.
- Status: `status_message` for success text and `last_error` for failures.
- Harness lease: `harness_token`, `harness_inv_id`, `harness_revision`, set only
  by `create_investigation()`.

Selections are clamped by each `refresh_*()` after rebuilding its vector, so a
shrinking list cannot leave the selection out of range.

## Main loop

Each iteration of the loop in `tui/main.cpp`:

1. `timeout(120)` while a task is running, otherwise `timeout(-1)` to block. The
   poll is what lets the spinner animate and lets `finish_task()` run promptly.
2. `getch()`.
3. `finish_task()`: if the background task is done, move it to `show_task`,
   reset the detail cursor, record any error, set a status line, and refresh the
   current list. The loop then opens the Detail page.
4. `ERR` (no key) while a task runs just re-renders; `KEY_RESIZE` erases and
   re-renders.
5. While `busy()`, `q` asks to cancel and quit and `Esc` requests cancellation;
   other keys are ignored.
6. Otherwise the action begins: clear `last_error`, compute `global_back`
   (`Esc`, `b`, `Left`), dispatch on `page`, then render.

Clearing `last_error` at the start of each action is deliberate. It lets a failed
action display its error until the next key press, then allows a later successful
action to show its status instead of leaving the previous error latched forever.

## Rendering

`render()` draws four bands:

- `draw_banner(left, center, right)`: product and workspace, a spinner based on
  the tick counter while busy, and `project :: target` on the right.
- `draw_title(text, note)`: the page name and a `selected/total` position note.
- The body: `draw_list()` for lists, field rows for the Query form, or
  `draw_textview()` for Detail.
- `draw_help()` and `draw_status()`: the per-page key hints and the status or
  error line.

If the terminal is smaller than 48 columns or 8 rows, `render()` draws a size
warning and returns before any page logic.

`draw_list()` paints from `*top`, keeping the selection visible, and prints the
empty note when there are no rows. `draw_textview()` scrolls by `row` and pans by
`col`, clamping both. The Detail render case also clamps `detail_row` before
building the `line N/total` note so the counter never shows an out-of-range
value for a frame.

## Background tasks

`App::launch()` creates a `BackgroundTask` on the heap, assigns it to `task`, and
runs the body on `std::thread`. Exceptions in the body are stored in
`task->error`. The thread sets `done` when finished. The UI thread never blocks
on analysis work.

- `busy()` is true while `task` exists and is not done.
- `finish_task()` is the only place a task becomes `show_task` and the Detail
  page is populated.
- `request_cancel()` sets `task->cancel` and, if the body has published a job id
  with `set_job()`, calls `ProjectStore::cancel_job()`. Long operations poll
  `task->cancel` between steps (for example the analysis profile).
- `~App()` cancels and joins the worker.

`BackgroundTask::set_job()` / `get_job()` are mutex-guarded because the worker
thread and the UI thread both touch the current job id.

Task bodies build an action request with `action_request()` (which repairs a
missing `target_id` from the first listed target), call
`StaticService::prepare()` then `execute()`, and render the result through
`text_of()` plus the raw JSON envelope.

## Service access

`App` owns one `StaticService` for the workspace. Page refreshes call
`ProjectStore` methods (`list_projects`, `project_info`, `functions`,
`function_views`, `evidence`, `job_info`). Detail builders (`job_detail_lines`,
`evidence_detail_lines`, `project_json_lines`, `capabilities_lines`) call the
same store and dump the JSON as text.

The Harness page is the one exception: `harness_action()` has no list operation,
so `refresh_harness()` reads `wb_investigations` directly with SQLite, newest
first, limit 200. `show`, `actions`, and `events` still go through
`harness_action()`.

`refresh_current()` re-runs the refresh for the active page after a task
finishes, so counts and statuses stay current without the user pressing refresh.

## Detail pages

`detail_main()` chooses the line source:

- If `show_task` is set, it returns the task's `lines` (or `raw` when
  `detail_show_raw` is on and raw content exists).
- Otherwise it returns `static_lines`, populated by `App::show_static()`.

`show_static()` clears `show_task`, resets the cursor and search state, and
pushes the Detail page. This is how capabilities, project info, investigation
records, actions, and events are shown.

On Detail, `J` toggles raw JSON only when a task result is present. The `/` find
counts matches across the current line source and jumps to the first; `n` moves
to the next match and wraps. Starting a new static view clears the needle so a
stale search does not carry across pages.

## Navigation and help

Pages are a stack. `push_page()` records the current page and sets the new one;
`go_back()` pops. `Esc`, `b`, and `Left` are handled as `global_back` on pages
that do not consume them. `q` is context sensitive: quit on Projects, open Query
on the list pages. `r`/`F5` refreshes page-dependent lists.

Each page's `draw_help()` string is the authoritative key hint shown at the
bottom; keep it in sync when adding bindings.

## Adding a page

1. Add an enumerator to `tui::Page` in `tui/app.hpp`.
2. Add the state the page needs (vector, selection, scroll offset) to `App`.
3. Add a `refresh_*()` method and include it in `refresh_current()`.
4. Add a `case` in `render()` with a title, position note, help line, and body.
5. Add a `case` in the input dispatch in `tui/main.cpp`; reuse `handle_arrow()`
   for list movement and gate on `global_back`.
6. Add a key that reaches the page from an existing page and update both help
   strings.
7. Add a scenario in `tests/tui_tests.cpp`.

## Adding an operation

The Query form is free-form: `run_query()` passes `backend`, `operation`,
`address`, and `view` into `action_request()`. To add a dedicated key binding
(for example a new AIRECE view), call `run_function_view()` or `run_query()`
directly from the page's dispatch. If a backend rejects the default
`arguments`, special-case it in `run_query()` the way Ghidra is handled.

## Status and dialogs

- Success: `set_status("...")`.
- Failure: set `last_error`; `draw_status()` renders it in the error style. The
  loop clears it at the start of the next action.
- `prompt_line(label, initial)` returns a value on `Enter` and `nullopt` on
  `Esc`; `Esc` leaves the previous value unchanged.
- `confirm_yesno(label)` toggles with `y`/`n` or arrow keys and returns only on
  `Enter`; `Esc` returns false immediately. Callers therefore expect `y` then
  `Enter`, not a single key.

## Test harness design

`tests/tui_tests.cpp` runs the real `indago-tui` binary on a pseudo-terminal.
Assertions read a reconstructed screen rather than the raw byte stream, because
ncurses only emits changed cells and a raw buffer would not represent the stable
screen.

- `Screen` is a character grid that applies the escape subset ncurses emits:
  cursor addressing (`H`/`f`/`A`/`B`/`C`/`D`/`G`/`d`), erases (`J`/`K`/`X`),
  insert/delete (`L`/`M`/`P`), charset selection, and OSC. Unknown sequences and
  attributes this suite does not assert on are dropped.
- `Session` forks a pty with `forkpty`, sets `TERM=xterm-256color` and a UTF-8
  locale, execs the binary with `--workspace`/`--project`, and keeps the master
  non-blocking. `send()` writes keys and pumps output briefly; `expect()` and
  `gone()` poll with a timeout; `resize()` issues `TIOCSWINSZ` and `SIGWINCH`;
  `wait_exit()` polls `waitpid(WNOHANG)`. The destructor kills the child.
- `want()` and `want_gone()` wrap `check()`, which increments pass/fail counters
  and prints `FAIL <description>` on a miss.

`seed_workspace()` creates one temporary workspace and returns a `Seed`: a
project, a real ELF fixture imported as a target, a second fixture for import
tests, static functions with views, two evidence rows backed by a real
content-store blob, two queued jobs created through `StaticService::prepare`,
and two investigations created through `harness_action("create")`.

Each scenario opens its own `Session` against the same workspace, so one failure
does not cascade into the next. The workspace path is under
`fs::temp_directory_path()` and removed at the end of `main()`.

### Writing a scenario

Add a function, call it from `main()` in an order that respects shared state, and
assert with `want`/`want_gone` on stable strings such as a page title, a row id,
or a status phrase. Prefer values the app prints deterministically over layout
positions.

Run the suite directly for fast iteration:

```sh
cmake --build --preset linux-native --target indago_tui_tests
./out/native-Linux/tui/indago_tui_tests ./out/native-Linux/tui/indago-tui
```

### Test gotchas

- Key sequences depend on terminfo. This host's `xterm-256color` uses
  application-cursor mode (`ESC O A` for Up, not `ESC [ A`), and `Home`/`End` are
  `ESC O H`/`ESC O F`. Check `infocmp` before changing the key constants.
- `list_projects()` orders by newest first, and a scenario that creates a project
  shifts the selection for later scenarios. Run mutating scenarios last.
- A failed action latches `last_error` until the next action; the loop clears it
  per action. Test an error followed by a success in the same session to cover
  the clearing behavior.
- Some work is asynchronous. Use generous timeouts for analysis and explore, and
  wait for a result string rather than a fixed sleep.
- The Windows build compiles the test to a stub that prints "skipped" because
  `forkpty` is unavailable.
