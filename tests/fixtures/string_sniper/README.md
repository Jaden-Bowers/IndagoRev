# String sniper fixture binaries

Standalone C99 inputs for Ghidra `string_sniper` inspection. Building this project
only compiles and links executables; it registers no tests. Each executable's
entry point references its fixture strings through `puts`. No fixture performs
network requests, opens fixture paths, or executes embedded commands.

Build from the repository root (Windows builds produce PE; Linux builds produce ELF):

```sh
cmake -S tests/fixtures/string_sniper -B out/string-sniper-fixtures
cmake --build out/string-sniper-fixtures --config Debug
```

Generated binaries stay in the ignored `out/` directory. Import a binary into a
Ghidra-backed Indago project with standard analysis before querying its strings.
Ghidra string discovery, reference recovery, and address ordering depend on the
compiler and analysis profile; these are inspection inputs, not golden results.
Scores are additive heuristic leads. The default minimum score is 1, and even an
ordinary string can qualify because it has a native reference.

Each C source contains at least 70 nonblank code lines, excluding comments.
The fixtures contain distinct strings and direct native references for manual
inspection; no automated checks execute as part of building.

| Target | Code lines | Inspection purpose |
| --- | --- | --- |
| `indago_sniper_network` | 105 | HTTP/HTTPS variants, reserved IPv4 text, token boundaries, and controls including unsupported schemes and malformed addresses. |
| `indago_sniper_credentials` | 119 | Credential spellings across lowercase, uppercase, embedded words, URLs, quoted fields, and controls. |
| `indago_sniper_paths` | 105 | Forty Windows, Unix, registry, relative-path, and execution markers, including overlapping credential indicators. |
| `indago_sniper_ranking` | 116 | Twenty-four low-score strings, twelve medium-score URLs, and twelve high-score combined indicators; linker address ordering may vary. |
| `indago_sniper_references` | 91 | Forty distinct functions directly reference one string; inspect total reference counts and the 32-detail cap. |
| `indago_sniper_pagination` | 239 | Eighty equal-score URLs and a long string for pagination, search, score filtering, and text truncation. |

## Python harness

The standalone harness lives in `tests/string_sniper_harness.py`, with shared
support in `tests/string_sniper_support.py`. It uses only the Python standard
library and requires Python 3.10+, CMake 3.25+, and a native C compiler. Full mode
also requires an Indago executable built with the string sniper operation and
an available Ghidra/JDK installation. Configure `GHIDRA_HOME` or
`INDAGO_GHIDRA_HEADLESS`, or use an Indago build that bundles Ghidra.

Run from the repository root:

```sh
python3 tests/string_sniper_harness.py --indago /absolute/path/to/indago
```

This command builds the six binaries, **executes them**, imports each into its
own fresh project, and runs the full Ghidra suite. The harness was implemented
without running tests or fixture executables. Building the CMake fixture project
alone still does not run tests.

The default suite covers these finite domains:

| Area | Checks |
| --- | --- |
| Binary coverage | ELF/PE signatures, every declared NUL-terminated marker, exact stdout order and occurrence counts, exit code, and empty stderr. |
| Analysis baseline | Every fixture marker discovered, references recovered, artifact hashes, locations, metadata types, heuristic tags, and additive scores. Incidental compiler strings receive structural checks. |
| Score filters | Every integer threshold from 0 through 100 for every binary, default threshold 1, and CLI forwarding at 0, 1, 4, and 100. |
| Search | Every complete marker in original, upper, and lower case; marker prefixes; missing text; metadata-like words; and combined score/search filters. |
| Pagination | Full traversal at page sizes 1, 2, 3, 7, 16, 31, 32, 33, 64, 80, 81, and 128; stable order, offsets, revisions, membership, uniqueness, and termination. |
| Scan limits | Accepted candidate caps 1, 2, 3, 7, 16, 31, 32, 33, 64, and 100000; descending ranking and completeness flags. This measures the current accepted-finding cap, not the number of data items visited. |
| Cursors | Replay, changed page size, cross-artifact reuse, changed score/search/operation/collection/profile, stale revision, altered binding, invalid offsets, malformed encodings, and oversized cursors. |
| Request validation | Score types/ranges, budget types/ranges, scan bounds, unknown arguments and operations, and invalid profiles and collections; crashes do not count as successful rejection. |
| Output budgets | 4096, 8192, 16384, 32768, 65536, and 262144 bytes; output size, truncation, retained evidence, text prefixes, and preserved scores. |
| Specialized fixtures | Forty referencing functions with 32 returned details, low/medium/high ranking groups, and explicit long-string truncation. |
| Lifecycle | Close/reopen persistence and asynchronous cancellation. A job that completes before cancellation is accepted as a completion race, not proof that interruption occurred. |

The threshold domain and fixture marker set are exhaustive. Arbitrary inputs,
all possible option combinations, other compilers, and all Ghidra discoveries
are outside this finite suite. Ghidra must actually discover all fixture markers;
missing discovery or unavailable Ghidra fails the run rather than silently
skipping coverage. The full matrix issues thousands of native commands and can
take substantial time because every query publishes evidence.

To run the binary checks without Ghidra:

```sh
python3 tests/string_sniper_harness.py --mode binaries
```

To reuse existing binaries and select a smaller part of the matrix:

```sh
python3 tests/string_sniper_harness.py --indago /absolute/path/to/indago \
  --no-build --fixture pagination --phase pagination --phase budgets
```

`--fixture` and `--phase` may be repeated. Full mode always performs binary checks
and establishes an analysis baseline before selected phases. Supported phases
are `scores`, `search`, `pagination`, `cursors`, `validation`, `budgets`, and
`lifecycle`. Specialized reference/ranking checks run when their fixtures are
selected. `--fail-fast` stops the matrix after its first failed case while
preserving cleanup and reports.

Use `--build-dir`, `--config`, and `--report-dir` to change build configuration
and destinations. `--wall-ms` sets each Ghidra request's budget, while `--timeout`
sets the subprocess timeout in seconds and must exceed the request budget.
Each run creates a unique directory under `out/string-sniper-harness/` containing
`report.json`, request JSON, command stdout/stderr logs, and an isolated Indago
workspace. Reports include case outcomes, diagnostics, elapsed times, commands,
artifact SHA-256 values, and selected phases. Failed workspaces are retained for
inspection. Sessions are closed on exit; reports and evidence remain on disk.

Exit status is 0 when the selected checks pass, 1 for assertion failures, and 2
for infrastructure errors. A missing executable or Ghidra installation is an
infrastructure error. No existing user projects are reused.
