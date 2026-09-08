# Avoiding unchanged payload rebuilds

Bundle generation still discovers all configured workers, hashes every included
payload and retains the same dependency tracking and bundle identity. A small
CMake helper now writes generated metadata, resource and assembly inputs only when
their literal contents change. Reconfiguration no longer changes their timestamps
just because a schema, test or unrelated source configuration changed.

This prevents unnecessary embedded-payload recompilation/relinking; it is not
payload removal, a hash-cache shortcut or an executable-size reduction. Full
footprint/performance optimization still follows harness completion. Large WSL
directory scans and configure-time hashing over the mounted Windows tree remain.
CMake's documentation also recommends content-stable generation for build inputs.
[CMake file-writing documentation](https://cmake.org/cmake/help/latest/command/file.html#writing).

Development checks on 2026-09-07:

- The tiny CMake fixture passed on Windows and Linux: exact literal bytes,
  unchanged timestamps and changed-content invalidation, including template-like
  tokens, semicolons and quotes. Each run took about one second.
- A full Windows reconfigure preserved hashes and timestamps of all three
  generated bundle files (8.08 seconds).
- A full Linux reconfigure preserved hashes and timestamps of all three files
  (251 seconds, 480-second watchdog): `out/stable-generation-linux-checks.log`.

The checks did not copy or delete engine payloads. The measured Windows executable
at this checkpoint was 1,313,508,864 bytes; no size reduction is claimed here.

The following Frida update exposed a Linux dependency bug: unchanged `.incbin`
source text left old payload bytes in its object while the manifest hash advanced.
The generated assembly now explicitly depends on every included payload file via
`OBJECT_DEPENDS`; content-stable source generation alone is insufficient. A tiny
same-path, same-length payload replacement regression passes, and the repaired
full build rebuilt `engines.S.o`. The embedded Frida smoke and all six bounded
Linux CLI suites subsequently passed (`out/payload-dependency-linux-frida-checks.log`
and `out/harness-cli-paging-linux-checks.log`). Failed extraction temporaries are
also removed by an RAII guard; preexisting cache files were not deleted.

## Group-local extraction identity

The private extraction cache now keys each requested group (`runtime`, `ghidra`,
`ilspy`, `enrichment`, `network`) by its own canonical name/hash manifest. Changing capa, for
example, no longer invalidates unchanged Ghidra or ILSpy cache paths. The complete
embedded manifest and per-file hash verification remain unchanged; this is not a
tool removal or a hash-cache shortcut. Unknown/unavailable groups fail explicitly.
The tiny identity fixture passes on Windows and Linux, including reorder stability,
cross-group independence, changed-name/content invalidation and duplicate rejection.

New group paths live under `engines/groups-v1`. Existing legacy caches are left
untouched and are not silently trusted or deleted. The first use of each group
may therefore require one additional extraction; subsequent unrelated tool updates
reuse that group. This is a forward-looking footprint improvement, not a claim
that old disk usage was reclaimed. Core cache code also checks nested extraction
parents for symlinks/reparse points before and after directory creation. These
checks are not a security boundary against concurrent same-user filesystem races.

`indago runtime payloads` reports the embedded file count/byte total, group manifest
hash and group cache path without extracting or scanning the cache. It separates
embedded worker bytes from native executable code and does not mislabel this as
total installed/build/legacy-cache disk usage. Use it to budget a first extraction.
Lossless [payload compression](payload-compression.md) now separates stored and
expanded sizes while retaining raw group identities and post-extraction hashing.

## Bounded Linux native-test artifacts

`tests/run_linux_model_checks.sh BUILD [TEST ...]` can select named native tests.
Because a Linux test may statically link the complete embedded payload, the runner
reserves the main executable's size plus 256 MiB rather than assuming a small test
binary. It checks the C: 20 GiB floor and temporary-filesystem free space. Only one
new test executable is kept at a time; its SHA-256 and logs remain after that
generated copy is removed, including cleanup on failure. Source, main executable,
bundled engines and preexisting caches are untouched. This is a development
artifact-retention improvement, not a product feature removal or an OS disk quota.
