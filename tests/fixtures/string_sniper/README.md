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
