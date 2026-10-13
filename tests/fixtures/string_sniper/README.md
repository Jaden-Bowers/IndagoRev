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

| Target | Inspection purpose |
| --- | --- |
| `indago_sniper_network` | HTTP/HTTPS, uppercase URL matching, reserved IPv4 text, and an ordinary reference-only string. |
| `indago_sniper_credentials` | Credential keywords in multiple spellings and cases, with mixed-alphanumeric and ordinary controls. |
| `indago_sniper_paths` | Drive, UNC, Unix, registry, and relative paths, plus cmd.exe, PowerShell, sh, bash, and System32 markers. |
| `indago_sniper_ranking` | Twenty-four low-score strings before a high-score string combining indicators; inspect sorting with a small max_items and a sufficient scan_limit. Linkers may reorder data. |
| `indago_sniper_references` | Forty distinct functions directly reference one string; inspect total xref_count and the 32-entry xrefs cap after Ghidra analysis. |
| `indago_sniper_pagination` | Eighty equal-score URL strings plus a long string; inspect cursors, search, score filtering, and text truncation with a small output budget. |
