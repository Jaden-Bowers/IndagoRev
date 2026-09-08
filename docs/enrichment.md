# Bundled capability and string enrichment

The native static service exposes `capa/capabilities` and `floss/strings` through
the ordinary query, durable job, cancellation, evidence, index and scoped harness
paths. Upstream capa 9.4.0 and FLOSS 3.1.1 standalone workers are embedded in the
primary executable after `tools/bundle-enrichment.ps1` stages their pinned release
archives. No user-installed Python, pip environment or PATH executable is used.
These are upstream frozen builds, not IndagoRev source builds or rewritten engines.

```
indago query --project demo --backend capa --operation capabilities
indago query --project demo --backend capa --operation capabilities --format dotnet
indago query --project demo --backend floss --operation strings --mode static
indago query --project demo --backend floss --operation strings --mode decoded --address 0x140001000
```

capa accepts PE/ELF (magic-based default routing) and explicitly requested .NET.
The adapter fixes Vivisect or the built-in .NET extractor; it never auto-discovers
IDA/Binary Ninja/Ghidra installations, loads serialized analysis reports, accepts
custom rules/plugins or enables dynamic-report backends. A native-address function
restriction is optional. Upstream embedded rules and signatures remain unchanged.
Rule matches are **capability leads**, not proof a path executes or maliciousness.

FLOSS defaults to static strings; explicit modes are stack, tight, decoded and all.
Non-static modes use the upstream PE analysis/emulation path. Static extraction
also works on ELF bytes. Optional function restriction applies only to non-static
modes. `minimum_length` (4–256) is available in JSON action arguments. Automatic
Go/Rust/.NET language specialization is currently disabled. Emulation does not
execute the target image natively, but the parser/emulator is not a security sandbox.

Input is capped at 16 MiB, child wall time at 60 seconds or a lower requested
budget, child output at 4 MiB or a lower budget, and normalized summaries at 512
items or a lower item budget. Native JSON documents retain upstream metadata,
rules/matches and extraction categories. The outer evidence hash protects the
stored document; `upstream_stdout_sha256` separately records the observed output
stream hash, whose original whitespace is not retained. Timeouts, cancellation,
nonzero exits and incomplete JSON output produce explicit incomplete results,
not invented findings. A too-small output budget may retain only a diagnostic.

Normalized capa entities retain rule pointers and up to eight native match
locations, marking omissions. FLOSS static offsets use the `file` address space.
Stack/tight/decoded summaries may point to a native **emulated recovery site**;
this is never interpreted as the string's storage address or a live observation.
Language-specific and otherwise ambiguous locations stay in upstream evidence.
The raw document is not re-walked as if its internal layout were XAIR/Ghidra IR.
Use scoped index descriptors and evidence JSON-pointer paging for omitted details.

Packaging retains both project licenses and provenance. capa archive hashes match
GitHub release asset digests; FLOSS's older release has no published asset digest,
so its official HTTPS downloads are locally pinned. Transitive frozen-dependency
license reconciliation and reproducible source-build qualification remain release
gates. PyInstaller workers may use temporary extraction space; process cancellation
does not promise cleanup of every crash leftover. No OS memory quota or disposable
hostile-code lab is claimed.

Direct upstream checks and native import → enrichment → indexed evidence →
harness/reuse gates passed on Windows PE and Linux ELF using source-backed benign
fixtures. The .NET capa path passed on a compile-only managed fixture. FLOSS's
selected-decoder emulation recovered the expected marker from separately compiled
x86 and x64 PE fixtures, with linker-map-pinned decoder addresses and no target
execution. Windows native regressions passed 4/4 (7.09 seconds); Linux passed 5/5
(each under 60 seconds). Logs: `out/enrichment-harness-windows-checks.log`,
`out/enrichment-cli-linux-checks.log`, `out/enrichment-dotnet-windows-checks.log`,
`out/enrichment-decoded-windows-checks.log`, `out/enrichment-decoded-x86-windows-checks.log`.
These finite development checks do not establish general extraction completeness.
