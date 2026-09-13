# Bounded managed static and runtime analysis

Task 7 additions: explicit imported portable PDB mappings (`arguments.pdb`),
CoreCLR startup EventPipe through `managed_trace:true` on trusted I/O experiments,
and `ilspy/artifact` for bounded ZIP/OLE/PDF/source/WASM inspection. See
[catalogue coverage](catalogue-runtime-coverage.md) for limits and fixture evidence.
PDB documents are metadata only: no source paths or SourceLink URLs are accessed.
Runtime module handles and method tokens are trace-scoped, not automatically
certified static module identities. Live CoreCLR gates pass on Windows and Linux;
the Mono hook contract remains a mocked API test rather than live qualification.

The native CLI now supports the `ilspy` backend through a privately bundled,
self-contained worker using the unmodified ICSharpCode.Decompiler 11.0.0.9375
library. The application remains C++20; the managed worker and .NET 10.0.11 runtime
are embedded resources, extracted and SHA-256 verified on first use. A system
ILSpy installation, SDK or .NET runtime is not required to run this backend.
Build preparation is explicit (`tools/bootstrap-managed-sdk.ps1`, then
`tools/build-ilspy.ps1`); normal product execution does not download dependencies.
The SDK, package lock and upstream licenses are recorded alongside the worker.
The build also checks exact archive SHA-512 pins for ILSpy and both runtime packs
in `workers/ilspy/dependency-hashes.json`. NuGet's locked content hash and the
signed `.nupkg` archive hash are deliberately distinct: signature metadata changes
the archive hash. See [NuGet's metadata design](https://github.com/NuGet/Home/wiki/Nupkg-Metadata-File).

After `target import`, use:

```
indago query --project demo --backend ilspy --operation inventory
indago query --project demo --backend ilspy --operation types --max-items 32
indago query --project demo --backend ilspy --operation methods --offset 0 --max-items 32
indago query --project demo --backend ilspy --operation decompile --address 0x06000002
indago query --project demo --backend ilspy --operation assembly --address 0x06000002
indago index entities --project demo --backend ilspy --kind managed_method
```

Here `--address` selects a MethodDef **metadata token**, not a VA or RVA. Indexed
locations use the artifact hash and `managed_metadata` address space. Managed
methods do not enter the native `functions` identity table. Selected-method
pseudocode retains its token and raw evidence pointer. `source_il_mappings` now
exposes upstream ILSpy generated sequence points, with method tokens, half-open IL
intervals and 1-based UTF-16 line/column coordinates in the returned C# text. These
are generated-source spans, not original PDB source or a complete token bijection.
IL disassembly
uses upstream ILSpy and retains bounded reference callbacks: exact UTF-16 spans
in the returned assembly string, metadata references and method-scoped IL offsets
(`managed_il:0x06000002`). These are not machine addresses, C# token mappings or
proof of semantic completeness. Native semantics
and partial decompiler outcomes remain separate from Ghidra/XAIR views.

Limits: input snapshot 16 MiB, method body 16 KiB IL, page 128 rows, offset
1,000,000, output 1 MiB, wall time 60 seconds (or a lower requested budget).
Metadata names are capped at 512 UTF-16 code units; raw artifact evidence remains
available. A bounded text writer stops large pseudocode rendering. The parent
process runner provides timeout/cancellation and descendant cleanup. This is
process isolation, **not** a hostile-code sandbox or OS-enforced memory quota.

The worker never executes target assemblies, runs their initializers, loads their
resources as programs, or searches the GAC/host directories/network for referenced
assemblies. Supply `arguments.dependencies` as up to eight explicitly imported
target IDs (16 MiB each, 32 MiB aggregate). The native store verifies each artifact;
the worker snapshots and rechecks SHA-256 and resolves exact assembly identity
(name, version, culture, public-key token). Duplicate identities fail closed.
Unprovided framework dependencies remain unresolved; no version fallback, GAC,
network or host-directory search is used. Harness dependencies must belong to the
investigation's component scope. Dependencies may resolve each other within this
explicit set; multi-module netmodule resolution is not implemented.

`references` exposes AssemblyRef tokens and resolved artifact hashes. Indexing adds
`managed_assembly_dependency` relationships into the destination's managed metadata
address space, without treating tokens as native addresses. This is assembly-level
resolution. `member_refs` additionally uses upstream ILSpy metadata resolution for
MemberRef signatures (not name-only matching) and indexes destination artifact/token
relationships as `managed_member_reference`. Unresolved entities remain explicit;
exhaustive forwarded-type/generic/netmodule coverage is not claimed.
`resources` lists ManifestResource tokens, and for embedded resources validates
the backing file range and records its SHA-256. Use the existing scoped artifact
derivation operation to materialize that range; the worker does not execute it.

Frida `recipe:managed` provides bounded Mono exported `mono_runtime_invoke` and
`mono_compile_method` enter/leave/JIT-result observations, names/tokens when accessor
exports exist, and invoke exception presence. Method handles are session identities,
not globally stable tokens or proven assembly mappings. It does not collect managed
object contents, every managed call, CLR/CoreCLR events or Android Java events.
The new recipe has a simulated API contract test, not a live Mono qualification.
No full managed-program understanding is claimed.

Use `indago action run --request FILE` for dependency-bearing queries, for example:

```json
{"project":"demo","target_id":"tgt_APP_ID","backend":"ilspy",
 "operation":"member_refs","arguments":{"dependencies":["tgt_LIBRARY_ID"]}}
```

Replace the placeholders with imported IDs. Select the application explicitly:
importing a dependency changes the project's latest target. Standard-library
assemblies must also be imported if their resolution is required.

The backend uses normal durable static jobs, cancellation, indexed evidence and
scoped harness proposals. No live model inference is required for these checks.

Initial verification: direct-worker checks passed on Windows/Linux, and the
Windows native import → methods → decompile → indexed evidence → harness/reuse
gate passed (`out/ilspy-cli-windows-checks.log`). Four Windows native regression
suites passed in 8.90 seconds. IL-reference mapping checks also passed against
source-built PE32/x86 and PE32+/x64 fixtures. The packaged IL view and scoped
evidence-page lookup now pass full native CLI/index/harness checks on both
platforms (`out/evidence-pages-cli-windows-checks.log` and
`out/ilspy-il-cli-linux-checks.log`). No fixture was executed as a target.
