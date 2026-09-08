# Bounded managed static analysis

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
pseudocode retains its token and raw evidence pointer; exact C# token-to-IL
mapping is not yet exposed and is explicitly marked incomplete. IL disassembly
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
assemblies. Its initial resolver returns unresolved for every dependency; affected
decompilation is partial. Explicit imported dependency resolution,
cross-assembly relationships, exact token maps and managed runtime observation
remain future work. No full managed-program understanding is claimed.

The backend uses normal durable static jobs, cancellation, indexed evidence and
scoped harness proposals. Live model inference remains unconfigured.

Initial verification: direct-worker checks passed on Windows/Linux, and the
Windows native import → methods → decompile → indexed evidence → harness/reuse
gate passed (`out/ilspy-cli-windows-checks.log`). Four Windows native regression
suites passed in 8.90 seconds. IL-reference mapping checks also passed against
source-built PE32/x86 and PE32+/x64 fixtures. The packaged IL view and scoped
evidence-page lookup now pass full native CLI/index/harness checks on both
platforms (`out/evidence-pages-cli-windows-checks.log` and
`out/ilspy-il-cli-linux-checks.log`). No fixture was executed as a target.
