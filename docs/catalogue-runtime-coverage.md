# Task 7: catalogue-driven artifact and runtime coverage

Status: managed runtime/PDB and bounded artifact integrations implemented and
source-fixture tested; **not a completed all-format coverage contract**.
Linux managed/artifact parsing now uses the scoped namespace/cgroup profile in
[pre-task8-and-protection.md](pre-task8-and-protection.md). Older statements below
about absence of OS memory isolation describe the earlier Task 7 increment;
Windows remains a separate nonsandboxed parser profile.
The frozen 116-entry 2014–2024 catalogue is unchanged.
2025 remains held out. Nothing in this work executes archive challenges.

## Native interfaces

`indago benchmark coverage --request coverage.json`, where the request supplies
`catalogue`, verifies the frozen catalogue hash and emits member-to-family routes,
challenge IDs and parent container hashes. It explicitly distinguishes filename
hints from supported parsers. It does not extract archives, inspect solutions,
change the denominator or create execution authority.

`indago target route --project P --id TARGET_ID` probes at most 64 KiB of an imported
artifact, checks its artifact hash, and returns a bounded signature-based route.
The harness exposes this as `retrieve {family:artifact,operation:route,request:{}}`
within existing component scope. Misleading filenames cannot override recognized
PE/CLR, ELF, PDF, ZIP, DEX, WASM or capture signatures. A ZIP signature does not
prove an APK/JAR identity. Unsupported/truncated formats remain explicit.

Read source/scripts with scoped artifact pages and use existing bounded helpers for
validated transformations; do not execute source by selecting a filename suffix.
Managed embedded resources now expose exact file ranges and hashes for existing
artifact derivation, after which the child can be classified separately.

## Catalogue findings and adapter decisions

These are outer-container findings, not complete inspection of nested formats.
Bundled library files are not automatically independent entry points.

| Family / concrete catalogue evidence | Existing path | Additional work |
|---|---|---|
| PE/ELF and managed PE candidates | XAIR/Ghidra, ILSpy, native experiments | Confirm loader architecture and runtime per artifact; CLR/CoreCLR observation |
| PCAP/PCAPNG: eleven challenge identities | Offline Wireshark packet/stream evidence | Task-specific protocol and application-state reconstruction |
| APK: 2015 C6, 2017 C8, 2019 C3, 2023 ItsOnFire | Bounded archive preparation, native children through existing engines | DEX/Android resources adapter; add Android runtime only when static recovery needs it |
| JAR: 2018 C1 | Archive preparation and byte access | JVM bytecode/decompiler adapter; controlled JVM execution when demonstrated necessary |
| TPK: 2020 C5 | Archive preparation; inspect children for managed/native code | Assess actual package dependencies before installing a Tizen environment |
| HTML/JS: 2014 C2 and later web challenges | Source pages and bounded helper reconstruction | Script-aware parsing and controlled browser/JS execution, no host browser target execution |
| Python: 2020 C1, 2024 frog | Source pages and helpers | Controlled interpreter/library profiles only when reconstruction is insufficient |
| PDF 2014 C4; DOC 2016 C2; XLS 2020 C4 | Signature routing and artifact bytes | Bounded PDF/OLE/VBA/XLM extraction; active content remains unexecuted |
| WASM: 2018 C5 | Confirmed signature route | WASM disassembly/validation and bounded execution adapter |
| Verilog: 2024 bloke2 | Source pages, native solver/helper workspace | Pinned HDL simulator profile and bounded testbench execution |
| NES 2019 C8; Intel HEX 2017 C9; TAP/DSK 2023 kupo | Explicit unusual-format routes | Confirm machine/encoding and use dedicated ISA/emulator adapters; do not feed to x86 lifting |
| IMG/VM disks: 2018 C12, 2022 C10, 2023 mbransom, 2024 catbert | Raw artifacts and lineage | Filesystem extraction, firmware/machine profiles and selected whole-system execution |
| XNB and native libraries: 2023 X | ILSpy for managed assembly; raw resource bytes | XNB parsing and game/runtime dependency assessment, not a blanket game-engine environment |
| YARA: 2024 aray | Text plus bounded solver/helper reconstruction | Rule-to-constraint translation with validation |

The coverage report is deliberately `all_formats_supported:false`. A family hint
does not imply its challenge needs runtime; static extraction/reconstruction should
be attempted first. No Android image, game engine, legacy machine image or additional
interpreter was downloaded by this increment. The existing private .NET SDK/runtime
and existing Frida payload were reused.

## Managed implementation and tests

See [managed analysis](managed-analysis.md) for explicit dependency resolution,
generated source/IL mapping, assembly relationships, embedded resources and the
bounded Mono observation recipe.

`tests/task7_managed_contract.cjs` checks exact dependency resolution during actual
ILSpy decompilation, missing/bad/duplicate dependencies, generated source/IL spans
and resource hashes. The source fixture includes a throwing initializer so it must
remain static. `tests/task7_cli_contract.cjs` checks native import/routing,
dependency evidence, indexed destination-artifact relationships and frozen catalogue
coverage. `tests/task7_managed_recipe.cjs` simulates Frida accessor/invoke/JIT APIs;
it is not a live managed-runtime test.

Windows CLI evidence: `out/task7-cli-ZLAetq/summary.json`; direct worker evidence:
`out/task7-worker-final-tests.log` and `out/task7-worker-linux-final-tests.log`.
The final direct-worker checks include native cross-assembly MemberRef resolution.
The native CLI gate also checks rejection of out-of-investigation dependencies and
the scoped harness route endpoint. No benchmark score or solve claim is produced.
The final Linux CLI gate also passed: `out/task7-cli-mvcSaV/summary.json`.

Windows harness/controller/runtime-path regressions passed 3/3 (17.57 seconds),
knowledge passed separately, and the final controller/knowledge pair passed 2/2
(13.60 seconds). Linux harness/controller/knowledge passed 3/3 (21.31 seconds).
Tests have 90-second or smaller per-process limits, with disk-backed Linux TMPDIR.
The final Linux controller/knowledge pair passed 2/2 in 14.93 seconds.

## September 12 completion increment

- `ilspy/artifact`: ZIP inventory/member bytes, OLE structured streams, PDF pages and
  object inspection (including inert active-content dictionaries), UTF-8 source pages,
  and upstream WABT validation/disassembly. No script, macro, or document execution.
- `transform.run` with `spec:{method:container_member,entry:"literal name"}` imports
  a child with parent/content hashes and lineage. The harness requires its existing
  derived-artifact grant and reserves 1 MiB per extraction. Parent bound is 4 MiB;
  child bound 1 MiB; private worker deadline 5 seconds. Member names are not host paths.
- Ghidra's existing JVM and Dalvik loaders discovered and decompiled the source-built
  `Task7Bytecode` class and DEX. No competing bytecode semantic engine was added.
- `ilspy/decompile` and `assembly` accept an explicitly imported `arguments.pdb` ID.
  Portable-PDB SHA and PE debug GUID/stamp must match. Original document hashes,
  lines/columns and IL offsets are retained; source paths are never opened or fetched.
- `runtime io-run` and harness `experiment.run` with engine `io` support
  `managed_trace:true`. CoreCLR startup EventPipe emits native method, module,
  assembly and exception events. Trace bytes are imported and parsed through
  Microsoft TraceEvent; the existing trusted-target execution grant still applies.
  Trace handles/tokens remain trace-scoped observations, not certified loaded-file
  hashes. This does not attach to arbitrary processes or grant challenge acceptance.
- NuGet lockfile and archive pins cover every dependency. The managed payload ships
  upstream notices and WABT, prepared by `tools/build-ilspy.ps1`.

Evidence: Windows artifact gate `out/task7-artifacts-Wg7iHO`, Linux artifact gate
`out/task7-artifacts-ittRak`; JVM `out/task7-bytecode-YoaCC7`, DEX
`out/task7-bytecode-Yl5cyq`; Windows harness CoreCLR
`out/task7-harness-trace-6J8zED`, Linux CoreCLR `out/task7-runtime-ByZ4RG`.
Matching/mismatched/altered PDB tests passed on both worker platforms. Windows
controller/workbench regressions passed 2/2 in 13.92 seconds. Final affected
regressions passed Windows 2/2 (13.60 seconds) and Linux 2/2 (15.92 seconds):
`out/task7-windows-final-tests.log`, `out/task7-linux-final-tests.log`.
Final artifact gates (including harness-granted extraction) are
`out/task7-artifacts-OVgy3E` and `out/task7-artifacts-bVY7H7`; final Windows
harness trace gate is `out/task7-harness-trace-ainFGB`.

Read-only catalogue assessment: `out/task7-catalogue-8Tm9Yy/assessment.json`.
2018 C1 contains `InviteValidator.class`; 2019 C3 contains `classes.dex`, Android
resources and Kotlin metadata (inventory is explicitly paginated); 2020 C5 contains
`TKApp.dll`, Xamarin/Tizen assemblies and images. Parent/child hashes are preserved.
No answers were inspected and no challenge was executed. These findings support
static bytecode/managed extraction first, not installation of complete Android or
Tizen systems. The DEX fixture compiler was development-only Google R8 8.3.37,
archive SHA-256 `59753e70a74f918389cc87f1b7d66b5c0862932559167425708ded159e3de439`.

## Explicit remaining all-FLARE-On coverage gaps

The earlier table's additional-work column remains a research backlog, not a claim
that all its environments now work. Android binary resources, VBA/XLM execution,
HDL simulation, NES/legacy machine and disk adapters, XNB semantic decoding, and
target-specific interpreter/library profiles still require dedicated work when a
solve needs them. PDF streams are exposed in their original encoding with filter
metadata; this is not a universal embedded-program decoder. Generic/forwarded-type
and netmodule cases, live Mono and legacy .NET Framework observation, hostile parser
memory isolation and broad archive robustness remain qualification/coverage work.
The new workers have bounded input/output and parent-enforced deadlines, **not an
OS memory sandbox**. CoreCLR traces can be partial and diagnostics can be disabled;
missing events never establish absence. No all-challenge completion or new solve
score is claimed by this increment.
