# Native executable-format metadata

The `lief` static backend links LIEF 1.0.0's C++ static library into `indago`.
No installed LIEF, Python, shared LIEF library, or paid extended service is used.
The private SDK is staged explicitly by `tools/bootstrap-lief.ps1`; normal CMake
configuration does not download anything. Windows uses the matching static CRT.
The SDKs are upstream builds, not locally reproduced builds.

Supported operations:

| Operation | Scope | Meaning |
| --- | --- | --- |
| `inventory` | PE/ELF | Native machine/class/header values, entrypoint and section count |
| `sections` | PE/ELF | Raw section fields, file range validity, native virtual-address space |
| `libraries` | PE/ELF | Declared imported library names; no dependency resolution |
| `resources` | PE | Native resource hierarchy, code page, size/hash and verified file location |
| `notes` | ELF | Native note type/name, description hash and small description bytes |

Example: `indago query --project sample --backend lief --operation resources`.
`indago analyze --project sample --backend lief` runs inventory, sections and
libraries through the same persisted action path. Format-specific operations
remain explicit queries. The default `analyze` preset remains the native
AIRECE/XAIR/Ghidra baseline; it does not run every optional adapter on every input.
Collections accept `--offset` and `--max-items`; JSON actions put offset in
`arguments.offset`. `page.next_offset` advances by actually delivered records,
including when output limits shorten a page. A page with remaining parsed records
is partial. Resource traversal is bounded at 65,536 nodes and depth 32; an exhausted
traversal explicitly reports `scan_complete: false` and is not resumable beyond
that traversal. A single oversized record returns a diagnostic, not a cursor loop.

PE resource data is not automatically extracted. LIEF's reported offset and data
are checked against the same input snapshot before receiving a `file` location.
The content hash/range can feed an explicitly granted `transform.slice`; publication
and admission still use the existing derived-artifact ledger. ELF NOBITS sections
are not given invented file-backed ranges. Note descriptions are byte strings, not
executed or interpreted as instructions. Invalid UTF-8 names retain hex bytes;
oversized names retain hashes and explicit omissions.

Each query uses a killable same-executable worker with an input snapshot capped at
16 MiB, output at 1 MiB, 128 records/page, and wall time at 60 seconds or the lower
request limit. Cancellation and descendant cleanup reuse the native process runner.
This is process isolation, **not** a hostile-code security sandbox or OS memory
quota. Parsing may allocate beyond input size. It performs no target execution,
signature trust verification, host dependency search, or network lookup.

`completed` means the requested page was produced, not that the executable is
valid or that LIEF recovered every malformed structure. Upstream can return a
partial parse without a completeness verdict; this uncertainty is retained in
every successful response. Signature parsing, relocations and unrequested rich
tables are disabled where the upstream parser supports that switch. LIEF metadata
does not replace XAIR semantics, Ghidra's Program, or ILSpy metadata identities.

Native records are persisted as evidence and indexed as section/resource/library/
format-note entities. Harness proposals use the same scoped action path. Source-
backed worker fixtures exercise PE resources, ELF notes, pagination and identity
failure without launching the target. Production malformed-input fuzzing,
reproducible builds and transitive-license reconciliation remain qualification work.

Upstream resource-offset implementation checked against
[LIEF 1.0.0 ResourceNode](https://github.com/lief-project/LIEF/blob/1.0.0/src/PE/ResourceNode.cpp).
