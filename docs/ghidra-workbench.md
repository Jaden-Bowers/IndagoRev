# Ghidra workbench

The C++ adapter owns a persistent Java `DecompInterface` worker. Ghidra's
Program database, decompiler, p-code and verdicts remain native to Ghidra,
not merged into XAIR IR. Queries produce immutable platform evidence.

## Private distribution

Stage Ghidra 12.1.2 and the platform's Temurin JDK (pins in
`config/toolchain.lock.json`), then build normally:

```powershell
./tools/bundle-ghidra.ps1 -Ghidra C:/path/ghidra_12.1.2_PUBLIC -Jdk C:/path/jdk
cmake --build out/build --config Release --target indago
```

On Linux use `bash tools/bundle-ghidra.sh /path/ghidra /path/jdk` before CMake.
The executable embeds distribution, scripts, Java and license notices. Bundled
builds need no runtime downloads, system Java or source-tree script paths.
Files extract into a SHA-256-verified private cache on use. Runtime commands
do not extract Ghidra. The full-distribution bundle is roughly 1.3–1.4 GB: one
distributable, not one process or an in-process Java-free decompiler.
The runtime bundle profile now omits foreign-platform native helpers and Java
runtime-construction modules when present; see [packaging](knowledge-workbench.md).

## Operations

Existing: `import`, `inspect`, `functions`, `decompile`, `tokens`, `assembly`,
`xrefs`, `calls`, `strings`, `imports`, `exports`, `types`, `variables`, `cfg`.
Added: `pcode`, `control_flow`, `analyze`, `session`, `flush`, `close`,
`annotate`, `annotations`. Function queries and annotations require `address`.

```powershell
indago query --project demo --backend ghidra --operation functions --max-items 32
indago query --project demo --backend ghidra --operation functions --cursor CURSOR --max-items 32
indago query --project demo --backend ghidra --operation pcode --address 0x140001000
```

Arguments include `search`, `collection`, `cursor`, `scan_limit` (CLI
`--scan-limit`) and profile `standard` or `inventory`. Continuation is returned
in `pagination.next_cursor`, bound to artifact/session, operation, address,
search, collection and program revision. Reuse these parameters when paging.
Default collections include `functions`, `decompilation/tokens`,
`pcode/operations`, `cfg/blocks`, `recovered/variables` and
`control_flow/indirect_flows`. Select `pcode/varnodes`, `cfg/edges` or
`control_flow/jump_tables` for those pages. Filtering scans at most 100,000
generated entries. Check partial status and `scan_may_be_incomplete` before
interpreting absence. Byte budgets can shorten pages; a zero-item budget
failure requires a larger budget.

`pcode` exports HighFunction operations, varnodes and def/use links. IDs are
scoped to function and program revision; partial pages may reference omitted
values. `tokens` provides exact UTF-16 offsets in `rendered_c`, line/column,
address ranges and symbol/type/p-code/varnode links. Offsets do not index the
separate original `decompiled_c` string.

`control_flow` exports computed-flow candidates, recovered switch tables,
calling convention and no-return metadata. Candidates are not exhaustive
proof. Bounded native exception/TLS and indirect-pointer recovery is implemented;
see [analysis depth](analysis-depth.md) for its exact coverage and remaining limits.

## Analysis and persistence

`standard` retains initial auto-analysis. `inventory` imports without it.
Use `analyze` with current `expected_revision` (CLI `--expected-revision`)
for bounded analysis, optionally seeded at an address. Profiles use separate
saved Programs: continue using the same profile. Existing action submission
can run analysis asynchronously.

Workers idle out after five minutes. `session` describes the worker, `flush`
invalidates the decompiler cache, and `close` saves and stops it. Reopening
uses the saved Program. Cache identity includes bytes, worker scripts,
engine identity, loader policy and profile. Dead startup-owner locks are
recoverable. Cancellation is cooperative per request; startup cancellation
terminates its process tree.
If an interrupted import left a project shell without the expected Program,
the adapter recognizes Ghidra's exact missing-Program startup error. A later
bounded query retries import into that project without `-overwrite`; existing
Programs and edits are not deliberately replaced. Successful readiness clears
the internal recovery marker. This repairs the demonstrated timeout → permanently
failed reopen loop without deleting the project or silently replaying a model call.
First-use extraction and platform persistence add overhead outside the worker
query budget; this is not a hard end-to-end latency guarantee.

Edits use `action run --request edit.json`:

```json
{
  "project": "demo", "backend": "ghidra", "operation": "annotate",
  "address": "0x140001000",
  "arguments": {
    "expected_revision": 0,
    "annotation": {"kind": "rename", "name": "decode_record"}
  }
}
```

Kinds: `rename` (`name`), `comment` (`text`), `signature` (`prototype`), and
`variable_type` (`symbol_id`, existing `type_path`). These are user assertions,
not inferred facts. Transactions increment Program revision, invalidate the
decompiler cache and save before success. Stale cursors/edits are rejected.
History is capped at 256 edits per Program. Bounded `create_structure` annotations
under `/IndagoUser` are supported as described in the runtime workbench record;
arbitrary datatype construction is not. Old immutable evidence is retained.
Requery changed views; dependent knowledge records track Program revisions.

`tests/ghidra_workbench_smoke.ps1` checks paging, native p-code, token spans,
persisted rename/reopen, stale cursors and inventory-to-analysis. The Linux
`.sh` companion checks basic p-code, tokens and saved-session reuse.
Production qualification remains deferred.
