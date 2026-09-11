# Native static stage

See [static contracts and indexed identity](static-model.md) for schema validation,
job recovery, revision freshness and the indexed query surface.

Build with CMake as described in the root README, then verify:

```powershell
ctest --test-dir out/build -C Release --output-on-failure
powershell -NoProfile -File tests/static_gate.ps1
```

The integration gate requires Ghidra/JDK and tests fresh PE and ELF
through persisted evidence. AIRECE's implementation lives in `components/airece`
and is compiled into `indago.exe`, including XAIR_SYM and static Z3. No AIRECE
executable or `INDAGO_AIRECE` setting is used. Bundled builds contain private
Ghidra, Java and worker scripts; see [Ghidra workbench](ghidra-workbench.md).
Unbundled development builds accept `GHIDRA_HOME` or `INDAGO_GHIDRA_HEADLESS`.
Upstream XAIR has a Python build-time contract check, not a
Python application runtime.

## Query surface

| Backend | Operations |
| --- | --- |
| airece | inspect, functions, function, calls, xrefs, slice, path, flow, taint, evidence |
| xair | inventory, semantic, cfg |
| sym | solve_branch, source_to_sink, symbolic_slice, taint, path_condition |
| ghidra | import, inspect, functions, decompile, tokens, assembly, xrefs, calls, strings, imports, exports, types, variables, cfg, pcode, control_flow, analyze, session, flush, close, annotate, annotations |

AIRECE views: compact, agent, pseudocode, disassembly, json. XAIR semantic
results include decoded instructions, operations, SSA definitions/uses, flags,
memory effects and completeness. CFG includes functions, blocks, edges, calls,
indirect candidates, dominators/postdominators, loops and reachability.

```powershell
$cli = '.\out\build\Release\indago.exe'
& $cli project create --name demo
& $cli target import --project demo --file sample.exe
& $cli analyze --project demo
& $cli functions --project demo
& $cli query --project demo --backend ghidra --operation decompile --address 0x140001000
& $cli query --project demo --backend airece --operation slice --address 0x140001000
& $cli query --project demo --backend airece --operation flow --source 'value(v0)' --target 'reach@0x140001013'
& $cli evidence list --project demo
```

Addresses/selectors are examples: use the imported artifact's inventory.
Choose `--workspace DIR` to override `.indago`. `function show --project demo
--id fn_ID` returns independent backend views and attributed claims linked by
artifact/address. Backend-native relationships, verdicts and source mappings
remain in evidence; no unified supposedly authoritative IR is manufactured.

## Jobs and bounds

`action run --request action.json` is synchronous; `action submit` launches a
native background worker. Use `job list`, `job show --id job_ID` and `job cancel
--id job_ID`, each with `--project demo`.

```json
{
  "schema": "indago.action.v1",
  "project": "demo",
  "backend": "ghidra",
  "operation": "functions",
  "budget": {"wall_ms": 120000, "output_bytes": 2097152, "max_items": 2048},
  "arguments": {}
}
```

Optional `target_id` selects an import; `artifact_sha256` rejects stale requests.
Queries publish immutable revisions and evidence, including partial/failure and
cancellation results. Retrieve native payloads with `evidence show --id ev_ID`.
Exit codes: 0 completed, 3 partial, 130 cancelled, 1 failed, 2 invalid request.

JSON is implemented; protobuf is not. Ghidra sessions idle out after five minutes.
Symbolic slices are conservative dependency slices enriched with native findings,
not path-sensitive proofs. Unsupported semantics remain unknown. Memory budgets
are engine-specific, not a universal hard RSS limit. Windows is verified; POSIX
is not yet qualified. Existing dependency pin discrepancies remain documented in
`config/toolchain.lock.json`. The native primary binary is not a self-contained
single-file distribution of Ghidra. AIRECE runs in `indago __airece` internally
so cancellation can terminate the analysis process without a second executable.
Z3 is built from source (its pinned upstream commit is fetched unless
`XAIR_Z3_SOURCE_ROOT` points to an existing checkout).
