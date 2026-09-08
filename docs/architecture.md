# Native static and runtime architecture

The C++20 `indago` executable is the transport-neutral shared core and CLI. It
is the only writer of project metadata. Future gRPC, GUI, and MCP frontends will
call the same native domain layer rather than reimplement project logic.

Targets are copied into a SHA-256 content store before analysis. A target row
links a project to that immutable content. Every analysis creates a revision and
a durable job record. Backend adapters run out of process and return a common
result envelope. Raw exports are separately content-addressed, while normalized
function/string entities and evidence references are transactional SQLite rows.

```text
indago.exe -> ProjectStore (transactional SQLite + immutable content store)
          \-> same-binary AIRECE/XAIR/XAIR_CFG/XAIR_SYM workers
          \-> native Ghidra adapter -> installed Ghidra engine
          \-> same-binary runtime owner -> embedded DbgEng / private GDB/MI
          \-> same-binary instrumentation owner -> embedded DynamoRIO host/client
```

Backend facts are intentionally not collapsed. The same address may have one
AIRECE entity and one Ghidra entity, each tied to its producer revision. This is
the first piece of the plan's thin semantic interchange and preserves future
disagreement analysis.

## Current behavior and limits

Runtime sessions use a separate versioned SQLite queue/observation store and link
file locations to existing static anchors without merging observed and derived
evidence. See [runtime architecture and CLI](runtime-stage.md). Targets execute
only after explicit launch/attach/instrument; host execution is not an isolation boundary.
DbgEng calls stay on a dedicated owner thread with a real event wait; only its
documented SetInterrupt API crosses threads. Instrumentation uses source-built,
architecture-matched deployment helpers, not drrun or a second debugger. Payloads
are embedded in the primary executable and extracted by content hash.

- Jobs support synchronous or asynchronous execution, exclusive leases,
  idempotency keys, append-only events and explicit expired-worker recovery.
- Ghidra uses persistent Program/DecompInterface sessions with cancellable requests.
- Only native-file import is implemented; archive expansion is not.
- Indexed discoveries, relations and attributed claims are revision-scoped.
  Location anchors link backend views without asserting equivalent semantics.
- SQLite schema version 4 upgrades earlier workspaces without deleting raw
  evidence. Run `index rebuild --project NAME` to backfill old evidence.
- Bundled action/result/evidence schemas are embedded in the executable and
  validated at the service boundary. JSON transport is implemented, not protobuf.
- The toolchain lock is observational and unqualified until dependency pins are
  reconciled and clean Windows/Linux qualification reports exist.
