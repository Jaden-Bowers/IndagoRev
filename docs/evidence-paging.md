# Scoped evidence paging

`harness read` now supports `family: evidence`, `operation: read`. Unlike
`evidence/show`, this returns a navigable page instead of omitting a native result
that cannot fit in the 4 KiB controller packet. Both external and built-in owners
use the same implementation; no live inference is required.

```
{
  "project": "demo", "id": "inv_ID",
  "family": "evidence", "operation": "read",
  "request": {"id": "ev_ID", "pointer": "", "offset": 0, "limit": 8}
}
```

Pointers are standard JSON pointers relative to the **native result**, not the
evidence wrapper, filesystem or project. Object/array pages return child
descriptors and their pointers, with small scalar values inlined. Follow a child
pointer to read its value. Large keys that cannot fit the pointer bound are
explicitly omitted with a key hash; no shortened pointer is invented.

String reads return `text`, `total_bytes` and `next_offset` in UTF-8 **bytes**.
Pass `max_bytes` (4–2048, default 1024) and the returned `next_offset` to continue.
Offsets into a multibyte character are rejected. Text boundaries and JSON escapes
are preserved, and the emitted packet stays at most 4096 bytes. Strings may be
shorter than the requested window to meet that serialized size limit.

Each page retains the evidence ID, artifact hash, revision, producer, native
status and raw source hash. Supply the returned `raw_sha256` on later reads for an
explicit snapshot pin. Component scope is checked before opening the raw object;
the exact bounded byte snapshot is hashed before parsing. Invalid pins, corrupt
objects and missing pointers fail closed. Reading does not mutate evidence or
broaden investigation scope.

Limits are 16 MiB of raw JSON per read, a 1024-byte pointer, 16 collection items per
page and a 4 KiB response. Larger snapshots return an explicit omission and ask for
a narrower backend query. Parsing the bounded snapshot still allocates JSON
structures; this is not an OS memory quota or parser sandbox. `partial` describes
the selected value window; `native_status` independently retains backend
completeness. Object pages are descriptors, not a claim that all child payloads
were included. A verified excerpt does not prove a claim's semantic correctness.

## Finding native evidence through the index

The same harness read path supports `family: index` and operations `entities`,
`relations`, `claims`, `revisions`. The selected investigation component always
supplies the artifact filter; queries cannot expand it. Existing index filters
such as backend, kind, name, revision, anchor and ID are available, along with
offset and limit (default four, maximum sixteen).

Responses are bounded descriptors: IDs, producer/revision/freshness, normalized
locations and native evidence pointers. Large names/IDs/pointers are explicitly
omitted with hashes, never silently clipped. Native payloads and claim values
are not inlined. Follow `evidence_id` and `json_pointer` with `evidence/read` to
verify/read source data. Index projections label `source_verified: false`; their
metadata is not a substitute for verifying the native evidence snapshot. Packet
size may reduce the item count and `next_offset` advances by the rows delivered.

New index rows/revisions also carry `source_status`, `source_result_incomplete`
and `projection_partial`. `partial` is their conservative union: a completely
indexed partial worker result is still partial source evidence. Publication status
comes from the saved evidence envelope, not a guessed backend-native status word.
Failed retries remain historical and do not advance a usable analysis head.
Reindexing preserves this rule and updates older derived rows; raw evidence and
its native verdict are unchanged. These fields concern the returned result and
index projection, not completeness of program understanding or capture coverage.
