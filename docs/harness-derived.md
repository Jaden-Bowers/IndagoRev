# Harness derived artifacts

The external and built-in harness can publish outputs of existing native byte
transforms, admit verified outputs into investigation scope, then use ordinary
static analysis and finite validators on them. This is not arbitrary code
execution, a new semantic engine, or permission to import unrelated files.

## Explicit grant and action

Include both fields at `harness create`:

```json
{
  "workbench_mutations": true,
  "derived_artifacts": {"max_artifacts": 4, "max_bytes": 1048576}
}
```

Omission disables publication, including for saved investigations predating this
increment. A supplied grant must be positive; defaults within the object are four
artifacts and 1 MiB. Caps are 16 artifacts, 16 MiB total reserved bytes, and 32
components including declared roots plus potential derived entries. Neither a
model decision nor a checkpoint can alter the grant.

An ordinary proposal can contain this nested request:

```json
{
  "backend": "workbench",
  "operation": "transform.run",
  "target_id": "tgt_SCOPED_PARENT",
  "arguments": {
    "offset": 2,
    "size": 1024,
    "spec": {"method": "slice"},
    "title": "Candidate embedded executable",
    "assumptions": ["Header boundary is a hypothesis, not a behavioral proof"]
  }
}
```

The parent defaults to the pinned primary when no component selector is supplied.
`artifact_sha256` can also select a scoped parent. `arguments.artifact`, if present,
must match it. Reused methods are `slice`, `xor` with `key_hex`, `hex_decode`, and
`base64_decode`; no unreviewed future transform automatically inherits permission.
Parents are at most 4 MiB, selected ranges at most 1 MiB. Omitting `size` means the
remaining bytes, but fails if that exceeds 1 MiB. All admitted methods preserve or
shrink byte count.

Each proposal conservatively reserves one artifact and the input range size,
alongside the existing fixed mutation reservation. Reusing the same proposal key
does not reserve again. Failed, interrupted, shrinking or deduplicated operations
do not refund reservations. These are logical work/output bounds, not a hard disk
quota; database/index overhead and other workspace writers are not charged as
derived bytes. Keep the development free-space guard enabled.

## Identity, admission and recovery

The transform engine persists content-addressed output, native transformation
lineage and a knowledge record. The harness receipt retains target/hash, parent
hash, byte count, knowledge ID and mapping. Before admission, the harness verifies
the receipt against the scoped request, the imported target's content identity
and the reserved size. The admission entry and completed action receipt are saved
together in the investigation settlement transaction.

Only `derived_artifact.admitted: true` authorizes subsequent analysis of the
returned component. The root `scope.components` and its `scope.sha256` remain
immutable; that fingerprint identifies the roots, not the full evolving ledger.
`derived_components` records parent, admitting action and knowledge identity.
`harness scope`, scoped retrieval and final reproducibility components include
both roots and admitted entries. The primary remains unchanged even if the
underlying project selects a newly imported target.

An output may deduplicate to an existing project artifact. It can be admitted only
because this authorized transform produced the same bytes, not merely because
the artifact was discovered elsewhere in the project. Already scoped hashes do
not create duplicate admission entries. Deriving from a previously admitted
component is allowed within the same shared limits.

Cancellation before dispatch prevents execution. A running native child is killable;
if it published before cancellation wins at settlement, the output/receipt is
retained without admission. A failed identity/admission check returns a partial
receipt with an explicit diagnostic, not an analysis grant.

A crash after the final knowledge publication can now recover the exact committed
revision through its transactional action pointer, then recheck admission without
repeating the transform. A crash earlier in staging/import can still leave an
unadmitted output without that pointer; it remains `interrupted`/`outcome_unknown`
and cannot auto-replay. A new key cannot replay an identical uncertain mutation.
See [native workers, exact recovery and remaining limits](harness-workers.md).

Portable bundle import retains historical derived entries but resets new derived
artifact grants to zero and disables workbench mutations. Imported history is not
portable publication or execution authority.

## Scientific limits

Byte provenance does not imply instruction identity, successful unpacking,
behavioral equivalence or independently verified challenge completion. Reanalysis
retains backend-native evidence, and finite validators retain counterexamples.
Caller-supplied expected bytes are not an independent oracle. Reports still use
`verified_solve: false`; no live model inference is configured by this increment.

## Bounded development verification, 2026-09-07

- Windows native harness/model/knowledge: 3/3 passed in 8.58 seconds, each with a
  60-second deadline (`out/harness-derived-windows-checks.log`).
- Windows CLI harness: passed in 1.65 seconds under a 60-second watchdog and the
  free-space/scratch guard (`out/qualification-harness-549fe3d46185407e96078076464b3805/`).
- Linux native HTTP/model/harness/knowledge: 4/4 passed, each test bounded to
  60 seconds, with a 240-second outer compilation/test watchdog
  (`out/harness-derived-linux-checks.log`).
- Linux CLI knowledge, PE/ELF32/ELF64 harness and source-backed runtime regression:
  6/6 passed under a 120-second outer watchdog (`out/harness-derived-linux-cli-checks.log`).

Tests cover explicit grants, range/count/byte rejection, conservative reservations,
idempotent receipt reuse, scoped lineage, content deduplication, unscoped-parent
refusal, interrupted-transform non-replay and portable grant stripping. A scripted
controller extracts a wrapped benign PE, admits the existing content-addressed PE
only through its derivation receipt, obtains native XAIR inventory, receives a
negative comparison and corrects the finite expectation. CLI checks publish and
admit one byte without changing roots. Both native builds succeeded. Approximately
45.3 GiB remained free on C:; no corpus extraction, live inference, hostile sample
execution or large benchmark was performed. These checks are not production or
universal-challenge qualification.
