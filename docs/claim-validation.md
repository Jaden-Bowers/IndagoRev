# Explicit native claim checks

The harness can verify structured assertions against immutable backend evidence
before publishing a report. This is not a natural-language truth checker: prose
without a corresponding check remains unverified, and passing a check does not
prove that the surrounding explanation follows from it.

Read-only tool: `harness read` with `family: validation`, `operation: check`.
Its `request.checks` is an array of 1–8 checks. Each operand is a reference:

```json
{
  "operation": "sum",
  "operands": [
    {"evidence_id":"ev_ID","pointer":"/program/segments/0/va","raw_sha256":"HASH"},
    {"evidence_id":"ev_ID","pointer":"/program/segments/0/mem_size","raw_sha256":"HASH"}
  ],
  "expected": "0x402800"
}
```

Obtain real IDs, pointers and hashes from `evidence/read`; placeholders above are
not runnable. For base `0x401000` and size `6144`, the exclusive end is `0x402800`,
not `0x401800` as one live model response incorrectly calculated.

| Operation | Operands | Expected value |
| --- | --- | --- |
| `equal` | One scalar, e.g. native format or architecture | Exact JSON scalar |
| `sum` | Unsigned base, unsigned size | Exact unsigned sum, decimal or hexadecimal |
| `contains` | Base, size, address | Boolean membership in `[base, base + size)` |
| `bits` | One unsigned scalar, plus explicit `mask` field | Boolean: all mask bits are set |

Arithmetic/mask operands are checked unsigned 64-bit values. Negative numbers, floats, malformed
numbers, trailing text and addition/range overflow are rejected. Bit interpretation
belongs to the backend/caller: a successful mask test does not establish a universal
permission convention. Native semantics are not merged between producers.

Checks use the existing scope-checked, SHA-verified evidence reader. Required
snapshot pins must match. Operands must be complete scalars, at most 512 encoded
bytes; each native snapshot is bounded by the existing 16 MiB reader limit.
Missing, corrupt, partial-page or out-of-scope operands are errors, not passed
checks. A complete scalar from a partial analysis may be checked, but this does
not make that analysis complete. Source native status is retained in the receipt.

Report claims may include a `checks` array. Every referenced evidence ID must
also appear in that claim's citations. The report has a total limit of 16 checks.
Contradictions reject publication transactionally with actual/expected feedback;
the owner can revise the hypothesis or finish with explicit gaps. Passing receipts
are saved as `check_result`; absent checks are marked `not_checked`.
The ordinary citation audit still checks current metadata, not source bytes or
prose entailment. Receipts describe verification at publication time, not a new
live audit. All reports retain `verified_solve: false`.

Development tests cover exact labels, range arithmetic, exclusive ends, masks,
overflow, malformed values, stale hashes, cross-scope/uncited operands, tampering,
and rejection before any report is published. These are short regressions, not
production qualification.
