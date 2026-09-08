# Saved-report citation audit

`indago harness audit --project PROJECT --id INVESTIGATION --limit 8 --offset 0`
reassesses a saved report against the current local evidence index. It is read-only,
does not need an owner token, and never changes the report or investigation revision.
Both owners can retrieve it through `harness read`, family `investigation`, operation
`audit`; a small limit such as 4 fits the controller's bounded read packet.

The audit checks every saved citation (at most 512 under the report contract),
then pages issues with `next_offset`. It detects missing/inconsistent metadata,
changed citation revisions/source hashes, superseded analysis heads, incomplete
results and a later Ghidra Program revision in the same persistent session—even
when the newer query used a different operation scope.

`citations_current` means the metadata checks found no issue, not that the answer
is true. `needs_review` means at least one citation needs attention. `not_reported`
means there is no saved report. Zero citations can be current vacuously; inspect
the report's gaps and `citations_checked`, not just this status.

The immutable report retains its original citation snapshot. `report_sha256`
identifies that snapshot. `source_bytes_verified:false` and
`semantic_entailment_checked:false` are explicit: this lightweight audit does not
rehash all backend payloads or prove that claims follow from them. Use normal
evidence retrieval for source integrity, then a new investigation/reanalysis for
updated conclusions. `verified_solve` remains false.

New reports now pin raw source hashes as well as backend revisions. Older reports
without a saved source hash still get revision/currency checks; the audit cannot
retroactively invent a historical hash pin. Answered reports also reject citations
from a Ghidra Program revision already known to have advanced at publication time.

This is local evidence bookkeeping, not a security boundary against an operator
editing the SQLite database. It does not grant runtime execution or model inference.

## Bounded development checks, 2026-09-07

Windows native checks passed 4/4 in 8.17 seconds
(`out/harness-audit-windows-checks.log`); Linux native checks passed 5/5 with
60-second individual deadlines (`out/harness-audit-linux-checks.log`). Coverage
includes unchanged saved reports, superseded analysis heads, the shared read
envelope and synthetic Ghidra Program revisions across operation scopes. The
Windows CLI revision/audit smoke passed in 1.51 seconds under a storage guard
(`out/qualification-harness-cb05d2215fc24caf800c2fd97189fa05/`). These are offline
controller/metadata tests, not live inference or complete Ghidra qualification.
