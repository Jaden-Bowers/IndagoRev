# Pi investigation frontend

Implementation plan and current boundary:

1. Pin Pi and provide a reproducible local-provider launcher: implemented.
2. Keep native identities/jobs/evidence inside a thin tool adapter: implemented.
3. Offer normal source/file/script/shell work alongside direct analysis tools:
   implemented. PowerShell uses Pi's built-in tool; WSL has an explicit adapter.
4. Reuse native knowledge for findings and receipts, inject bounded summaries and
   recent observations, retain Pi compaction and checkpoints: implemented.
5. Preserve the old controller and prepare matched plain/tools/knowledge trials:
   implemented. New challenge performance has not yet been measured.

The frontend is under `agent/`; the C/C++ core remains the authority for native
analysis, identity, evidence and runtime receipts. Pi owns the model conversation,
normal coding tools, streaming, session history and compaction. There is no required
planning patch or four-field proposal before ordinary analysis.

The adapter retains backend-native semantics and exposes complete result receipts
as ordinary readable files. Active program selection is explicit and survives
session restart. Native analysis receipts and optional model summaries are stored
in the existing knowledge database. Plain shell observations are persisted as
receipts with their uncertainty; they are not automatically promoted into verified
program facts. Summary dependencies use existing native freshness checks.

Knowledge mode currently uses bounded native summary lookup and recent tool
observations. It does not implement embedding retrieval or a second summarizing
model. Exact-repeat hints do not detect every semantically equivalent renamed
helper. More elaborate context selection should be justified by measured failures.

The initial frontend is a pinned Node/Pi distribution beside the native executable.
Single-file frontend packaging, additional provider configuration UX, Linux desktop
capture, vision-model qualification and broader environment qualification remain
separate work. The old controller and historical results are unchanged.

The subsequent [context engineering revision](context-engineering.md) supersedes
the initial summary-lookup and recent-observation injection described above. It
adds request manifests, focused retrieval, progressive tool discovery, native graph
neighborhoods, helper deadlines and bounded recovery.

See [setup and benchmark commands](../agent/README.md). Pi's integration contracts
are documented in its [SDK](https://pi.dev/docs/latest/sdk) and
[extension API](https://pi.dev/docs/latest/extensions).
