# Ghidra worker

See [the current workbench contract](../../docs/ghidra-workbench.md) for private
bundling, pagination, p-code, analysis controls and revisioned edits.

## Persistent native adapter

`query_ghidra` starts `IndagoSession.java` with an imported Ghidra Program and
one persistent `DecompInterface`. The mailbox is keyed by the target SHA-256
under the project store's workers directory. Subsequent native CLI processes
reuse that Java process for five minutes after the most recent request.

JSON operations: `import`, `inspect`, `functions`, `decompile`, `tokens`,
`assembly`, `xrefs`, `calls`, `strings`, `imports`, `exports`, `types`, `variables`, and `cfg`. Function operations take
an address. `max_items`, `max_output_bytes`, and `timeout_ms` bound requests.
Native decompiler verdicts and diagnostics are retained. Tokens preserve
native syntax class and address ranges; `rendered_offset`/`rendered_end` index
the `rendered_c` string in UTF-16 code units, not the separate original C source.

Cancellation files cancel the per-request Ghidra task monitor. A client timeout
also signals cancellation. Import uses Ghidra's analysis timeout; a cancellation
during startup terminates the startup process tree. The worker stays
alive for other queued clients after an individual request cancellation.

`tests/ghidra_mailbox_smoke.ps1 -Mailbox <active mailbox>` exercises all worker
operations and verifies that requests share the same session PID.

Bundled builds use private scripts and Java. Unbundled development builds
discover the script beside an installed `bin/../workers` tree,
then the development source tree. `INDAGO_GHIDRA_SCRIPTS` explicitly overrides
the script directory. Script and Ghidra-property hashes accompany results.
Function bodies preserve discontiguous inclusive ranges. Xrefs include incoming
references to interior addresses as well as outgoing references, with native
address spaces. Composite type fields and native string definitions are retained.
