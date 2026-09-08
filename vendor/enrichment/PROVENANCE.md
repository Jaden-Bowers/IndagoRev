# Upstream enrichment workers

capa 9.4.0 and FLOSS 3.1.1 are the official Mandiant standalone release builds,
not source-built or reimplemented by IndagoRev. They embed their upstream Python
runtime and dependencies with PyInstaller; a user Python installation is not used.
IndagoRev's adapter, job control and evidence indexing remain native C++.

Pinned archive URLs and SHA-256 values are in releases.json. capa's digests match
the publisher's GitHub release asset metadata. FLOSS's older release supplies no
asset digest: its HTTPS-downloaded archives are locally pinned, not independently
publisher-authenticated by those local hashes.

Source and upstream build specifications:

- https://github.com/mandiant/capa/tree/v9.4.0
- https://github.com/mandiant/capa/blob/v9.4.0/.github/pyinstaller/pyinstaller.spec
- https://github.com/mandiant/flare-floss/tree/v3.1.1
- https://github.com/mandiant/flare-floss/blob/v3.1.1/.github/pyinstaller/floss.spec

Both upstream projects use Apache-2.0; their license files accompany the workers.
Full transitive frozen-dependency license reconciliation and reproducible
source-build qualification remain release gates. Do not describe these packaged
workers as fully distribution-qualified merely because development checks pass.

The adapter must select only built-in, offline static backends. It must not auto
discover proprietary host decompilers, load external analysis reports/plugins,
execute targets on the host, or treat capability matches as proof of behavior.
FLOSS emulation is upstream analysis, not native execution of the target image.
