# Repository layout

- `src/`, `include/`: native platform and CLI.
- `components/airece/`: AIRECE source integrated into the executable, not an
  external application dependency.
- `xair/XAIR`, `xair/XAIR_CFG`, `xair/XAIR_SYM`: pinned Git submodules from
  Jaden-Bowers repositories. Their commits include the required integration
  changes; do not apply the old patches a second time.
- `vendor/`: third-party source snapshots, SDK inputs, and upstream notices.
  These are intentionally not blanket-converted to unreviewed upstream HEADs.
- `workers/`: authored adapters and embedded-worker entry points.
- `contracts/`, `config/`, `tests/`, `docs/`, `tools/`: schemas, pins,
  bounded diagnostics, documentation, and build/staging utilities.

## Dependency updates

```sh
git submodule update --init --recursive
git submodule status
```

The superproject gitlinks are the checkout authority.
`config/toolchain.lock.json` records matching revisions and component provenance.
Integration branches live in the owned engine repositories; existing upstream
default branches are not force-pushed or rewritten.

To update an engine, commit and push its changes first, then update the parent
gitlink and toolchain lock together and run the native build checks. Never use
`git submodule update --remote` as a reproducible build step.
`tools/bootstrap-xair.ps1` is a compatibility wrapper for submodule initialization.
Historical patches in `components/patches/` remain provenance records only.

Frida's two large static development libraries remain Git LFS objects, not normal
Git blobs. Use `git lfs install` and `git lfs pull` before building its worker.
Native-core builds do not link those libraries. No Git history was rewritten to
remove older source snapshots.

## Local data

`out/`, `.indago/`, `work/`, `flare-on-chals/`, and `ghidra/` remain ignored.
They contain builds, engine staging, private analysis, or independent checkouts.
They are not needed for the native presets and are not shipped by a clone.
The private inference profiles and challenge corpus are not published.

**Do not run `git clean -fdx` as a cleanup shortcut.** Local staged engines and
analysis history may be expensive or impossible to reconstruct.
