# Repository and local development data

The main repository tracks authored source, tests, documentation, integration
patches, and vendored dependencies with their upstream notices. The two large
Frida static libraries use Git LFS: install Git LFS and run `git lfs pull` after
cloning. They are build inputs, not removable build output.

The independent XAIR checkouts are pinned in `config/toolchain.lock.json`.
On a fresh clone, run `pwsh tools/bootstrap-xair.ps1` to obtain those revisions
and apply the checked-in integration patches. Existing checkouts are never reset.
Other engine staging steps remain documented in README and `docs/`.

Local-only directories are deliberately retained and ignored:

- `out/`: builds, staged engines, test logs, and solve evidence.
- `.indago/` and `work/`: analysis state and working data.
- `flare-on-chals/`: challenge corpus and its independent upstream history.
- `ghidra/` and `xair/`: independent upstream development checkouts.

Do not run a blanket `git clean -fdx`: these directories contain expensive build
inputs and irreplaceable analysis history, not merely disposable caches.
This source commit is not a published executable release or license qualification.
