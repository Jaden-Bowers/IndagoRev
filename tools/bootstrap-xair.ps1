$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot/..").Path
# Compatibility entry point: the pinned commits already contain the patches.
& git -C $root submodule update --init --recursive -- xair/XAIR xair/XAIR_CFG xair/XAIR_SYM
if ($LASTEXITCODE) { throw 'Submodule initialization failed; existing edits were not forced or reset.' }
