$ErrorActionPreference = 'Stop'
$root = (Resolve-Path "$PSScriptRoot/..").Path
$lock = Get-Content "$root/config/toolchain.lock.json" -Raw | ConvertFrom-Json
function GitChecked([string[]]$Arguments) {
    & git @Arguments
    if ($LASTEXITCODE) { throw "Git failed: $Arguments" }
}
foreach ($item in @(
    @{ key='xair'; name='XAIR'; patch='xair-block-reopen.patch' },
    @{ key='xair_cfg'; name='XAIR_CFG'; patch='xair-cfg-parent.patch' },
    @{ key='xair_sym'; name='XAIR_SYM'; patch='xair-sym-parent.patch' }
)) {
    $component = $lock.components.($item.key)
    $destination = Join-Path $root $component.path
    if (Test-Path $destination) {
        throw "Existing checkout preserved: $destination. Inspect it manually; bootstrap only creates missing checkouts."
    }
    GitChecked @('clone', '--no-checkout', "https://github.com/Jaden-Bowers/$($item.name).git", $destination)
    GitChecked @('-C', $destination, 'checkout', '--detach', $component.revision)
    GitChecked @('-C', $destination, 'apply', '--unidiff-zero', "$root/components/patches/$($item.patch)")
}
