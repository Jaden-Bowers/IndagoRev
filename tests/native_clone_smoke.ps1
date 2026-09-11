param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path $Executable).Path
$root = (Resolve-Path "$PSScriptRoot/..").Path
$workspace = Join-Path $root ('out/clone-smoke-' + [guid]::NewGuid().ToString('N'))
function Invoke-Native([string[]]$Arguments) {
    $raw = & $Executable --workspace $workspace @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Native clone smoke failed: $Arguments : $raw" }
    return ($raw | ConvertFrom-Json)
}
$null = Invoke-Native @('version')
$null = Invoke-Native @('capabilities')
$null = Invoke-Native @('project','create','--name','clone-smoke')
$null = Invoke-Native @('target','import','--project','clone-smoke','--file',
    "$root/xair/XAIR/tests/corpus/phase3/control-flow.pe64")
foreach ($operation in @('inventory','cfg','semantic')) {
    $result = Invoke-Native @('query','--project','clone-smoke','--backend','xair',
        '--operation',$operation,'--address','0x140001000','--timeout-ms','30000')
    if (!$result.evidence_ids.Count) { throw "No persisted evidence for $operation" }
}
$result = Invoke-Native @('query','--project','clone-smoke','--backend','airece',
    '--operation','function','--address','0x140001000','--timeout-ms','30000')
if (!$result.evidence_ids.Count) { throw 'No persisted AIRECE evidence' }
Write-Output "Native clone smoke passed; target was not executed. Evidence: $workspace"
