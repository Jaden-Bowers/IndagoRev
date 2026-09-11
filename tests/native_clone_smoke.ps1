param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path $Executable).Path
$root = (Resolve-Path "$PSScriptRoot/..").Path
$workspace = Join-Path $root ('out/clone-smoke-' + [guid]::NewGuid().ToString('N'))
function Invoke-Native([string[]]$Arguments) {
    $raw = & $Executable --workspace $workspace @Arguments
    $code = $LASTEXITCODE
    if ($code -notin @(0,3)) { throw "Native clone smoke failed: $Arguments : $raw" }
    $result = $raw | ConvertFrom-Json
    # This fixture intentionally includes an unresolved indirect call. Preserve
    # its partial verdict, but never accept timeouts or empty/truncated results.
    if ($code -eq 3) {
        $nativePartial = ($result.backend -eq 'xair' -and $result.data.native_status -eq 'ok') -or
            ($result.backend -eq 'airece' -and $result.data.native_exit_code -eq 3 -and
             $result.data.native_output -match '^fn 0x140001000 ' -and $result.data.locations.Count -gt 0)
        if ($result.status -ne 'partial' -or !$nativePartial -or $result.data.truncated) {
            throw "Unexpected partial result: $raw"
        }
    }
    return $result
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
    if ($operation -eq 'cfg' -and (!$result.data.blocks.Count -or !$result.data.edges.Count)) {
        throw 'CFG contains no blocks/edges'
    }
}
$result = Invoke-Native @('query','--project','clone-smoke','--backend','airece',
    '--operation','function','--address','0x140001000','--timeout-ms','30000')
if (!$result.evidence_ids.Count) { throw 'No persisted AIRECE evidence' }
Write-Output "Native clone smoke passed; target was not executed. Evidence: $workspace"
