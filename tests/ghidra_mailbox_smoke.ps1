param([string]$Mailbox)
$ErrorActionPreference = 'Stop'
function Invoke-Request([string]$Operation, [string]$Address = '', [int]$MaxBytes = 2097152, [string]$Expected = '', [bool]$Cancel = $false) {
    $requestId = [guid]::NewGuid().ToString('N')
    $request = @{operation=$Operation;address=$Address;max_items=1000;max_output_bytes=$MaxBytes;timeout_ms=30000} | ConvertTo-Json -Compress
    if ($Cancel) {[IO.File]::WriteAllText((Join-Path $Mailbox "$requestId.cancel"),'cancel')}
    $temporary = Join-Path $Mailbox "$requestId.tmp"
    [IO.File]::WriteAllText($temporary,$request)
    Move-Item -LiteralPath $temporary -Destination (Join-Path $Mailbox "$requestId.request")
    $response = Join-Path $Mailbox "$requestId.response"
    $deadline = [DateTime]::UtcNow.AddSeconds(35)
    while (!(Test-Path -LiteralPath $response)) { if ([DateTime]::UtcNow -gt $deadline) {throw 'Worker response timeout'}; Start-Sleep -Milliseconds 25 }
    $result = Get-Content -Raw -LiteralPath $response | ConvertFrom-Json
    if ((Get-Item -LiteralPath $response).Length -gt $MaxBytes) {throw 'Output byte bound exceeded'}
    if ($Expected) {if ($result.status -ne $Expected) {throw "Expected $Expected, got $($result.status)"}}
    elseif ($result.status -notin @('completed','partial')) {throw ($result | ConvertTo-Json -Depth 12)}
    return $result
}
$bounded=Invoke-Request 'functions' '' 1024 'partial'
if (!$bounded.partial) {throw 'Bounded result missing partial flag'}
$failure=Invoke-Request 'decompile' '0x999' 2097152 'failed'
Write-Output 'Output bound and invalid-function failure passed'
$inventory=Invoke-Request 'functions'
$entry=$inventory.functions[0].entry
$workerPid=$inventory.session_pid
$cancelled=Invoke-Request 'decompile' $entry 2097152 'cancelled' $true
foreach ($operation in @('import','decompile','tokens','assembly','xrefs','types','variables','cfg')) {
    $result=Invoke-Request $operation $entry
    if ($result.session_pid -ne $workerPid) {throw 'Session was not reused'}
    if ($operation -eq 'tokens' -and $result.decompilation.tokens.Count -eq 0) {throw 'No pseudocode tokens'}
    if ($operation -eq 'cfg' -and $result.cfg.blocks.Count -eq 0) {throw 'No CFG blocks'}
    Write-Output "$operation : $($result.status), pid=$workerPid"
}
