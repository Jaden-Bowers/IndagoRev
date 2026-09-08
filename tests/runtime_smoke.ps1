param(
    [string]$Executable = "$PSScriptRoot/../out/build/Release/indago.exe",
    [string]$Fixture = "$PSScriptRoot/../out/build/Release/indago_runtime_fixture.exe"
)
$ErrorActionPreference = 'Stop'
$Executable = (Resolve-Path $Executable).Path
$Fixture = (Resolve-Path $Fixture).Path
$workspace = Join-Path ([IO.Path]::GetTempPath()) ('indago-runtime-' + [guid]::NewGuid().ToString('N'))
function Invoke-Indago([string[]]$Command) {
    $raw = & $Executable --workspace $workspace @Command
    if ($LASTEXITCODE -notin @(0,3)) { throw "Command failed: $Command : $raw" }
    $value = $raw | ConvertFrom-Json
    if ($value.status -eq 'failed' -or $value.state -eq 'failed') { throw ($value | ConvertTo-Json -Depth 30) }
    return $value
}
$null = Invoke-Indago @('project','create','--name','smoke')
$null = Invoke-Indago @('target','import','--project','smoke','--file',$Fixture)
$inventory = Invoke-Indago @('query','--project','smoke','--backend','xair','--operation','inventory','--max-items','4096')
$symbol = $inventory.data.symbols | Where-Object { $_.name -eq 'runtime_probe' -or $_.name -eq '_runtime_probe' } | Select-Object -First 1
if (!$symbol) { throw 'Fixture function was not found by static inventory' }
$session = Invoke-Indago @('runtime','launch','--project','smoke','--file',$Fixture)
$common = @('--project','smoke','--session',$session.id)
try {
    if ($session.state -ne 'stopped') { throw 'Launch did not stop' }
    $resolved = Invoke-Indago (@('runtime','resolve') + $common + @('--static-address',$symbol.location.address))
    if ($resolved.location.artifact_sha256 -ne $inventory.artifact_sha256) { throw 'Runtime/static artifact mismatch' }
    $null = Invoke-Indago (@('runtime','breakpoint') + $common + @('--static-address',$symbol.location.address))
    $hit = $false
    for ($i=0; $i -lt 8; $i++) {
        $stop = Invoke-Indago (@('runtime','continue') + $common + @('--wait','true'))
        if ($stop.last_event.kind -eq 'breakpoint') { $hit=$true; break }
        if ($stop.state -eq 'exited') { break }
    }
    if (!$hit) { throw 'Fixture breakpoint not hit' }
    $registers = Invoke-Indago (@('runtime','registers') + $common)
    $spText = if ($registers.arch -eq 'x86') { $registers.values.esp } else { $registers.values.rsp }
    $sp = [Convert]::ToUInt64($spText.Substring(2),16)
    $requestPath = Join-Path $workspace 'capture-request.json'
    @{memory=@(@{address=('0x{0:x}' -f ($sp - 128));size=1024})} | ConvertTo-Json -Depth 5 | Set-Content -Encoding ASCII $requestPath
    $capture = Invoke-Indago (@('runtime','capture') + $common + @('--request',$requestPath))
    if (!$capture.id -or !$capture.data.registers.values) { throw 'Capture missing' }
    $memory = Invoke-Indago (@('runtime','memory') + $common + @('--address',$resolved.location.runtime_address,'--size','16'))
    if ($memory.size -ne 16) { throw 'Instruction memory read failed' }
    $symbolicPath = Join-Path $workspace 'symbolic-request.json'
    if ($registers.arch -eq 'x86') {
        @{symbolic_memory=@(@{address=('0x{0:x}' -f ($sp + 4));size=1})} | ConvertTo-Json -Depth 5 | Set-Content -Encoding ASCII $symbolicPath
    } else {
        @{symbolic_registers=@('rcx')} | ConvertTo-Json -Depth 5 | Set-Content -Encoding ASCII $symbolicPath
    }
    $sym = Invoke-Indago (@('runtime','symbolic') + $common + @('--observation',$capture.id,'--mode','solve_branch','--request',$symbolicPath))
    if ($sym.data.producer -ne 'XAIR/XAIR_SYM' -or $sym.data.capture_id -ne $capture.id) { throw 'Symbolic provenance missing' }
    if ($sym.data.results.Count -lt 1 -or $sym.data.results[0].branches.Count -lt 1) { throw ('No seeded branch results: ' + ($sym | ConvertTo-Json -Depth 40)) }
    if (($sym.data.results[0].branches | Where-Object native_verdict -eq 'sat').Count -ne 2) { throw 'Both branch alternatives should be satisfiable with the selected symbolic input' }
    $null = Invoke-Indago (@('runtime','step') + $common)
    $trace = Invoke-Indago (@('runtime','trace') + $common + @('--max-steps','2'))
    if ($trace.observation_ids.Count -lt 1) { throw 'Trace did not capture instructions' }
    $evidence = Invoke-Indago (@('runtime','observations') + $common + @('--kind','capture'))
    if ($evidence.observations.Count -ne 1) { throw 'Capture evidence was not persisted' }
    $null = Invoke-Indago (@('runtime','detach') + $common)
    [pscustomobject]@{status='passed'; fixture=$Fixture; workspace=$workspace; session=$session.id; capture=$capture.id; symbolic_status=$sym.data.status} | ConvertTo-Json -Compress
} finally {
    $state = Invoke-Indago (@('runtime','status') + $common)
    if ($state.worker_alive -and $state.state -notin @('detached','exited','terminated','failed')) {
        $null = Invoke-Indago (@('runtime','terminate') + $common)
    }
}
