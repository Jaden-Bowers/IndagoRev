param(
  [ValidateSet('native','static','knowledge','runtime','harness','runtime-evidence','frida')][string]$Suite='native',
  [string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",
  [string]$Fixture='',
  [ValidateSet('both','pe','elf')][string]$StaticFormat='both',
  [ValidateRange(1,480)][int]$TimeoutSeconds=480,
  [UInt64]$MinimumFreeBytes=21474836480,
  [UInt64]$ScratchBudgetBytes=536870912
)
$ErrorActionPreference='Stop'
$root=(Resolve-Path "$PSScriptRoot/..").Path
$exe=(Resolve-Path $Executable).Path
. "$PSScriptRoot/storage_guard.ps1"
$freeAtStart=Assert-IndagoStorage -Path $root -MinimumFreeBytes $MinimumFreeBytes -ReserveBytes $ScratchBudgetBytes
$report=Join-Path $root ('out/qualification-'+$Suite+'-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($report)
if($Suite -eq 'native') {
  $program=(Get-Command ctest).Source
  $arguments=@('--test-dir',('"'+$root+'/out/build"'),'-C','Release','--timeout','180','--output-on-failure')
} else {
  $program=(Get-Command powershell).Source
  $scripts=@{static='static_gate.ps1';knowledge='knowledge_cli_smoke.ps1';runtime='runtime_workbench_smoke.ps1';harness='harness_cli_smoke.ps1';'runtime-evidence'='runtime_evidence_bundle_smoke.ps1';frida='frida_smoke.ps1'}
  $arguments=@('-NoProfile','-File',('"'+$PSScriptRoot+'/'+$scripts[$Suite]+'"'),'-Executable',('"'+$exe+'"'))
  if($Suite -eq 'static'){$arguments+=@('-Format',$StaticFormat)}
  elseif($StaticFormat -ne 'both'){throw 'StaticFormat applies only to the static suite'}
  if($Fixture){if($Suite -notin @('runtime','harness','frida')){throw 'Fixture supported only for runtime/harness/frida'};$arguments+=@('-Fixture',('"'+(Resolve-Path $Fixture).Path+'"'))}
}
$started=[DateTime]::UtcNow
$process=Start-Process -FilePath $program -ArgumentList $arguments -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput "$report/stdout.log" -RedirectStandardError "$report/stderr.log"
$null=$process.Handle
$timedOut=$false;$storageStopped=$false
while(-not $process.WaitForExit(500)){
  if(([DateTime]::UtcNow-$started).TotalSeconds -ge $TimeoutSeconds){$timedOut=$true;break}
  try {
    $remaining=Assert-IndagoStorage -Path $root -MinimumFreeBytes $MinimumFreeBytes -ReserveBytes 0
    # Conservative volume delta also sees unrelated writers. It is not attribution
    # or a hard filesystem quota; either condition stops this test's process tree.
    if($freeAtStart -gt $remaining -and ($freeAtStart-$remaining) -gt $ScratchBudgetBytes){$storageStopped=$true;break}
  }catch{$storageStopped=$true;break}
}
if($timedOut -or $storageStopped) {
  # Only terminate the process tree created by this invocation.
  & taskkill /PID $process.Id /T /F | Out-Null
  $process.WaitForExit()
}
$process.WaitForExit()
$result=[ordered]@{suite=$Suite;status=$(if($storageStopped){'storage_budget'}elseif($timedOut){'timeout'}elseif($process.ExitCode -eq 0){'passed'}else{'failed'});exit_code=$process.ExitCode;started_utc=$started.ToString('o');elapsed_seconds=([DateTime]::UtcNow-$started).TotalSeconds;timeout_seconds=$TimeoutSeconds;minimum_free_bytes=$MinimumFreeBytes;scratch_budget_bytes=$ScratchBudgetBytes;free_bytes_at_start=$freeAtStart;executable=$exe;logs=$report;scope='bounded development qualification, not production certification'}
$result|ConvertTo-Json|Set-Content "$report/result.json" -Encoding utf8
$result|ConvertTo-Json -Compress
if($timedOut -or $storageStopped -or $process.ExitCode -ne 0){Get-Content "$report/stdout.log";Get-Content "$report/stderr.log";exit 1}
