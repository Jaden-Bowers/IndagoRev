param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",
      [string]$Fixture="$PSScriptRoot/../out/build/Release/indago_runtime_fixture.exe")
$ErrorActionPreference='Stop'
$Executable=(Resolve-Path $Executable).Path
$Fixture=(Resolve-Path $Fixture).Path
$workspace=Join-Path ([IO.Path]::GetTempPath()) ('indago-instrument-'+[guid]::NewGuid().ToString('N'))
function Invoke-Native([string[]]$Arguments) {
    $raw=& $Executable --workspace $workspace @Arguments
    if($LASTEXITCODE -notin @(0,3,130)){throw "$Arguments : $raw"}
    $r=$raw|ConvertFrom-Json
    if($r.state -eq 'failed' -or $r.status -eq 'failed'){throw $raw}
    $r
}
function Wait-Run($session) {
    $end=(Get-Date).AddSeconds(15)
    do {
        $state=Invoke-Native @('runtime','status','--project','smoke','--session',$session.id)
        if($state.state -notin @('starting','running')){return $state}
        Start-Sleep -Milliseconds 50
    }while((Get-Date) -lt $end)
    throw 'Instrument smoke deadline exceeded'
}
$null=Invoke-Native @('project','create','--name','smoke')
$session=Invoke-Native @('runtime','instrument','--project','smoke','--file',$Fixture,'--max-events','8','--timeout-ms','2000')
$state=Wait-Run $session
if($state.result_status -ne 'partial'){throw 'Capped trace must be partial'}
$blocks=Invoke-Native @('runtime','observations','--project','smoke','--session',$session.id,'--kind','instrumentation_block')
if($blocks.observations.Count -ne 8){throw 'Event budget mismatch'}
if(!$blocks.observations[0].data.location.anchor_id){throw 'Static/runtime location link missing'}
$request=Join-Path $workspace 'wait.json'
@{argv=@('wait')}|ConvertTo-Json|Set-Content -Encoding ASCII $request
$cancelled=Invoke-Native @('runtime','instrument','--project','smoke','--file',$Fixture,'--max-events','8','--timeout-ms','5000','--request',$request)
$null=Invoke-Native @('runtime','cancel','--project','smoke','--session',$cancelled.id)
$cancelState=Wait-Run $cancelled
if($cancelState.result_status -ne 'cancelled'){throw 'Cancellation was not preserved'}
[pscustomobject]@{status='passed';fixture=$Fixture;workspace=$workspace;bounded_session=$session.id;cancelled_session=$cancelled.id}|ConvertTo-Json -Compress
