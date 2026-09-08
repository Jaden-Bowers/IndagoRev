param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe", [string]$Fixture="$PSScriptRoot/../out/build/Release/indago_runtime_fixture.exe")
$ErrorActionPreference='Stop'
$Executable=(Resolve-Path $Executable).Path
$Fixture=(Resolve-Path $Fixture).Path
$workspace=Join-Path ([IO.Path]::GetTempPath()) ('indago-attach-'+[guid]::NewGuid().ToString('N'))
function Run([string[]]$Command) {
    $raw=& $Executable --workspace $workspace @Command
    if($LASTEXITCODE -notin @(0,3)){throw $raw}
    $r=$raw|ConvertFrom-Json
    if($r.status -eq 'failed' -or $r.state -eq 'failed'){throw $raw}
    $r
}
$null=Run @('project','create','--name','attach')
$target=Start-Process -FilePath $Fixture -ArgumentList 'wait' -WindowStyle Hidden -PassThru
try {
    $session=Run @('runtime','attach','--project','attach','--pid',"$($target.Id)")
    $common=@('--project','attach','--session',$session.id)
    if($session.state -ne 'stopped'){throw 'Attach did not stop'}
    $null=Run (@('runtime','registers')+$common)
    $null=Run (@('runtime','continue')+$common)
    Start-Sleep -Milliseconds 100
    $state=Run (@('runtime','status')+$common)
    if($state.state -eq 'stopped'){$null=Run (@('runtime','continue')+$common)}
    $paused=Run (@('runtime','pause')+$common)
    if($paused.state -ne 'stopped'){throw 'Pause failed'}
    $null=Run (@('runtime','detach')+$common)
    [pscustomobject]@{status='passed';operation='attach-pause-detach';workspace=$workspace}|ConvertTo-Json -Compress
}finally{
    if(!$target.HasExited){$target.Kill();$target.WaitForExit()}
}
