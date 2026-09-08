param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",[string]$Fixture="$PSScriptRoot/../out/build/Release/indago_runtime_fixture.exe")
$ErrorActionPreference='Stop'
$workspace=Join-Path $env:TEMP ('indago-process-next-'+[guid]::NewGuid().ToString('N'))
function Run([string[]]$Command){$text=& $Executable --workspace $workspace @Command;if($LASTEXITCODE -notin @(0,3)){throw "$Command : $text"};$r=$text|ConvertFrom-Json;if($r.status -eq 'failed'){throw $text};return $r}
$null=Run @('project','create','--name','smoke')
$request=Join-Path $workspace 'follow.json';@{follow_children=$true;argv=@('children')}|ConvertTo-Json|Set-Content $request -Encoding utf8
$session=Run @('runtime','launch','--project','smoke','--file',(Resolve-Path $Fixture).Path,'--request',$request)
$common=@('--project','smoke','--session',$session.id)
try {
  $found=$false
  for($i=0;$i -lt 12;$i++){
    $state=Run (@('runtime','continue')+$common+@('--wait','true'))
    if($state.state -eq 'exited'){break}
    $processes=Run (@('runtime','processes')+$common)
    $created=Run (@('runtime','observations')+$common+@('--kind','process_created'))
    if($processes.processes.Count -gt 1 -and @($created.observations|Where-Object {$_.data.parent_process_id}).Count){$found=$true;break}
  }
  if(!$found){throw 'No child process inventory'}
  foreach($process in $processes.processes){$selected=Run (@('runtime','select-process')+$common+@('--pid',"$($process.pid)"));if($selected.pid -ne $process.pid){throw 'Process selection failed'}}
  $created=Run (@('runtime','observations')+$common+@('--kind','process_created'))
  if(!@($created.observations|Where-Object {$_.data.parent_process_id}).Count){throw 'No parent/child identity relationship'}
  $null=Run (@('runtime','terminate')+$common)
  [pscustomobject]@{status='passed';workspace=$workspace;processes=$processes.processes.Count}|ConvertTo-Json -Compress
}finally{$final=Run (@('runtime','status')+$common);if($final.worker_alive -and $final.state -notin @('exited','terminated','detached')){& $Executable --workspace $workspace runtime terminate @common|Out-Null}}
