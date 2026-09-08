param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",[string]$Fixture="$PSScriptRoot/../out/build/Release/indago_runtime_fixture.exe")
$ErrorActionPreference='Stop'
$Executable=(Resolve-Path $Executable).Path;$Fixture=(Resolve-Path $Fixture).Path
$workspace=Join-Path $env:TEMP ('indago-telemetry-next-'+[guid]::NewGuid().ToString('N'))
function Run([string[]]$Command){$text=& $Executable --workspace $workspace @Command;if($LASTEXITCODE -notin @(0,3,130)){throw "$Command : $text"};return $text|ConvertFrom-Json}
function WaitRun($id){for($i=0;$i -lt 300;$i++){$s=Run @('runtime','status','--project','smoke','--session',$id);if($s.state -notin @('starting','running')){if($s.state -eq 'failed'){throw ($s|ConvertTo-Json -Depth 8)};return $s};Start-Sleep -Milliseconds 50};throw 'Worker deadline'}
$null=Run @('project','create','--name','smoke')
$request=Join-Path $workspace 'effects.json'
@{telemetry='effects';code_scope='main'}|ConvertTo-Json|Set-Content $request -Encoding utf8
$trace=Run @('runtime','instrument','--project','smoke','--file',$Fixture,'--max-events','10000','--timeout-ms','3000','--request',$request)
$null=WaitRun $trace.id
$memory=Run @('runtime','observations','--project','smoke','--session',$trace.id,'--kind','memory_effect')
$calls=Run @('runtime','observations','--project','smoke','--session',$trace.id,'--kind','control_transfer')
if(!$memory.observations.Count -or !$calls.observations.Count){throw 'Missing effects/transfer records'}
if(!$calls.observations[0].data.native.transfer_kind){throw 'Missing transfer kind'}
$completed=Run @('runtime','observations','--project','smoke','--session',$trace.id,'--kind','memory_effect_completed')
if(!@($completed.observations|Where-Object {$_.data.native.write_confirmed -eq $true -and $_.data.native.after_hex}).Count){throw 'No completed native store snapshot'}
$taken=Run @('runtime','observations','--project','smoke','--session',$trace.id,'--kind','control_transfer_taken')
if(!$taken.observations.Count){throw 'No executed transfer correlation'}
$feedback=Run @('runtime','feedback','--project','smoke','--session',$trace.id,'--observation',$taken.observations[0].id,'--backend','xair')
if(!$feedback.overlay.index.relations -or !$feedback.overlay.evidence_ids.Count){throw 'Runtime feedback did not reach static index'}
$target=Start-Process -FilePath $Fixture -ArgumentList 'wait' -WindowStyle Hidden -PassThru
try {
  $attached=Run @('runtime','instrument','--project','smoke','--backend','frida','--pid',"$($target.Id)",'--recipe','config','--timeout-ms','500','--max-events','128')
  $null=WaitRun $attached.id
  $target.Refresh();if($target.HasExited){throw 'Frida attach deadline killed the existing target'}
}finally{if(!$target.HasExited){$target.Kill();$target.WaitForExit()}}
[pscustomobject]@{status='passed';workspace=$workspace;memory_events=$memory.observations.Count;transfer_events=$calls.observations.Count;attach_session=$attached.id}|ConvertTo-Json -Compress
