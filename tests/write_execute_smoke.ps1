param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",[string]$Fixture="$PSScriptRoot/../out/build/write_execute_fixture.exe")
$ErrorActionPreference='Stop'
$workspace=Join-Path $env:TEMP ('indago-write-execute-'+[guid]::NewGuid().ToString('N'))
function Run([string[]]$Command){$text=& $Executable --workspace $workspace @Command;if($LASTEXITCODE -notin @(0,3)){throw "$Command : $text"};return $text|ConvertFrom-Json}
$null=Run @('project','create','--name','smoke')
$request=Join-Path $workspace 'effects.json';@{telemetry='effects';code_scope='application'}|ConvertTo-Json|Set-Content $request -Encoding utf8
$session=Run @('runtime','instrument','--project','smoke','--file',(Resolve-Path $Fixture).Path,'--max-events','10000','--timeout-ms','3000','--request',$request)
$common=@('--project','smoke','--session',$session.id)
for($i=0;$i -lt 300;$i++){$state=Run (@('runtime','status')+$common);if($state.state -notin @('starting','running')){break};Start-Sleep -Milliseconds 50}
if($state.state -eq 'failed'){throw ($state|ConvertTo-Json -Depth 6)}
$writes=Run (@('runtime','observations')+$common+@('--kind','write_execute'))
$write=$writes.observations|Where-Object {$_.data.location.mapping_status -ne 'file_identity_only'}|Select-Object -First 1
if(!$write){throw 'No anonymous-code write/execute link'}
if(!$write.data.write_observation){throw 'Write provenance is not linked'}
$feedback=Run (@('runtime','feedback')+$common+@('--observation',$write.id,'--backend','xair'))
if(!$feedback.data.derivation.regions.Count){throw 'Generated code reanalysis lineage missing'}
$modules=Run (@('runtime','observations')+$common+@('--kind','module_loaded'))
if($modules.observations.Count -lt 2){throw 'No additional-module lifetimes'}
[pscustomobject]@{status='passed';workspace=$workspace;write_execute=$write.id;module_count=$modules.observations.Count}|ConvertTo-Json -Compress
