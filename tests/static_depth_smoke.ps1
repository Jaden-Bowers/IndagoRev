param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",[string]$Fixture="$PSScriptRoot/../out/build/static_depth_fixture.exe")
$ErrorActionPreference='Stop'
$workspace=Join-Path $env:TEMP ('indago-static-depth-'+[guid]::NewGuid().ToString('N'))
function Run([string[]]$Command){$text=& $Executable --workspace $workspace @Command;if($LASTEXITCODE -notin @(0,3)){throw "$Command : $text"};return $text|ConvertFrom-Json}
function Query($operation,$address='',$arguments=@{}){$request=Join-Path $workspace 'action.json';@{project='smoke';backend='ghidra';operation=$operation;address=$address;arguments=$arguments;budget=@{max_items=512;wall_ms=120000;output_bytes=1048576}}|ConvertTo-Json -Depth 8|Set-Content $request -Encoding utf8;Run @('action','run','--request',$request)}
$null=Run @('project','create','--name','smoke')
$null=Run @('target','import','--project','smoke','--file',(Resolve-Path $Fixture).Path)
$functions=Query 'functions' '' @{search='guarded_read'}
$flow=Query 'control_flow' $functions.data.functions[0].entry
if(!$flow.data.control_flow.exception_relations.Count){throw 'No typed exception-handler association'}
if(!$flow.data.control_flow.initialization_callbacks.Count){throw 'No TLS callback recovery'}
$dispatch=Query 'functions' '' @{search='dispatch_value'}
$virtual=Query 'control_flow' $dispatch.data.functions[0].entry
if(!$virtual.data.control_flow.virtual_dispatch.Count){throw 'No native CALLIND site export'}
$chosen=Query 'functions' '' @{search='dispatch_chosen'}
$resolved=Query 'control_flow' $chosen.data.functions[0].entry
if(!@($resolved.data.control_flow.virtual_dispatch|Where-Object {$_.target.address}).Count){throw 'No constant pointer-chain recovery'}
$relations=Run @('index','relations','--project','smoke','--backend','ghidra','--kind','static_dispatch_candidate')
if(!$relations.records.Count){throw 'Resolved dispatch candidate was not indexed'}
if(!$flow.index.relations){throw 'Recovered relationships were not indexed'}
$null=Query 'close'
[pscustomobject]@{status='passed';workspace=$workspace;handlers=$flow.data.control_flow.exception_relations.Count;callbacks=$flow.data.control_flow.initialization_callbacks.Count;dispatch_sites=$virtual.data.control_flow.virtual_dispatch.Count}|ConvertTo-Json -Compress
