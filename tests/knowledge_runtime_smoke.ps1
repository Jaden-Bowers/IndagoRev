param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",[Parameter(Mandatory)][string]$Workspace,[Parameter(Mandatory)][string]$Observation)
$ErrorActionPreference='Stop'
function Action([string]$Family,[string]$Operation,$Request){$path=Join-Path $Workspace 'knowledge-runtime-request.json';$Request|ConvertTo-Json -Depth 32|Set-Content $path -Encoding utf8;$text=& $Executable --workspace $Workspace $Family $Operation --request $path;if($LASTEXITCODE -notin @(0,3)){throw $text};return $text|ConvertFrom-Json}
$record=Action knowledge put @{project='smoke';kind='hypothesis';title='Captured execution hypothesis';scope=@{observation_id=$Observation};body=@{prediction='Captured bytes belong to this observation';alternatives=@('another code epoch');unknowns=@('unobserved execution')};dependencies=@(@{type='observation';id=$Observation})}
if($record.freshness -ne 'current'){throw 'Runtime observation dependency is not current'}
$packet=Action graph event @{project='smoke';observation=$Observation;output_bytes=8192;limit=10}
if(!$packet.observation.id){throw 'Runtime evidence packet missing identity'}
$destination=$Workspace+'-bundle'
$null=Action bundle export @{project='smoke';destination=$destination}
$manifest=Get-Content (Join-Path $destination 'manifest.json') -Raw|ConvertFrom-Json
$raw=@($manifest.runtime.runtime_observations|ForEach-Object {$_.record|ConvertFrom-Json}|Where-Object {$_.data.raw_sha256})
if(!$raw.Count){throw 'Fixture raw telemetry provenance missing'}
foreach($item in $raw){if($manifest.objects.sha256 -notcontains $item.data.raw_sha256){throw 'Raw telemetry was not copied into bundle'}}
$import=Action bundle import @{source=$destination;destination=$Workspace+'-restored'}
$Workspace=$import.workspace
$restored=Action knowledge show @{project='smoke';id=$record.id}
if($restored.freshness -ne 'current'){throw 'Runtime dependency did not survive portable import'}
$event=Action graph event @{project='smoke';observation=$Observation;output_bytes=8192;limit=10}
if($event.observation.id -ne $Observation){throw 'Imported event identity changed'}
[pscustomobject]@{status='passed';workspace=$Workspace;observation=$Observation;checks='runtime dependency, event packet, raw telemetry/evidence bundle round-trip'}|ConvertTo-Json -Compress
