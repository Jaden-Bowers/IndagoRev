param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe")
$ErrorActionPreference='Stop'
$capture=& "$PSScriptRoot/write_execute_smoke.ps1" -Executable $Executable | ConvertFrom-Json
if($capture.status -ne 'passed'){throw 'Generated-code capture failed'}
& "$PSScriptRoot/knowledge_runtime_smoke.ps1" -Executable $Executable -Workspace $capture.workspace -Observation $capture.write_execute
