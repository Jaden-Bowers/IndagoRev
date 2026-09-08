param([Parameter(Mandatory)][string]$Ghidra,[Parameter(Mandatory)][string]$Jdk)
$ErrorActionPreference='Stop'
$root=(Resolve-Path "$PSScriptRoot/..").Path
$Ghidra=(Resolve-Path $Ghidra).Path
$Jdk=(Resolve-Path $Jdk).Path
$stage="$root/out/runtime-payload/windows/ghidra"
if(Test-Path "$stage/java") {throw 'Java stage already exists; use the existing stage or explicitly move it before restaging'}
New-Item -ItemType Directory -Force "$stage/distribution" | Out-Null
Copy-Item "$Ghidra/*" "$stage/distribution" -Recurse -Force
Copy-Item $Jdk "$stage/java" -Recurse
Write-Output 'Private Ghidra and OpenJDK staged; rebuild indago to embed them.'
