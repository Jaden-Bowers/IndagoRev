param(
    [Parameter(Mandatory=$true)][string]$Project,
    [string]$Executable,
    [string]$Node
)
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
if(!$Executable){$Executable=Join-Path $repo 'out/build/Release/indago.exe'}
if(!$Node){$Node=(Get-Command node -ErrorAction Stop).Source}
$gui=Join-Path $repo 'out/gui/Release/indago-gui.exe'
$bridge=Join-Path $repo 'agent/desktop.mjs'
foreach($file in @($Executable,$Node,$gui,$bridge)){if(!(Test-Path -LiteralPath $file -PathType Leaf)){throw "Missing runtime file: $file"}}
$resolvedProject=(Resolve-Path -LiteralPath $Project).Path
# Native PowerShell invocation preserves literal arguments, including spaces.
& $gui --project $resolvedProject --exe (Resolve-Path -LiteralPath $Executable).Path --node $Node --agent $bridge
