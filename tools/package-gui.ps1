param([string]$Destination, [string]$Executable, [string]$Node)
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
if(!$Destination){$Destination=Join-Path $repo 'out/IndagoRev-Desktop'}
if(!$Executable){$Executable=Join-Path $repo 'out/build/Release/indago.exe'}
if(!$Node){$Node=(Get-Command node -ErrorAction Stop).Source}
$Destination=[IO.Path]::GetFullPath($Destination)
if(Test-Path -LiteralPath $Destination){throw 'Destination must be new; existing packages are never overwritten.'}
$gui=Join-Path $repo 'out/gui/Release/indago-gui.exe'
foreach($file in @($gui,$Executable,$Node)){if(!(Test-Path -LiteralPath $file -PathType Leaf)){throw "Required build/runtime missing: $file"}}
New-Item -ItemType Directory -Path $Destination,(Join-Path $Destination 'runtime'),(Join-Path $Destination 'agent'),(Join-Path $Destination 'notices') | Out-Null
Copy-Item -LiteralPath $gui -Destination (Join-Path $Destination 'IndagoRev.exe')
Copy-Item -LiteralPath $Executable -Destination (Join-Path $Destination 'indago.exe')
Copy-Item -LiteralPath $Node -Destination (Join-Path $Destination 'runtime/node.exe')
Copy-Item -LiteralPath (Join-Path $repo 'LICENSE') -Destination (Join-Path $Destination 'notices/IndagoRev-LICENSE.txt')
Copy-Item -LiteralPath (Join-Path $repo 'vendor/imgui/LICENSE.txt') -Destination (Join-Path $Destination 'notices/Dear-ImGui-LICENSE.txt')
Get-ChildItem -LiteralPath (Join-Path $repo 'agent') -File | Where-Object {$_.Extension -in @('.mjs','.ts','.ps1','.md') -or $_.Name -in @('package.json','pnpm-lock.yaml')} | ForEach-Object {
  Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $Destination 'agent')
}
# Hoisted install produces ordinary package directories rather than absolute
# pnpm junctions back into the development tree. All versions remain lock-pinned.
& pnpm --dir (Join-Path $Destination 'agent') install --prod --frozen-lockfile --ignore-scripts --node-linker=hoisted
if($LASTEXITCODE -ne 0){throw 'Pinned agent dependency staging failed'}
Copy-Item -LiteralPath (Join-Path $repo 'gui/PORTABLE-README.txt') -Destination (Join-Path $Destination 'START-HERE.txt')
$nodeNotice=Join-Path (Split-Path $Node -Parent) 'LICENSE'
if(Test-Path -LiteralPath $nodeNotice){Copy-Item -LiteralPath $nodeNotice -Destination (Join-Path $Destination 'notices/Node-LICENSE.txt')}
else {
  $nodeVersion=(& $Node --version).Trim()
  if($nodeVersion -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+$'){throw 'Unexpected Node version'}
  Invoke-WebRequest -Uri "https://raw.githubusercontent.com/nodejs/node/$nodeVersion/LICENSE" -OutFile (Join-Path $Destination 'notices/Node-LICENSE.txt')
}
# These are install-time manifests, not runtime dependencies; some contain the
# local package-store path. Only remove these exact files in the newly made tree.
foreach($name in @('.modules.yaml','.pnpm-workspace-state-v1.json')){
  $metadata=Join-Path $Destination "agent/node_modules/$name"
  if(Test-Path -LiteralPath $metadata){Remove-Item -LiteralPath $metadata}
}
Write-Output "Package: $Destination"
