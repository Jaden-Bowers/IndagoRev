param([string]$Build,[string]$Payload)
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
if(!$Build){$Build=Join-Path $repo 'out/emulation-windows'}
if(!$Payload){$Payload=Join-Path $repo 'out/runtime-payload/windows'}
cmake -S (Join-Path $repo 'workers/emulation') -B $Build -A x64 -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded "-DCMAKE_INSTALL_PREFIX=$Payload"
if($LASTEXITCODE){throw 'Emulation configure failed'}
cmake --build $Build --config Release --parallel 4
if($LASTEXITCODE){throw 'Emulation build failed'}
cmake --install $Build --config Release
if($LASTEXITCODE){throw 'Emulation staging failed'}
Write-Output 'Reconfigure and rebuild Indago to embed the emulation worker and notices.'
