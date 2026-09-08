param([string]$Build="$PSScriptRoot/../out/frida-worker")
$ErrorActionPreference='Stop'
$root=(Resolve-Path "$PSScriptRoot/..").Path
cmake -S "$root/workers/frida" -B $Build -G 'Visual Studio 17 2022' -A x64 "-DFRIDA_DEVKIT=$root/vendor/frida/windows"
if($LASTEXITCODE) {throw 'Frida configuration failed'}
cmake --build $Build --config Release --parallel 4
if($LASTEXITCODE) {throw 'Frida build failed'}
$stage="$root/out/runtime-payload/windows/frida"
New-Item -ItemType Directory -Force $stage|Out-Null
Copy-Item "$Build/Release/indago_frida_host.exe","$root/vendor/frida/COPYING" $stage
Write-Output 'Frida staged. Rebuild indago to embed it.'
