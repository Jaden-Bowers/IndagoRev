param([int]$Jobs=6)
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
function Build-Step([string[]]$Arguments) {
    & cmake @Arguments
    if($LASTEXITCODE){throw "CMake failed: $Arguments"}
}
$revision=(Get-Content -LiteralPath "$root/vendor/dynamorio/INDAGO_UPSTREAM_REVISION" -Raw).Trim()
if($revision -ne '59352ff71fefdb8542fc5bd2ae3b76181a50072e'){throw 'Unexpected DynamoRIO revision'}
$perl=(Get-Command perl -ErrorAction SilentlyContinue).Source
if(!$perl){$perl='C:/Program Files/Git/usr/bin/perl.exe'}
foreach($bits in @(64,32)) {
    $platform=if($bits -eq 64){'x64'}else{'Win32'}
    $engine="$root/out/dr$bits"
    $worker="$root/out/dr-worker$bits"
    Build-Step @('-S',"$root/vendor/dynamorio",'-B',$engine,'-G','Visual Studio 17 2022','-A',$platform,"-DPERL_EXECUTABLE=$perl",'-DBUILD_TESTS=OFF','-DBUILD_DOCS=OFF','-DBUILD_SAMPLES=OFF','-DBUILD_CLIENTS=OFF','-DBUILD_EXT=OFF','-DDISABLE_WARNINGS=ON')
    Build-Step @('--build',$engine,'--config','RelWithDebInfo','--target','dynamorio','drinjectlib','drconfiglib','--parallel',"$Jobs")
    Build-Step @('-S',"$root/workers/dynamorio",'-B',$worker,'-G','Visual Studio 17 2022','-A',$platform,"-DDynamoRIO_DIR=$engine/cmake",'-DCMAKE_POLICY_VERSION_MINIMUM=3.5')
    Build-Step @('--build',$worker,'--config','Release','--parallel',"$Jobs")
    $payload="$root/out/runtime-payload/windows/dynamorio"
    $null=New-Item -ItemType Directory -Force "$payload/bin$bits","$payload/lib$bits/release"
    Copy-Item -LiteralPath "$engine/lib$bits/release/dynamorio.dll" -Destination "$payload/lib$bits/release/dynamorio.dll"
    foreach($dll in @('drinjectlib.dll','drconfiglib.dll')) {
        Copy-Item -LiteralPath "$engine/lib$bits/$dll" -Destination "$payload/bin$bits/$dll"
    }
    Copy-Item -LiteralPath "$worker/Release/indago_dr_host.exe" -Destination "$payload/bin$bits/indago_dr_host.exe"
    Copy-Item -LiteralPath "$worker/Release/indago_dr_client.dll" -Destination "$payload/lib$bits/indago_dr_client.dll"
}
Copy-Item -LiteralPath "$root/vendor/dynamorio/License.txt" -Destination "$payload/License.txt"
Write-Output "Runtime payload staged: $payload. Rebuild indago to embed it."
