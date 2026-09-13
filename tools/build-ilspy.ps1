param([string]$Sdk = (Join-Path $env:USERPROFILE '.cache/indago/dotnet-sdk-10.0.400/dotnet.exe'),
      [ValidateSet('win-x64','linux-x64','both')][string]$Runtime = 'both',
      [switch]$VerifyOnly)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
if (!(Test-Path -LiteralPath $Sdk)) { throw 'Run bootstrap-managed-sdk.ps1 first or select a private .NET 10.0.400 SDK' }
if ((& $Sdk --version) -ne '10.0.400') { throw 'Expected pinned .NET SDK 10.0.400' }
if ((Get-PSDrive -Name C).Free -lt 22GB) { throw '20 GiB free-space floor plus 2 GiB build reserve required' }
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1'
$env:DOTNET_GENERATE_ASPNET_CERTIFICATE='false'
$env:DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE='true'
$env:DOTNET_CLI_HOME=Join-Path (Split-Path (Split-Path $Sdk -Parent) -Parent) 'dotnet-home'
$project=Join-Path $repo 'workers/ilspy/Indago.Ilspy.Worker.csproj'
& $Sdk restore $project --locked-mode --configfile (Join-Path $repo 'workers/ilspy/NuGet.Config')
if ($LASTEXITCODE -ne 0) { throw 'Locked ILSpy restore failed' }
$hashes=Get-Content -LiteralPath (Join-Path $repo 'workers/ilspy/dependency-hashes.json') -Raw | ConvertFrom-Json
$locked=Get-Content -LiteralPath (Join-Path $repo 'workers/ilspy/packages.lock.json') -Raw | ConvertFrom-Json
foreach($framework in $locked.dependencies.PSObject.Properties) {
    foreach($package in $framework.Value.PSObject.Properties) {
        $key=$package.Name.ToLowerInvariant()+'/'+$package.Value.resolved
        if(!$hashes.PSObject.Properties[$key]) { throw "Missing archive pin: $key" }
    }
}
foreach($entry in $hashes.PSObject.Properties) {
    $parts=$entry.Name.Split('/')
    $package=Join-Path $repo ("out/managed-packages/"+$entry.Name+"/"+$parts[0]+"."+$parts[1]+".nupkg")
    $stream=[IO.File]::OpenRead($package)
    $algorithm=[Security.Cryptography.SHA512]::Create()
    try { $actual=[Convert]::ToBase64String($algorithm.ComputeHash($stream)) }
    finally { $stream.Dispose(); $algorithm.Dispose() }
    if($actual -cne $entry.Value) { throw "Pinned package hash mismatch: $($entry.Name)" }
}
if($VerifyOnly) { Write-Output 'Pinned SDK, locked restore and all package archives verified; payload unchanged'; exit 0 }
$runtimes=if($Runtime -eq 'both'){@('win-x64','linux-x64')}else{@($Runtime)}
$licenses=@(
 @('TraceEvent','https://raw.githubusercontent.com/microsoft/perfview/v3.2.6/LICENSE.TXT','cfc21f5e8bd655ae997eec916138b707b1d290b83272c02a95c9f821b8c87310'),
 @('OpenMcdf','https://raw.githubusercontent.com/openmcdf/openmcdf/11b5d876cdebb472f1845dfa55e9e9b953aed65f/License.txt','4b89d4518bd135ab4ee154a7bce722246b57a98c3d7efc1a09409898160c2bd1'),
 @('PdfPig','https://raw.githubusercontent.com/UglyToad/PdfPig/a7bb35662bbbf405efddad50aedc9bcdcf515afc/LICENSE','4c510e162f896ea43b4b1cf1b743641d7c756f1004d0e5eaf0615b28b7ded409'))
foreach($license in $licenses){
 $file=Join-Path $repo ('out/'+$license[0]+'-LICENSE.txt')
 if(!(Test-Path -LiteralPath $file)){Invoke-WebRequest $license[1] -OutFile $file}
 if((Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash.ToLowerInvariant() -ne $license[2]){throw 'Upstream license hash mismatch'}
}
foreach($rid in $runtimes) {
    $platform=if($rid -eq 'win-x64'){'windows'}else{'linux'}
    $destination=Join-Path $repo "out/runtime-payload/$platform/ilspy"
    & $Sdk publish $project --no-restore -c Release -r $rid --self-contained true -o $destination
    if ($LASTEXITCODE -ne 0) { throw "ILSpy publish failed for $rid" }
    # Exact upstream notices accompany the private runtime/decompiler payload.
    Copy-Item -LiteralPath (Join-Path $repo 'vendor/ilspy/LICENSE') -Destination (Join-Path $destination 'ILSpy-LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $repo 'vendor/ilspy/PROVENANCE.md') -Destination (Join-Path $destination 'ILSpy-PROVENANCE.md')
    Copy-Item -LiteralPath (Join-Path $repo 'workers/ilspy/packages.lock.json') -Destination (Join-Path $destination 'packages.lock.json')
    foreach($license in $licenses){Copy-Item -LiteralPath (Join-Path $repo ('out/'+$license[0]+'-LICENSE.txt')) -Destination $destination}
    foreach($entry in $hashes.PSObject.Properties){
      $parts=$entry.Name.Split('/');$nuspec=Join-Path $repo ('out/managed-packages/'+$entry.Name+'/'+$parts[0]+'.nuspec')
      if(Test-Path -LiteralPath $nuspec){Copy-Item -LiteralPath $nuspec -Destination $destination}
    }
    $runtimePackage=Join-Path $repo "out/managed-packages/microsoft.netcore.app.runtime.$rid/10.0.11"
    foreach($notice in @('LICENSE.TXT','THIRD-PARTY-NOTICES.TXT')) {
        Copy-Item -LiteralPath (Join-Path $runtimePackage $notice) -Destination (Join-Path $destination "dotnet-$notice")
    }
}
& (Join-Path $PSScriptRoot 'build-wabt.ps1') -Platform $(if($Runtime -eq 'both'){'both'}elseif($Runtime -eq 'win-x64'){'windows'}else{'linux'})
