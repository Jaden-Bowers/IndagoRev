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
foreach($entry in $hashes.PSObject.Properties) {
    $parts=$entry.Name.Split('/')
    $package=Join-Path $repo ("out/managed-packages/"+$entry.Name+"/"+$parts[0]+"."+$parts[1]+".nupkg")
    $stream=[IO.File]::OpenRead($package)
    $algorithm=[Security.Cryptography.SHA512]::Create()
    try { $actual=[Convert]::ToBase64String($algorithm.ComputeHash($stream)) }
    finally { $stream.Dispose(); $algorithm.Dispose() }
    if($actual -cne $entry.Value) { throw "Pinned package hash mismatch: $($entry.Name)" }
}
if($VerifyOnly) { Write-Output 'Pinned SDK, locked restore and three package archives verified; payload unchanged'; exit 0 }
$runtimes=if($Runtime -eq 'both'){@('win-x64','linux-x64')}else{@($Runtime)}
foreach($rid in $runtimes) {
    $platform=if($rid -eq 'win-x64'){'windows'}else{'linux'}
    $destination=Join-Path $repo "out/runtime-payload/$platform/ilspy"
    & $Sdk publish $project --no-restore -c Release -r $rid --self-contained true -o $destination
    if ($LASTEXITCODE -ne 0) { throw "ILSpy publish failed for $rid" }
    # Exact upstream notices accompany the private runtime/decompiler payload.
    Copy-Item -LiteralPath (Join-Path $repo 'vendor/ilspy/LICENSE') -Destination (Join-Path $destination 'ILSpy-LICENSE.txt')
    Copy-Item -LiteralPath (Join-Path $repo 'vendor/ilspy/PROVENANCE.md') -Destination (Join-Path $destination 'ILSpy-PROVENANCE.md')
    Copy-Item -LiteralPath (Join-Path $repo 'workers/ilspy/packages.lock.json') -Destination (Join-Path $destination 'packages.lock.json')
    $runtimePackage=Join-Path $repo "out/managed-packages/microsoft.netcore.app.runtime.$rid/10.0.11"
    foreach($notice in @('LICENSE.TXT','THIRD-PARTY-NOTICES.TXT')) {
        Copy-Item -LiteralPath (Join-Path $runtimePackage $notice) -Destination (Join-Path $destination "dotnet-$notice")
    }
}
