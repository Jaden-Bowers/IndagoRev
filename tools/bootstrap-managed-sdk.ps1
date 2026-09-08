param([string]$Cache=(Join-Path $env:USERPROFILE '.cache/indago'))
$ErrorActionPreference='Stop'
$version='10.0.400'
$url='https://builds.dotnet.microsoft.com/dotnet/Sdk/10.0.400/dotnet-sdk-10.0.400-win-x64.zip'
$expected='9b8b88590e4da131bfd0da7aa089d0fc04d5418d5f8607ec13d55dc5a17b4399afd54d496c12657fa05c6c6546dc5eab930f26ac6c50f2d3a7712c0fb378c366'
$cacheRoot=[IO.Path]::GetFullPath($Cache)
$sdk=Join-Path $cacheRoot ('dotnet-sdk-'+$version)
$archive=Join-Path $cacheRoot ('dotnet-sdk-'+$version+'-win-x64.zip')
if(Test-Path -LiteralPath (Join-Path $sdk 'dotnet.exe')) {
  $actual=& (Join-Path $sdk 'dotnet.exe') --version
  if($LASTEXITCODE -ne 0 -or $actual -ne $version){throw 'Private SDK version mismatch'}
  [pscustomobject]@{sdk=$sdk;version=$actual;status='reused'}|ConvertTo-Json -Compress
  exit 0
}
if(Test-Path -LiteralPath $sdk){throw 'Private SDK directory already exists but is incomplete; inspect it before retrying'}
. "$PSScriptRoot/../tests/storage_guard.ps1"
$null=Assert-IndagoStorage -Path $PSScriptRoot -MinimumFreeBytes 21474836480 -ReserveBytes 2147483648
[void][IO.Directory]::CreateDirectory($cacheRoot)
if(-not (Test-Path -LiteralPath $archive)) {
  & curl.exe --fail --location --max-time 180 --max-filesize 400000000 --output $archive $url
  if($LASTEXITCODE -ne 0){throw 'Pinned SDK download failed; retained partial archive for inspection'}
}
if((Get-FileHash -LiteralPath $archive -Algorithm SHA512).Hash.ToLowerInvariant() -ne $expected){throw 'SDK archive SHA-512 mismatch'}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=[IO.Compression.ZipFile]::OpenRead($archive)
try {
  [UInt64]$bytes=0
  foreach($entry in $zip.Entries) {
    $bytes+=$entry.Length
    if($bytes -gt 2147483648){throw 'SDK expanded-size allowance exceeded'}
    $destination=[IO.Path]::GetFullPath((Join-Path $sdk $entry.FullName))
    if(-not $destination.StartsWith($sdk+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'SDK archive entry escapes its private directory'}
  }
} finally {$zip.Dispose()}
$null=Assert-IndagoStorage -Path $PSScriptRoot -MinimumFreeBytes 21474836480 -ReserveBytes $bytes
[IO.Compression.ZipFile]::ExtractToDirectory($archive,$sdk)
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1'
$actual=& (Join-Path $sdk 'dotnet.exe') --version
if($LASTEXITCODE -ne 0 -or $actual -ne $version){throw 'Extracted SDK version mismatch'}
[pscustomobject]@{sdk=$sdk;version=$actual;archive_sha512=$expected;expanded_bytes=$bytes;status='installed_private';system_install_modified=$false}|ConvertTo-Json -Compress
