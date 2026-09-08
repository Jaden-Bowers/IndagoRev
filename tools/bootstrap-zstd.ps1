$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot/../tests/storage_guard.ps1"
$null=Assert-IndagoStorage -Path $repo -ReserveBytes 67108864
$cache=Join-Path $env:USERPROFILE '.cache/indago/zstd'
[void][IO.Directory]::CreateDirectory($cache)
$archive=Join-Path $cache 'zstd-1.5.7.tar.gz'
if(!(Test-Path -LiteralPath $archive)){
    & curl.exe --silent --show-error --fail --location --max-time 60 --max-filesize 3000000 https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz --output $archive
    if($LASTEXITCODE -ne 0){throw 'Zstandard source download failed'}
}
if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3'){throw 'Zstandard source hash mismatch'}
$destination=Join-Path $repo 'vendor/zstd/upstream'
if(Test-Path -LiteralPath $destination){throw 'Zstandard source destination already exists; inspect instead of overwriting'}
$entries=@(& tar -tf $archive)
if($LASTEXITCODE -ne 0 -or $entries.Count -gt 10000){throw 'Invalid source archive inventory'}
foreach($entry in $entries){
    if(!$entry.StartsWith('zstd-1.5.7/',[StringComparison]::Ordinal) -or $entry -match '(^|/)\.\.(/|$)' -or $entry.Contains('\')){throw 'Unexpected source archive path'}
}
[void][IO.Directory]::CreateDirectory($destination)
# Library/build sources and notices only. Upstream CLI-test symlinks are not
# needed by this integration and are not portable through Windows tar.
& tar -xf $archive -C $destination --strip-components 1 zstd-1.5.7/lib zstd-1.5.7/build/cmake zstd-1.5.7/LICENSE zstd-1.5.7/COPYING zstd-1.5.7/README.md zstd-1.5.7/CHANGELOG
if($LASTEXITCODE -ne 0){throw 'Zstandard source extraction failed'}
Write-Output 'Pinned Zstandard C source staged; no installed codec/runtime dependency.'
