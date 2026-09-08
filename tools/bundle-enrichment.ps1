param([string]$Cache=(Join-Path $env:USERPROFILE '.cache/indago/enrichment'),
      [ValidateSet('windows','linux','both')][string]$Platform='both')
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot/../tests/storage_guard.ps1"
$null=Assert-IndagoStorage -Path $repo -MinimumFreeBytes 21474836480 -ReserveBytes 536870912
[void][IO.Directory]::CreateDirectory($Cache)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$releases=Get-Content -LiteralPath (Join-Path $repo 'vendor/enrichment/releases.json') -Raw | ConvertFrom-Json
foreach($release in $releases) {
    if($Platform -ne 'both' -and $Platform -ne $release.platform){continue}
    $archive=Join-Path $Cache $release.archive
    if(!(Test-Path -LiteralPath $archive)) {
        & curl.exe --fail --location --max-time 120 --max-filesize 64000000 $release.url --output $archive
        if($LASTEXITCODE -ne 0){throw "Download failed: $($release.archive)"}
    }
    if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $release.sha256){throw "Archive hash mismatch: $($release.archive)"}
    $destination=Join-Path $repo "out/runtime-payload/$($release.platform)/enrichment"
    [void][IO.Directory]::CreateDirectory($destination)
    $zip=[IO.Compression.ZipFile]::OpenRead($archive)
    try {
        if($zip.Entries.Count -ne 1 -or $zip.Entries[0].FullName -cne $release.entry -or $zip.Entries[0].Length -gt 67108864){throw 'Unexpected enrichment archive layout or size'}
        $file=Join-Path $destination $release.entry
        if(!(Test-Path -LiteralPath $file)) {[IO.Compression.ZipFileExtensions]::ExtractToFile($zip.Entries[0],$file,$false)}
        else {
            $stream=$zip.Entries[0].Open();$hasher=[Security.Cryptography.SHA256]::Create()
            try{$expected=[BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-','')}finally{$stream.Dispose();$hasher.Dispose()}
            if((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -cne $expected){throw "Existing payload differs; inspect before replacement: $file"}
        }
    } finally { $zip.Dispose() }
    foreach($notice in @('capa-LICENSE.txt','floss-LICENSE.txt','PROVENANCE.md','releases.json')) {
        Copy-Item -LiteralPath (Join-Path $repo "vendor/enrichment/$notice") -Destination (Join-Path $destination $notice)
    }
}
Write-Output 'Pinned upstream enrichment workers staged; rebuild the native executable to embed them.'
