$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot/../tests/storage_guard.ps1"
$null=Assert-IndagoStorage -Path $repo -ReserveBytes 268435456
$source=Join-Path $repo 'out/wireshark-stage/windows'
$destination=Join-Path $repo 'out/runtime-payload/windows/network'
$manifest=Get-Content -LiteralPath "$source/staged-files.json" -Raw | ConvertFrom-Json
if($manifest.Count -gt 100 -or ($manifest | Measure-Object bytes -Sum).Sum -gt 167772160){throw 'Offline worker manifest exceeds bound'}
[void][IO.Directory]::CreateDirectory($destination)
foreach($entry in $manifest){
    if($entry.name -match '[/\\:]|^\.' -or $entry.sha256 -notmatch '^[0-9a-f]{64}$'){throw 'Invalid worker manifest entry'}
    $file=Join-Path $source $entry.name
    if((Get-Item -LiteralPath $file).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256){throw 'Staged worker integrity mismatch'}
    $target=Join-Path $destination $entry.name
    if(!(Test-Path -LiteralPath $target)){Copy-Item -LiteralPath $file -Destination $target}
    elseif((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256){throw 'Existing bundled worker differs'}
}
Copy-Item -LiteralPath "$source/staged-files.json" -Destination "$destination/staged-files.json"
Copy-Item -LiteralPath "$repo/vendor/wireshark/PROVENANCE.md" -Destination "$destination/PROVENANCE.md"
Write-Output 'Offline Windows worker staged for embedding; no capture support installed.'
