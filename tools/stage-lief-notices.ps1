param([string]$Cache=(Join-Path $env:USERPROFILE '.cache/indago/lief/dependencies'))
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot/../tests/storage_guard.ps1"
$null=Assert-IndagoStorage -Path $repo -ReserveBytes 33554432
[void][IO.Directory]::CreateDirectory($Cache)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$packages=Get-Content -LiteralPath "$repo/vendor/lief/dependency-archives.json" -Raw | ConvertFrom-Json
foreach($package in $packages){
    $archive=Join-Path $Cache $package.name
    if(!(Test-Path -LiteralPath $archive)){
        & curl.exe --fail --location --max-time 30 --max-filesize 6000000 ("https://raw.githubusercontent.com/lief-project/LIEF/1.0.0/third-party/"+$package.name) --output $archive
        if($LASTEXITCODE -ne 0){throw 'LIEF dependency archive download failed'}
    }
    $bytes=[IO.File]::ReadAllBytes($archive)
    if($bytes.Length -gt 6000000){throw 'Dependency archive exceeds bound'}
    $hasher=[Security.Cryptography.SHA1]::Create()
    try{
        $prefix=[Text.Encoding]::ASCII.GetBytes("blob $($bytes.Length)`0")
        [void]$hasher.TransformBlock($prefix,0,$prefix.Length,$prefix,0)
        [void]$hasher.TransformFinalBlock($bytes,0,$bytes.Length)
        $hash=[BitConverter]::ToString($hasher.Hash).Replace('-','').ToLowerInvariant()
    }finally{$hasher.Dispose()}
    if($hash -cne $package.git_blob_sha1){throw 'LIEF dependency Git blob identity mismatch'}
    $zip=[IO.Compression.ZipFile]::OpenRead($archive)
    try{
        $count=0
        foreach($entry in $zip.Entries){
            if($entry.FullName -notmatch '(^|/)(LICENSE[^/]*|COPYING[^/]*|NOTICE[^/]*|COPYRIGHT[^/]*)$'){continue}
            if($entry.Length -gt 262144 -or $entry.FullName -match '(^|/)\.\.(/|$)' -or $entry.FullName.StartsWith('/') -or $entry.FullName.Contains('\')){throw 'Invalid notice archive entry'}
            $destination=Join-Path "$repo/vendor/lief/notices/$($package.name.Replace('.zip',''))" $entry.FullName
            [void][IO.Directory]::CreateDirectory((Split-Path $destination -Parent))
            if(!(Test-Path -LiteralPath $destination)){[IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$destination,$false)}
            else {
                $reader=[IO.StreamReader]::new($entry.Open())
                try{$expected=$reader.ReadToEnd()}finally{$reader.Dispose()}
                if([IO.File]::ReadAllText($destination) -cne $expected){throw 'Existing upstream notice differs'}
            }
            ++$count
        }
        Write-Output "$($package.name): $count standalone notice files; inspect inline license headers when zero"
    }finally{$zip.Dispose()}
}
