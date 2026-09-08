param([string]$Cache=(Join-Path $env:USERPROFILE '.cache/indago/lief'),
      [ValidateSet('windows','linux','both')][string]$Platform='both')
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot/../tests/storage_guard.ps1"
$null=Assert-IndagoStorage -Path $repo -MinimumFreeBytes 21474836480 -ReserveBytes 536870912
[void][IO.Directory]::CreateDirectory($Cache)
$packages=@(
    @{platform='windows';archive='LIEF-1.0.0-win64.zip';prefix='LIEF-1.0.0-win64';sha='1ad0799a5e699505f7e4ad31fd196105867cf29fd8b74485f32d02cfaba94fe2'},
    @{platform='linux';archive='LIEF-1.0.0-Linux-x86_64.tar.gz';prefix='LIEF-1.0.0-Linux-x86_64';sha='81b86bcc69d311a01ec1914d26c31ebbb605ac761ec02f10bc5b588de74a8e91'})
foreach($package in $packages) {
    if($Platform -ne 'both' -and $Platform -ne $package.platform){continue}
    $archive=Join-Path $Cache $package.archive
    if(!(Test-Path -LiteralPath $archive)) {
        & curl.exe --fail --location --max-time 120 --max-filesize 50000000 ("https://github.com/lief-project/LIEF/releases/download/1.0.0/"+$package.archive) --output $archive
        if($LASTEXITCODE -ne 0){throw 'LIEF SDK download failed'}
    }
    if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -cne $package.sha){throw 'LIEF SDK archive hash mismatch'}
    $destination=Join-Path $repo "out/lief-sdk/$($package.platform)"
    if(Test-Path -LiteralPath $destination){throw "SDK destination already exists; inspect it rather than overwriting: $destination"}
    $entries=@(& tar -tf $archive)
    if($LASTEXITCODE -ne 0 -or $entries.Count -gt 20000){throw 'Invalid LIEF archive inventory'}
    foreach($entry in $entries){
        if(!$entry.StartsWith($package.prefix+'/',[StringComparison]::Ordinal) -or $entry -match '(^|/)\.\.(/|$)' -or $entry.Contains('\')){throw 'Unexpected LIEF archive path'}
    }
    [void][IO.Directory]::CreateDirectory($destination)
    # Only development headers, static archive and import configuration. Shared
    # libraries and example programs are not needed or added to the application.
    $library=if($package.platform -eq 'windows'){'lib/LIEF.lib'}else{'lib/libLIEF.a'}
    & tar -xf $archive -C $destination --strip-components 1 ($package.prefix+'/include') ($package.prefix+'/'+$library) ($package.prefix+'/lib/cmake/LIEF')
    if($LASTEXITCODE -ne 0){throw 'LIEF selected SDK extraction failed'}
    Write-Output "LIEF 1.0.0 static SDK staged for $($package.platform)"
}
