# Inspect/extract the official package privately. No installer is executed and no
# capture driver, service, GUI shortcut, association or system setting is changed.
param([string]$Cache=(Join-Path $env:USERPROFILE '.cache/indago/wireshark'),[switch]$Extract)
$ErrorActionPreference='Stop'
$repo=Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot/../tests/storage_guard.ps1"
$null=Assert-IndagoStorage -Path $repo -ReserveBytes 536870912
[void][IO.Directory]::CreateDirectory($Cache)
$packages=@(
    @{name='7zip_26.00+dfsg-1_amd64.deb';url='https://archive.ubuntu.com/ubuntu/pool/universe/7/7zip/7zip_26.00+dfsg-1_amd64.deb';sha='97dc6694bd7919e163a600dff8a5d7f72d892934f97cb0d7deba285abff779ce';bound=3000000},
    @{name='Wireshark-4.6.8-x64.msi';url='https://www.wireshark.org/download/win64/Wireshark-4.6.8-x64.msi';sha='779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3';bound=85000000})
foreach($package in $packages){
    $file=Join-Path $Cache $package.name
    if(!(Test-Path -LiteralPath $file)){
        & curl.exe --fail --location --max-time 120 --max-filesize $package.bound $package.url --output $file
        if($LASTEXITCODE -ne 0){throw 'Private package download failed'}
    }
    if((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne $package.sha){throw 'Private package hash mismatch'}
}
$resolvedCache=[IO.Path]::GetFullPath($Cache)
if($resolvedCache -notmatch '^([A-Za-z]):[\\/]'){throw 'Private cache must be on a Windows drive for WSL staging'}
$linuxCache='/mnt/'+$resolvedCache.Substring(0,1).ToLowerInvariant()+$resolvedCache.Substring(2).Replace('\','/')
$extractor=Join-Path $Cache 'extractor'
if(!(Test-Path -LiteralPath $extractor)){
    & wsl -d Ubuntu -- dpkg-deb --extract "$linuxCache/7zip_26.00+dfsg-1_amd64.deb" "$linuxCache/extractor"
    if($LASTEXITCODE -ne 0){throw 'Private archive utility extraction failed'}
}
& wsl -d Ubuntu -- "$linuxCache/extractor/usr/lib/7zip/7z" l "$linuxCache/Wireshark-4.6.8-x64.msi"
if($LASTEXITCODE -ne 0){throw 'Wireshark package inventory failed'}
Write-Output 'Packages staged and inventoried; nothing installed or executed from the Wireshark package.'
if(!$Extract){return}
$destination=Join-Path $repo 'out/wireshark-stage/windows'
[void][IO.Directory]::CreateDirectory($destination)
$installer=New-Object -ComObject WindowsInstaller.Installer
$database=$installer.OpenDatabase((Join-Path $Cache 'Wireshark-4.6.8-x64.msi'),0)
$view=$database.OpenView('SELECT `File`.`File`, `File`.`FileName`, `Component`.`Directory_`, `File`.`FileSize` FROM `File`, `Component` WHERE `File`.`Component_` = `Component`.`Component`')
$view.Execute();$selected=@()
while($record=$view.Fetch()){
    $key=$record.StringData(1);$name=$record.StringData(2).Split('|')[-1];$directory=$record.StringData(3)
    $rootFile=$directory -eq 'INSTALLFOLDER' -and ($name -match '\.dll$|^tshark\.exe$|^COPYING\.txt$|^README\.txt$')
    $crt=$key -match '_amd64\.' -and $name -match '\.dll$'
    # No GUI/Qt, graphics/video, update agent, capture helpers, installer or driver.
    $gui=$name -match '^Qt6|^opengl|^d3dcompiler|^dxcompiler|^dxil|^avcodec|^avformat|^avutil|^swresample|^swscale|^WinSparkle'
    if(($rootFile -or $crt) -and !$gui){
        if($name -match '[/\\:]|^\.' -or $key -match '[/\\:]'){throw 'Unexpected selected package filename'}
        $selected+=[PSCustomObject]@{key=$key;name=$name;size=$record.IntegerData(4)}
    }
}
if($selected.Count -gt 100 -or ($selected | Measure-Object size -Sum).Sum -gt 167772160){throw 'Selected network worker exceeds staging bound'}
if(($selected.name | Select-Object -Unique).Count -ne $selected.Count){throw 'Duplicate selected package destination'}
& wsl -d Ubuntu --exec "$linuxCache/extractor/usr/lib/7zip/7z" e "$linuxCache/Wireshark-4.6.8-x64.msi" "-o$linuxCache/cabinet" -aos cab1.cab cab2.cab
if($LASTEXITCODE -ne 0){throw 'Cabinet extraction failed'}
foreach($cab in @('cab1.cab','cab2.cab')){
    & wsl -d Ubuntu --exec "$linuxCache/extractor/usr/lib/7zip/7z" e "$linuxCache/cabinet/$cab" "-o$linuxCache/selected-files" -aos @($selected.key)
    if($LASTEXITCODE -ne 0){throw 'Selected file extraction failed'}
}
$manifest=@()
foreach($item in $selected){
    $source=Join-Path "$Cache/selected-files" $item.key
    if((Get-Item -LiteralPath $source).Length -ne $item.size){throw 'Selected MSI file size mismatch'}
    $hash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    $target=Join-Path $destination $item.name
    if(!(Test-Path -LiteralPath $target)){Copy-Item -LiteralPath $source -Destination $target}
    elseif((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash){throw 'Existing selected worker file differs'}
    $manifest+=@{name=$item.name;msi_file_key=$item.key;bytes=$item.size;sha256=$hash}
}
$manifest|ConvertTo-Json -Depth 4 | Set-Content -LiteralPath "$destination/staged-files.json" -Encoding utf8
Write-Output "Selected upstream network worker staged: $($selected.Count) files; no package executable was run."
