param([ValidateSet('windows','linux','both')][string]$Platform='both',[int]$MaxFiles=64)
$ErrorActionPreference='Stop'
if($MaxFiles -lt 1 -or $MaxFiles -gt 128){throw 'Packing file bound must be 1..128'}
$repo=Split-Path $PSScriptRoot -Parent
. "$PSScriptRoot/../tests/storage_guard.ps1"
$null=Assert-IndagoStorage -Path $repo -ReserveBytes 1073741824
$packer=Join-Path $repo 'out/payload-codec-windows/Release/indago_payload_pack.exe'
if(!(Test-Path -LiteralPath $packer)){throw 'Build tools/payload-codec first'}
$cache=Join-Path $repo 'out/payload-packed'
[void][IO.Directory]::CreateDirectory($cache)
$platforms=if($Platform -eq 'both'){@('windows','linux')}else{@($Platform)}
$selected=@(foreach($os in $platforms){
    $base=Join-Path $repo "out/runtime-payload/$os"
    Get-ChildItem -LiteralPath $base -File -Recurse | Where-Object {
        $relative=[IO.Path]::GetRelativePath($base,$_.FullName).Replace('\','/')
        $needed=$relative -notmatch '^ghidra/java/jmods/'
        if($relative -match '^ghidra/distribution/.*/os/([^/]+)/'){
            $needed=$needed -and ($Matches[1] -eq $(if($os -eq 'windows'){'win_x86_64'}else{'linux_x86_64'}))
        }
        $needed -and $_.Length -ge 1048576 -and $_.Length -le 536870912
    }
}) | Sort-Object Length -Descending | Select-Object -First $MaxFiles
foreach($file in $selected){
    $null=Assert-IndagoStorage -Path $repo -ReserveBytes 1073741824
    $cacheBytes=[long](Get-ChildItem -LiteralPath $cache -File | Measure-Object Length -Sum).Sum
    if($cacheBytes -gt 805306368){throw 'Packing cache reached its 768 MiB development cap'}
    $info=[Diagnostics.ProcessStartInfo]::new($packer)
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.ArgumentList.Add($file.FullName);$info.ArgumentList.Add($cache)
    $process=[Diagnostics.Process]::Start($info)
    try{
        if(!$process.WaitForExit(30000)){$process.Kill($true);$process.WaitForExit();throw "Packing wall limit reached: $($file.Name)"}
        $result=$process.StandardOutput.ReadToEnd();$errorText=$process.StandardError.ReadToEnd()
        if($process.ExitCode -ne 0){throw "Packing failed: $errorText"}
        $record=$result | ConvertFrom-Json
        [pscustomobject]@{file=[IO.Path]::GetRelativePath($repo,$file.FullName);result=$record} | ConvertTo-Json -Depth 5 -Compress
    }finally{$process.Dispose()}
}
