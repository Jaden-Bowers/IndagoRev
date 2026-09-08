param([string]$Executable = "$PSScriptRoot/../out/build/Release/indago.exe")
$ErrorActionPreference='Stop'
$directory=Join-Path ([IO.Path]::GetTempPath()) ('indago-single-binary-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($directory)
$isolated=Join-Path $directory 'indago.exe'
Copy-Item -LiteralPath $Executable -Destination $isolated
# A bogus former configuration must not redirect analysis to another binary.
$env:INDAGO_AIRECE=Join-Path $directory 'does-not-exist.exe'
function Invoke-Isolated([string[]]$Arguments) {
    $output=& $isolated --workspace (Join-Path $directory 'store') @Arguments
    if($LASTEXITCODE -notin @(0,3)){throw "Integrated command failed: $output"}
    return ($output | ConvertFrom-Json)
}
$null=Invoke-Isolated @('project','create','--name','test')
$null=Invoke-Isolated @('target','import','--project','test','--file',"$PSScriptRoot/../xair/XAIR/tests/corpus/phase3/control-flow.pe64")
foreach($operation in @('inspect','functions','calls','xrefs','slice','taint')) {
    $arguments=@('query','--project','test','--backend','airece','--operation',$operation)
    if($operation -in @('xrefs','slice','taint')){$arguments+=@('--address','0x140001000')}
    $result=Invoke-Isolated $arguments
    if($result.data.provenance.executable -ne $isolated){throw 'Did not use isolated primary binary'}
}
$result=Invoke-Isolated @('query','--project','test','--backend','sym','--operation','source_to_sink','--source','value(v0)','--sink','reach@0x140001013')
if(!$result.evidence_ids.Count){throw 'Missing symbolic evidence'}
Write-Output "Integrated AIRECE and symbolic analysis passed using only $isolated"
