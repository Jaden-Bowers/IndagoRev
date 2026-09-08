param([string]$Executable = "$PSScriptRoot/../out/build/Release/indago.exe",[ValidateSet('both','pe','elf')][string]$Format='both')
$ErrorActionPreference = 'Stop'
$workspace = Join-Path ([IO.Path]::GetTempPath()) ('indago-gate-' + [guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($workspace)
function Invoke-Indago([string[]]$Arguments) {
    $raw = & $Executable --workspace $workspace @Arguments
    if ($LASTEXITCODE -notin @(0,3)) { throw "Command failed: $Arguments : $raw" }
    return ($raw | ConvertFrom-Json)
}
$bytes = New-Object byte[] 4120
function Put([int]$At, [UInt64]$Value, [int]$Count) {
    for ($i=0; $i -lt $Count; $i++) { $bytes[$At+$i] = [byte](($Value -shr (8*$i)) -band 255) }
}
$bytes[0]=127; $bytes[1]=69; $bytes[2]=76; $bytes[3]=70; $bytes[4]=2; $bytes[5]=1; $bytes[6]=1
Put 16 2 2; Put 18 62 2; Put 20 1 4; Put 24 0x401000 8; Put 32 64 8
Put 52 64 2; Put 54 56 2; Put 56 1 2
Put 64 1 4; Put 68 5 4; Put 72 4096 8; Put 80 0x401000 8; Put 88 0x401000 8
Put 96 24 8; Put 104 24 8; Put 112 4096 8
[byte[]]$code = @(0x48,0x39,0xd8,0x74,2,0x75,0,0x0f,0x94,0xc0,0x48,0x0f,0x45,0xc3,0xe8,0,0,0,0,0xff,0xd0,0xeb,0,0xc3)
[Array]::Copy($code,0,$bytes,4096,24)
$elf = Join-Path $workspace 'fixture.elf'
[IO.File]::WriteAllBytes($elf,$bytes)
foreach ($fixture in @(@('pe',"$PSScriptRoot/../xair/XAIR/tests/corpus/phase3/control-flow.pe64",'0x140001000','0x140001013'),@('elf',$elf,'0x401000','0x401013'))) {
    if($Format -ne 'both' -and $fixture[0] -ne $Format){continue}
    $project=$fixture[0]; $address=$fixture[2]
    $null=Invoke-Indago @('project','create','--name',$project)
    $null=Invoke-Indago @('target','import','--project',$project,'--file',$fixture[1])
    $null=Invoke-Indago @('analyze','--project',$project,'--profile','fast')
    foreach ($query in @(@('ghidra','decompile'),@('ghidra','tokens'),@('ghidra','cfg'),@('ghidra','xrefs'),@('ghidra','calls'),@('ghidra','types'),@('ghidra','variables'),@('ghidra','strings'),@('ghidra','imports'),@('ghidra','exports'),@('airece','calls'),@('airece','xrefs'),@('xair','semantic'))) {
        $result=Invoke-Indago @('query','--project',$project,'--backend',$query[0],'--operation',$query[1],'--address',$address)
        if (!$result.evidence_ids.Count) {throw 'Missing persisted evidence'}
    }
    $null=Invoke-Indago @('query','--project',$project,'--backend','airece','--operation','slice','--address',$address)
    $null=Invoke-Indago @('query','--project',$project,'--backend','airece','--operation','flow','--source','value(v0)','--target',"reach@$($fixture[3])")
    $functions=Invoke-Indago @('functions','--project',$project)
    $entry=$functions.functions | Where-Object address -eq $address | Select-Object -First 1
    if (!$entry) {throw 'Missing common function identity'}
    $views=Invoke-Indago @('function','show','--project',$project,'--id',$entry.id)
    if ('airece' -notin $views.views.backend -or 'ghidra' -notin $views.views.backend) {throw 'Independent backend views not linked'}
    $evidence=Invoke-Indago @('evidence','list','--project',$project)
    $record=Invoke-Indago @('evidence','show','--project',$project,'--id',$evidence.evidence[0].id)
    if (!$record.evidence[0].native_result) {throw 'Native result not persisted'}
    $indexed=Invoke-Indago @('index','entities','--project',$project,'--kind','instruction')
    if (!$indexed.records.Count) {throw 'Instructions not indexed'}
    $relations=Invoke-Indago @('index','relations','--project',$project,'--kind','definitions')
    if (!$relations.records.Count -or !$relations.records[0].target_entity) {throw 'SSA relations not linked'}
    $claims=Invoke-Indago @('index','claims','--project',$project)
    if (!$claims.records.Count) {throw 'Claims not indexed'}
    $null=Invoke-Indago @('index','rebuild','--project',$project)
    Write-Output "$project integration gate passed ($($evidence.evidence.Count) evidence records)"
}
Write-Output "Retained verification workspace: $workspace"
