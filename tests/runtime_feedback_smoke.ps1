param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",
      [string]$Fixture="$PSScriptRoot/../out/build/Release/indago_runtime_fixture.exe",
      [string]$Backend='xair')
$ErrorActionPreference='Stop'
$workspace=Join-Path ([IO.Path]::GetTempPath()) ('indago-feedback-'+[guid]::NewGuid().ToString('N'))
function Invoke-Native([string[]]$Command) {
  $text=& $Executable --workspace $workspace @Command
  if($LASTEXITCODE -notin @(0,3)) { throw "$Command : $text" }
  return $text | ConvertFrom-Json
}
$null=Invoke-Native @('project','create','--name','feedback')
$session=Invoke-Native @('runtime','launch','--project','feedback','--file',(Resolve-Path $Fixture).Path)
$common=@('--project','feedback','--session',$session.id)
try {
  $inventory=Invoke-Native @('query','--project','feedback','--backend','xair','--operation','inventory','--max-items','4096')
  $symbol=$inventory.data.symbols|Where-Object {$_.name -in @('runtime_probe','_runtime_probe')}|Select-Object -First 1
  if(!$symbol) {throw 'No fixture probe'}
  $null=Invoke-Native (@('runtime','breakpoint')+$common+@('--static-address',$symbol.location.address))
  for($i=0;$i -lt 8;$i++) {
    $stop=Invoke-Native (@('runtime','continue')+$common+@('--wait','true'))
    if($stop.last_event.kind -eq 'breakpoint') {break}
  }
  $capture=Invoke-Native (@('runtime','capture')+$common+@('--size','128'))
  if(!$capture.data.code_epoch.id) {throw 'Missing byte epoch'}
  $next=Invoke-Native (@('runtime','capture')+$common+@('--size','128'))
  if($next.data.code_epoch.id -eq $capture.data.code_epoch.id) {throw 'Independent reads must not imply continuity'}
  $result=Invoke-Native (@('runtime','reanalyze')+$common+@('--observation',$capture.id,'--backend',$Backend))
  if(!$result.data.derivation.target_id -or $result.data.analyses.Count -lt 3) {throw 'Missing static feedback'}
  if(@($result.data.analyses | Where-Object status -eq 'failed').Count) {throw ($result | ConvertTo-Json -Depth 40)}
  $lineage=Invoke-Native (@('runtime','lineage')+$common+@('--artifact',$result.data.derivation.artifact_sha256))
  if($lineage.derivations[0].source_observation_id -ne $capture.id) {throw 'Lineage lost'}
  [pscustomobject]@{status='passed';workspace=$workspace;session=$session.id;capture=$capture.id;analysis_status=$result.status}|ConvertTo-Json -Compress
} finally { $null=Invoke-Native (@('runtime','terminate')+$common) }
