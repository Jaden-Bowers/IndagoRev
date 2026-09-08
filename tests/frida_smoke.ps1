param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",
      [string]$Fixture="$PSScriptRoot/../out/build/Release/indago_telemetry_fixture.exe",
      [string]$Backend='xair')
$ErrorActionPreference='Stop'
$workspace=Join-Path ([IO.Path]::GetTempPath()) ('indago-frida-'+[guid]::NewGuid().ToString('N'))
function Invoke-Native([string[]]$Command) {
  $raw=& $Executable --workspace $workspace @Command
  if($LASTEXITCODE -notin @(0,3,130)) {throw "$Command : $raw"}
  return $raw|ConvertFrom-Json
}
$null=Invoke-Native @('project','create','--name','smoke')
$launch=@('runtime','instrument','--project','smoke','--file',(Resolve-Path $Fixture).Path,'--backend','frida','--timeout-ms','3000')
function Wait-Run($id) {
  for($i=0;$i -lt 300;$i++) {
    $s=Invoke-Native @('runtime','status','--project','smoke','--session',$id)
    if($s.state -in @('exited','failed','cancelled')) {return $s}
    Start-Sleep -Milliseconds 25
  }
  throw 'Worker deadline'
}
$run=Invoke-Native ($launch+@('--recipe','code','--max-events','256'))
$s=Wait-Run $run.id
if($s.result_status -ne 'completed') {throw ($s|ConvertTo-Json -Depth 5)}
$common=@('--project','smoke','--session',$run.id)
$observations=Invoke-Native (@('runtime','observations')+$common+@('--kind','code_capture'))
$capture=$observations.observations|Select-Object -First 1
if(!$capture.data.code_epoch.id) {throw 'No generated code capture'}
$result=Invoke-Native (@('runtime','reanalyze')+$common+@('--observation',$capture.id,'--backend',$Backend))
if(@($result.data.analyses|Where-Object status -eq 'failed').Count) {throw 'Static feedback failed'}
$identities=Invoke-Native (@('runtime','identities')+$common)
if(!$identities.identities.Count) {throw 'No indexed epoch'}
$io=Invoke-Native ($launch+@('--recipe','io','--max-events','256'))
$null=Wait-Run $io.id
$api=Invoke-Native @('runtime','observations','--project','smoke','--session',$io.id,'--kind','api_enter')
if(!$api.observations.Count) {throw 'No API events'}
foreach($recipe in @('config','network')){
  $extra=Invoke-Native ($launch+@('--recipe',$recipe,'--max-events','512'))
  $extraState=Wait-Run $extra.id
  if($extraState.state -eq 'failed'){throw ($extraState|ConvertTo-Json -Depth 8)}
  $events=Invoke-Native @('runtime','observations','--project','smoke','--session',$extra.id,'--kind','api_enter')
  $expected=if($recipe -eq 'network'){'connect'}else{'GetEnvironmentVariableW'}
  if(!@($events.observations|Where-Object {$_.data.native.payload.api -eq $expected}).Count){throw "Missing $recipe API observation"}
  if($recipe -eq 'network'){
    $sockets=Invoke-Native @('runtime','identities','--project','smoke','--session',$extra.id,'--kind','socket','--limit','100')
    if($sockets.identities.Count -lt 2 -or @($sockets.identities|Where-Object {$_.kind -ne 'socket' -or $_.record.creation_observed -ne $true -or $_.record.validity -ne 'creation_api_succeeded'}).Count){throw 'Missing observed socket creation identities'}
    $leaves=Invoke-Native @('runtime','observations','--project','smoke','--session',$extra.id,'--kind','api_leave','--limit','1000')
    if(@($leaves.observations|Where-Object {$_.data.socket_event -eq 'close_api_success'}).Count -lt 2){throw 'Socket closes not preserved'}
    $network=Invoke-Native @('runtime','network','--project','smoke','--session',$extra.id,'--limit','1')
    if($network.events.Count -ne 1 -or $null -eq $network.next_offset -or $network.packet_capture -ne $false -or !$network.events[0].observation_sha256){throw 'Bounded source-linked network view missing'}
    $cursor=Invoke-Native @('runtime','network','--project','smoke','--session',$extra.id,'--from','0','--limit','1')
    if($cursor.events.Count -ne 1 -or $null -eq $cursor.next_from -or $cursor.scanned_observations -gt 256){throw 'Network sequence cursor missing'}
    $next=Invoke-Native @('runtime','network','--project','smoke','--session',$extra.id,'--from',([string]$cursor.next_from),'--to',([string]$cursor.snapshot_to),'--limit','1')
    if($next.events.Count -ne 1 -or $next.events[0].sequence -le $cursor.events[0].sequence){throw 'Network sequence cursor repeated an event'}
    $socketView=Invoke-Native @('runtime','network','--project','smoke','--session',$extra.id,'--id',$sockets.identities[0].record.id,'--limit','100')
    if(!$socketView.events.Count -or @($socketView.events|Where-Object {$_.socket.id -ne $sockets.identities[0].record.id}).Count){throw 'Socket view crossed identity scope'}
    $calls=Invoke-Native @('runtime','identities','--project','smoke','--session',$extra.id,'--kind','api_call','--limit','100')
    $paired=@($calls.identities|Where-Object {$_.record.pair_complete -eq $true})
    if($paired.Count -lt 2){throw 'API entry/return pairs were not indexed'}
    $oneCall=Invoke-Native @('runtime','identities','--project','smoke','--session',$extra.id,'--kind','api_call','--id',$paired[0].record.id)
    if($oneCall.identities.Count -ne 1 -or $oneCall.identities[0].record.id -ne $paired[0].record.id){throw 'API identity filter failed'}
    $entry=Invoke-Native @('runtime','observations','--project','smoke','--session',$extra.id,'--id',$paired[0].record.entry_observation)
    $returned=Invoke-Native @('runtime','observations','--project','smoke','--session',$extra.id,'--id',$paired[0].record.return_observation)
    if($entry.observations[0].kind -ne 'api_enter' -or $returned.observations[0].kind -ne 'api_leave' -or $entry.observations[0].data.call_id -ne $returned.observations[0].data.call_id){throw 'API pair does not resolve to its source observations'}
  }
}
$capped=Invoke-Native ($launch+@('--recipe','modules','--max-events','2'))
$s=Wait-Run $capped.id
if($s.result_status -ne 'partial') {throw 'Event limit must be partial'}
[pscustomobject]@{status='passed';workspace=$workspace;session=$run.id;capture=$capture.id;api_events=$api.observations.Count}|ConvertTo-Json -Compress
