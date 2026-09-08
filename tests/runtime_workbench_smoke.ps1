param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",[string]$Fixture="$PSScriptRoot/../out/build/Release/indago_runtime_fixture.exe")
$ErrorActionPreference='Stop'
$Executable=(Resolve-Path $Executable).Path;$Fixture=(Resolve-Path $Fixture).Path
$workspace=Join-Path $env:TEMP ('indago-workbench-'+[guid]::NewGuid().ToString('N'))
function Run([string[]]$Command){$text=& $Executable --workspace $workspace @Command;if($LASTEXITCODE -notin @(0,3)){throw "$Command : $text"};$value=$text|ConvertFrom-Json;if($value.status -eq 'failed'){throw $text};return $value}
function Request($operation,$extra=@{}){$path=Join-Path $workspace 'request.json';$extra|ConvertTo-Json -Depth 20|Set-Content $path -Encoding utf8;return Run (@('runtime',$operation,'--project','smoke','--session',$script:session.id,'--request',$path))}
$null=Run @('project','create','--name','smoke')
$null=Run @('target','import','--project','smoke','--file',$Fixture)
$inventory=Run @('query','--project','smoke','--backend','xair','--operation','inventory','--max-items','4096')
$probe=($inventory.data.symbols|Where-Object {$_.name -in @('runtime_probe','_runtime_probe')}|Select-Object -First 1).location.address
$output=($inventory.data.metadata|Where-Object {$_.name -in @('runtime_output','_runtime_output')}|Select-Object -First 1).location.address
if(!$probe -or !$output){throw 'fixture symbols missing'}
$session=Run @('runtime','launch','--project','smoke','--file',$Fixture)
try {
  $bp=Request 'breakpoint' @{static_address=$probe;one_shot=$false}
  $hit=$false
  for($i=0;$i -lt 8;$i++){$stop=Request 'continue' @{wait=$true};if($stop.last_event.kind -eq 'breakpoint'){$hit=$true;break}}
  if(!$hit){throw 'probe not hit'}
  $list=Request 'breakpoints'
  if(!$list.breakpoints.Count){throw 'persistent breakpoint removed on hit'}
  $null=Request 'remove-breakpoint' @{breakpoint_id=$bp.native_breakpoint_id}
  $stack=Request 'stack';if(!$stack.frames.Count){throw 'no unwind frames'}
  $regs=Request 'registers';if(!$regs.extended.Count){throw 'no extended register export'}
  $sp=[Convert]::ToUInt64($(if($regs.arch -eq 'x86'){$regs.values.esp}else{$regs.values.rsp}).Substring(2),16)
  $pc=[Convert]::ToUInt64($(if($regs.arch -eq 'x86'){$regs.values.eip}else{$regs.values.rip}).Substring(2),16)
  $capture=Request 'capture' @{memory=@(@{address=('0x{0:x}' -f ($sp-128));size=1024});code_regions=@(@{address=('0x{0:x}' -f ($pc+128));size=32})}
  if($capture.region_observation_ids.Count -ne 1){throw 'region epoch missing'}
  $inputs=if($regs.arch -eq 'x86'){@{symbolic_memory=@(@{address=('0x{0:x}' -f ($sp+4));size=1})}}else{@{symbolic_registers=@('rcx')}}
  $inputs.observation=$capture.id
  $symbolic=Request 'symbolic' $inputs
  $validated=Request 'validate-witness' @{observation=$symbolic.id;timeout_ms=10000}
  if($validated.verdict -ne 'predicted destination observed'){throw ($validated|ConvertTo-Json)}
  # Feed a pinned, source-backed current-state witness into an external-owner
  # investigation. The read grant does not authorize harness execution.
  $hfile=Join-Path $workspace 'harness-request.json'
  @{project='smoke';objective='Retain a current-state witness without claiming entry-point acceptance';required_facts=@('acceptance');
    owner=@{mode='external';name='benign fixture feedback check';model_declaration='no inference'};
    runtime_observation_sessions=@($session.id)}|ConvertTo-Json -Depth 20|Set-Content $hfile -Encoding utf8
  $investigation=Run @('harness','create','--request',$hfile)
  $script:reasonRevision=0
  function Reason($op,$record) {
    $current=Run @('harness','show','--project','smoke','--id',$investigation.id)
    @{project='smoke';id=$investigation.id;owner_token=$investigation.owner_token;expected_revision=$current.revision;
      request=@{operation=$op;expected_revision=$script:reasonRevision;record=$record}}|ConvertTo-Json -Depth 25|Set-Content $hfile -Encoding utf8
    $saved=Run @('harness','reason','--request',$hfile)
    $script:reasonRevision=$saved.reasoning.revision
    return $saved.reasoning
  }
  $sources=@(@{evidence_id=$inventory.evidence_ids[0];pointer='/program/entry'})
  $reasoning=Reason 'hypothesize' @{obligation='o0_acceptance';statement='A symbolic current-state witness is reproducible';prediction='Predicted destination observed';falsifier='Different destination';sources=$sources}
  $hypothesis=$reasoning.hypotheses[0].id
  $reasoning=Reason 'candidate' @{obligation='o0_candidate_validation';hex='07';encoding='raw byte';assumptions='Demonstration candidate; causal connection to witness is not asserted';sources=$sources}
  $candidate=$reasoning.candidates[0].id
  $reasoning=Reason 'experiment' @{hypothesis=$hypothesis;candidate=$candidate;prediction='Recorded branch witness reaches destination';observe='branch_witness';pointer='/data/verdict';expected='predicted destination observed';sources=$sources}
  $experiment=$reasoning.experiments[0].id
  $receipt=(Request 'observations' @{id=$validated.observation_id;limit=1}).observations[0]
  $badPinRejected=$false
  try {$null=Reason 'feedback' @{id=$experiment;session=$session.id;observation=$receipt.id;sha256=('0'*64)}} catch {$badPinRejected=$true}
  if(!$badPinRejected){throw 'Tampered runtime pin accepted'}
  $reasoning=Reason 'feedback' @{id=$experiment;session=$session.id;observation=$receipt.id;sha256=$receipt.sha256}
  if($reasoning.experiments[0].state -ne 'observation_matches_prediction' -or $reasoning.verified_solve){throw 'Feedback scope or verdict failed'}
  '{}'|Set-Content $hfile -Encoding utf8
  $watch=Request 'watchpoint' @{static_address=$output;size=4;access='write';one_shot=$false}
  $stop=Request 'continue' @{wait=$true}
  if($stop.last_event.kind -ne 'breakpoint'){throw 'watchpoint not hit'}
  $null=Request 'remove-breakpoint' @{breakpoint_id=$watch.native_breakpoint_id}
  $null=Request 'step-out'
  $analysis=Request 'reanalyze' @{observation=$capture.id;backend='xair';timeout_ms=10000}
  if($analysis.data.derivation.regions.Count -ne 2){throw 'multi-region lineage missing'}
  $null=Request 'detach'
  [pscustomobject]@{status='passed';workspace=$workspace;session=$session.id;arch=$regs.arch}|ConvertTo-Json -Compress
}finally{$state=Request 'status';if($state.worker_alive -and $state.state -notin @('exited','detached','terminated','failed')){$null=Request 'terminate'}}
