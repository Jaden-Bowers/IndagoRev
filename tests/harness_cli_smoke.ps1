param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",[string]$Fixture="$PSScriptRoot/../xair/XAIR/tests/corpus/phase3/control-flow.pe64")
$ErrorActionPreference='Stop'
$workspace=Join-Path $env:TEMP ('indago-harness-cli-'+[guid]::NewGuid().ToString('N'))
function Run([string[]]$Arguments){$text=& $Executable --workspace $workspace @Arguments;if($LASTEXITCODE -notin @(0,3,130)){throw "$Arguments : $text"};return $text|ConvertFrom-Json}
function Harness([string]$Operation,$Request,[string]$Family='harness'){$path=Join-Path $workspace 'request.json';$Request|ConvertTo-Json -Depth 32|Set-Content $path -Encoding utf8;return Run @($Family,$Operation,'--request',$path)}
function Owned([string]$Operation,$Request){$current=Run @('harness','show','--project','smoke','--id',$script:id);$Request.project='smoke';$Request.id=$script:id;$Request.owner_token=$script:token;$Request.expected_revision=$current.revision;return Harness $Operation $Request}
$null=Run @('project','create','--name','smoke')
$target=Run @('target','import','--project','smoke','--file',$Fixture)
$system=Harness create @{project='smoke';manifest=@{os='windows';architecture='x64';components=@(@{name='fixture';target_id=$target.id;role='program';path='bin/fixture.exe'});launches=@(@{name='entry';component='fixture'})}} 'system'
$inv=Harness create @{project='smoke';system_manifest=$system.id;target_id=$target.id;workbench_mutations=$true;derived_artifacts=@{max_artifacts=1;max_bytes=1};objective='Inventory a source-backed synthetic executable';required_facts=@('file inventory');owner=@{mode='external';name='offline smoke';model_declaration='deterministic test; no model'};budget=@{max_actions=5;wall_ms=50000;output_bytes=327680}}
$id=$inv.id;$token=$inv.owner_token
$action=Owned propose @{key='inventory';proposal=@{gap='file inventory';expected_evidence='Native format and architecture';prediction='PE or ELF x86-family executable';fallback='Report missing inventory'};request=@{backend='xair';operation='inventory';budget=@{wall_ms=10000;output_bytes=65536;memory_bytes=2147483648;max_items=128}}}
$result=Owned run @{action_id=$action.id}
if($result.status -notin @('completed','partial') -or !$result.result.evidence_ids.Count){throw ($result|ConvertTo-Json -Depth 12)}
$again=Owned run @{action_id=$action.id}
if($again.job_id -ne $result.job_id){throw 'Repeated backend job'}
$packet=Harness context @{project='smoke';id=$id;output_bytes=8192}
if(($packet|ConvertTo-Json -Depth 32 -Compress).Contains($token)){throw 'Context disclosed owner token'}
$record=Run @('evidence','show','--project','smoke','--id',$result.result.evidence_ids[0])
if(!$record.evidence[0].native_result){throw 'Missing native evidence'}
$proposal=@{gap='byte hypothesis';expected_evidence='knowledge receipt or counterexample';prediction='finite bytes equal';fallback='retain mismatch'}
$note=Owned propose @{key='note';proposal=$proposal;request=@{backend='workbench';operation='knowledge.put';arguments=@{kind='summary';title='Synthetic byte hypothesis';body=@{text='Expected byte zero is a deliberately wrong hypothesis'}}}}
$noted=Owned run @{action_id=$note.id}
if($noted.result.state -ne 'inferred' -or !$noted.result.knowledge_ids.Count){throw 'Missing knowledge receipt'}
$comparison=Owned propose @{key='compare';proposal=$proposal;request=@{backend='workbench';operation='validate.compare';arguments=@{subject=$noted.result.knowledge_ids[0];cases=@(@{actual_artifact=$inv.artifact_sha256;expected_hex='00'})}}}
$compared=Owned run @{action_id=$comparison.id}
if($compared.status -ne 'completed' -or $compared.result.passed -ne $false -or !$compared.result.counterexamples.Count){throw 'Expected finite counterexample'}
$revision=Owned propose @{key='revise';proposal=$proposal;request=@{backend='workbench';operation='knowledge.revise';arguments=@{id=$noted.result.knowledge_ids[0];expected_revision=1;state='contradicted';body=@{text='The zero-byte expectation failed its finite comparison; behavior remains unknown'}}}}
$revised=Owned run @{action_id=$revision.id}
if($revised.status -ne 'completed' -or $revised.result.record_revision -ne 2 -or $revised.result.knowledge_ids[0] -ne $noted.result.knowledge_ids[0]){throw 'Guarded CLI assertion revision missing'}
$derive=Owned propose @{key='derive';proposal=$proposal;request=@{backend='workbench';operation='transform.run';arguments=@{offset=0;size=1;spec=@{method='slice'}}}}
$derived=Owned run @{action_id=$derive.id}
if($derived.status -ne 'completed' -or $derived.result.derived_artifact.admitted -ne $true -or $derived.result.derived_artifact.bytes -ne 1){throw 'Missing scoped derived admission'}
$scoped=Harness scope @{project='smoke';id=$id}
if($scoped.components.Count -ne 2 -or $scoped.root_components_mutable -ne $false){throw 'Derived scope did not preserve roots'}
$report=Owned finish @{status='partial';answer='Native file inventory collected; semantic behavior was not investigated.';claims=@(@{fact='file inventory';text='The native backend returned a file inventory.';evidence_ids=@($result.result.evidence_ids);limitations=@('Inventory is not a proof of program behavior')});gaps=@('Behavior remains uninvestigated')}
if($report.report.verified_solve -ne $false){throw 'Invalid solve claim'}
if($report.report.reproducibility.system_manifest.sha256 -ne $system.body.sha256){throw 'Missing manifest report pin'}
$audit=Run @('harness','audit','--project','smoke','--id',$id,'--limit','4')
if($audit.status -ne 'citations_current' -or $audit.report_modified -ne $false -or $audit.verified_solve -ne $false){throw 'Read-only report audit failed'}
$firstPage=Run @('harness','actions','--project','smoke','--id',$id,'--limit','1')
$secondPage=Run @('harness','actions','--project','smoke','--id',$id,'--limit','1','--offset','1')
if($firstPage.records.Count -ne 1 -or $secondPage.records.Count -ne 1 -or $firstPage.records[0].id -eq $secondPage.records[0].id -or $firstPage.next_offset -ne 1){throw 'Harness CLI paging options were ignored'}
$null=Owned release @{}
[pscustomobject]@{status='passed';workspace=$workspace;investigation=$id;job=$result.job_id;checks='native CLI propose/run/reuse, bounded context, native evidence, knowledge/validator receipts, derived admission, partial report, release'}|ConvertTo-Json -Compress
