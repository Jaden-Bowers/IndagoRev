param([string]$Executable="$PSScriptRoot/../out/build/Release/indago.exe",[string]$Corpus='C:/Users/Jaden/Desktop/Projects/IR/xair/tests/corpus/phase3')
$ErrorActionPreference='Stop'
$workspace=Join-Path $env:TEMP ('indago-knowledge-cli-'+[guid]::NewGuid().ToString('N'))
function Run([string[]]$Command){$text=& $Executable --workspace $workspace @Command;if($LASTEXITCODE -notin @(0,3,130)){throw "$Command : $text"};return $text|ConvertFrom-Json}
function Action([string]$Family,[string]$Operation,$Request){$path=Join-Path $workspace 'request.json';$Request|ConvertTo-Json -Depth 32|Set-Content $path -Encoding utf8;Run @($Family,$Operation,'--request',$path)}
$null=Run @('project','create','--name','smoke')
$inventory=@()
foreach($name in @('control-flow.pe64','scalar-arithmetic.pe64','memory-atomic.pe64','sse-string.pe64','compiler-prologue.pe64')){
    $file=Join-Path $Corpus $name
    $target=Run @('target','import','--project','smoke','--file',$file)
    $result=Run @('query','--project','smoke','--backend','xair','--operation','inventory','--target-id',$target.id,'--max-items','64','--timeout-ms','10000')
    if(!$result.evidence_ids.Count){throw 'XAIR inventory evidence missing'}
    $inventory+=@{name=$name;sha256=$target.artifact_sha256;status=$result.status}
}
$batch=Action batch create @{project='smoke';budget=@{wall_ms=30000;output_bytes=131072;memory_bytes=2147483648;max_jobs=2};steps=@(
    @{name='inventory';request=@{backend='xair';operation='inventory';budget=@{wall_ms=10000;output_bytes=65536;memory_bytes=2147483648;max_items=128}}},
    @{name='cfg';depends_on=@('inventory');allow_partial_dependencies=$true;request=@{backend='xair';operation='cfg';budget=@{wall_ms=10000;output_bytes=65536;memory_bytes=2147483648;max_items=128}}}
)}
$result=Action batch run @{project='smoke';id=$batch.id}
if($result.status -notin @('completed','partial') -or $result.jobs_started -ne 2){throw 'Batch did not execute both steps'}
$again=Action batch run @{project='smoke';id=$batch.id}
if($again.jobs_started -ne 2){throw 'Resume repeated completed work'}
$functions=Run @('index','entities','--project','smoke','--kind','function')
if(!$functions.records.Count){throw 'No functions indexed from IR corpus'}
$packet=Action graph packet @{project='smoke';id=$functions.records[0].id;depth=2;limit=20;output_bytes=16384}
if(!$packet.nodes.Count){throw 'Evidence packet missing seed'}
$gaps=Action coverage report @{project='smoke';limit=20}
if($gaps.negative_inference_allowed -ne $false){throw 'Coverage must not permit negative inference'}
$budget=Action batch create @{project='smoke';budget=@{wall_ms=10000;output_bytes=65536;memory_bytes=2147483648;max_jobs=1};steps=@(
    @{name='one';request=@{backend='xair';operation='inventory';budget=@{wall_ms=10000;output_bytes=65536;memory_bytes=2147483648;max_items=64}}},
    @{name='two';request=@{backend='xair';operation='inventory';budget=@{wall_ms=10000;output_bytes=65536;memory_bytes=2147483648;max_items=64}}}
)}
$limited=Action batch run @{project='smoke';id=$budget.id}
if($limited.status -ne 'budget_exhausted' -or $limited.jobs_started -ne 1){throw 'Aggregate budget not enforced'}
$cancel=Action batch create @{project='smoke';budget=@{wall_ms=10000;output_bytes=65536;memory_bytes=2147483648;max_jobs=1};steps=@(@{name='one';request=@{backend='xair';operation='inventory';budget=@{wall_ms=10000;output_bytes=65536;memory_bytes=2147483648;max_items=64}}})}
$null=Action batch cancel @{project='smoke';id=$cancel.id}
$cancelled=Action batch run @{project='smoke';id=$cancel.id}
if($cancelled.status -ne 'cancelled' -or $cancelled.jobs_started){throw 'Cancelled batch submitted work'}
$reset=Action batch run @{project='smoke';id=$cancel.id;reset_cancel=$true}
if($reset.jobs_started -ne 1){throw 'Explicit cancellation reset failed'}
$system=Action system create @{project='smoke';manifest=@{os='windows';architecture='x64';components=@(@{name='fixture';target_id=$target.id;role='program';path='bin/fixture.exe'});launches=@(@{name='entry';component='fixture'})}}
$preflight=Action system preflight @{project='smoke';id=$system.id;max_bytes=65536}
if($preflight.status -ne 'capability_blocked' -or $preflight.ready_for_execution -ne $false -or $preflight.artifacts[0].integrity -ne 'verified'){throw 'Manifest preflight must verify bytes without claiming an attested lab'}
[pscustomobject]@{status='passed';workspace=$workspace;corpus=$inventory;batch=$batch.id;checks='native XAIR corpus, batch dependencies/resume/budget/cancel, graph packets and coverage'}|ConvertTo-Json -Depth 8 -Compress
