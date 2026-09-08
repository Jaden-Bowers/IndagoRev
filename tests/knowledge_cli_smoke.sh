#!/usr/bin/env bash
set -euo pipefail
exe=${1:?executable};corpus=${2:?IR synthetic corpus directory}
workspace=$(mktemp -d /tmp/indago-knowledge-cli.XXXXXX)
run(){ local value rc=0;value=$("$exe" --workspace "$workspace" "$@")||rc=$?;if [[ $rc != 0 && $rc != 3 && $rc != 130 ]];then echo "$value" >&2;return 1;fi;echo "$value"; }
action(){ local family=$1 op=$2 request=$3;printf '%s' "$request" > "$workspace/request.json";run "$family" "$op" --request "$workspace/request.json"; }
run project create --name smoke >/dev/null
for name in control-flow.pe64 scalar-arithmetic.pe64 memory-atomic.pe64 sse-string.pe64 compiler-prologue.pe64;do
  target=$(run target import --project smoke --file "$corpus/$name")
  result=$(run query --project smoke --backend xair --operation inventory --target-id "$(jq -r .id <<<"$target")" --max-items 64 --timeout-ms 10000)
  jq -e '.evidence_ids|length>0' <<<"$result" >/dev/null
done
sha=$(jq -r .artifact_sha256 <<<"$target")
system=$(action system create "$(jq -nc --arg id "$(jq -r .id <<<"$target")" '{project:"smoke",manifest:{os:"windows",architecture:"x64",components:[{name:"fixture",target_id:$id,role:"program",path:"bin/fixture.exe"}],launches:[{name:"entry",component:"fixture"}]}}')")
preflight=$(action system preflight "$(jq -nc --arg id "$(jq -r .id <<<"$system")" '{project:"smoke",id:$id,max_bytes:65536}')")
jq -e '.status=="capability_blocked" and .ready_for_execution==false and .artifacts[0].integrity=="verified"' <<<"$preflight" >/dev/null
batch=$(action batch create '{"project":"smoke","budget":{"wall_ms":30000,"output_bytes":131072,"memory_bytes":2147483648,"max_jobs":2},"steps":[{"name":"inventory","request":{"backend":"xair","operation":"inventory","budget":{"wall_ms":10000,"output_bytes":65536,"memory_bytes":2147483648,"max_items":128}}},{"name":"cfg","depends_on":["inventory"],"allow_partial_dependencies":true,"request":{"backend":"xair","operation":"cfg","budget":{"wall_ms":10000,"output_bytes":65536,"memory_bytes":2147483648,"max_items":128}}}]}')
request=$(jq -nc --arg id "$(jq -r .id <<<"$batch")" '{project:"smoke",id:$id}')
done_batch=$(action batch run "$request");jq -e '.jobs_started==2 and (.status=="completed" or .status=="partial")' <<<"$done_batch" >/dev/null
again=$(action batch run "$request");jq -e '.jobs_started==2' <<<"$again" >/dev/null
entities=$(run index entities --project smoke --kind function)
packet=$(action graph packet "$(jq -nc --arg id "$(jq -er '.records[0].id' <<<"$entities")" '{project:"smoke",id:$id,depth:2,limit:20,output_bytes:16384}')")
jq -e '.nodes|length>0' <<<"$packet" >/dev/null
gaps=$(action coverage report '{"project":"smoke","limit":20}');jq -e '.negative_inference_allowed==false' <<<"$gaps" >/dev/null
derived=$(action transform run "$(jq -nc --arg sha "$sha" '{project:"smoke",artifact:$sha,offset:0,size:2,spec:{method:"slice"}}')")
derived_sha=$(jq -r .artifact_sha256 <<<"$derived")
validation=$(action validate compare "$(jq -nc --arg sha "$derived_sha" '{project:"smoke",scope:{artifact_sha256:$sha},cases:[{actual_artifact:$sha,expected_hex:"4d5a"}]}')")
jq -e '.state=="validated"' <<<"$validation" >/dev/null
signature=$(action knowledge put "$(jq -nc --arg sha "$sha" --arg matched "$derived_sha" '{project:"smoke",kind:"signature",title:"Fixture header",scope:{artifact_sha256:$sha},body:{sha256:$matched,offset:0,size:2}}')")
recognition=$(action recognize scan "$(jq -nc --arg sha "$sha" '{project:"smoke",artifact:$sha,publish:true}')")
jq -e '[.findings[]|select(.kind=="exact_bytes_signature")]|length>0' <<<"$recognition" >/dev/null
hypothesis=$(action knowledge put "$(jq -nc --arg sha "$sha" --arg dependency "$(jq -r .id <<<"$signature")" '{project:"smoke",kind:"hypothesis",title:"Header hypothesis",scope:{artifact_sha256:$sha},body:{prediction:"Header is MZ",alternatives:[],unknowns:[]},dependencies:[{type:"record",id:$dependency}]}')")
signature_update=$(jq '{project,kind,title:(.title+" revised"),scope,body,id,expected_revision:.revision}' <<<"$signature")
action knowledge put "$signature_update" >/dev/null
stale=$(action knowledge show "$(jq -nc --arg id "$(jq -r .id <<<"$hypothesis")" '{project:"smoke",id:$id}')");jq -e '.freshness=="stale"' <<<"$stale" >/dev/null
bundle="$workspace-bundle";restored="$workspace-restored"
action bundle export "$(jq -nc --arg dest "$bundle" '{project:"smoke",destination:$dest}')" >/dev/null
action bundle import "$(jq -nc --arg src "$bundle" --arg dest "$restored" '{source:$src,destination:$dest}')" >/dev/null
old_workspace=$workspace;workspace=$restored
stale=$(action knowledge show "$(jq -nc --arg id "$(jq -r .id <<<"$hypothesis")" '{project:"smoke",id:$id}')");jq -e '.freshness=="stale"' <<<"$stale" >/dev/null
action retention plan '{}' >/dev/null
jq -nc --arg workspace "$old_workspace" --arg restored "$restored" '{status:"passed",workspace:$workspace,restored:$restored,checks:"IR native corpus, batch/resume, graph, coverage, transform, validator, recognition, dependencies, bundle and retention plan"}'
