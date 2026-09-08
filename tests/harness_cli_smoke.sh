#!/usr/bin/env bash
set -euo pipefail
exe=${1:?executable};fixture=${2:?source-backed fixture}
workspace=$(mktemp -d /tmp/indago-harness-cli.XXXXXX)
run(){ local text rc=0;text=$("$exe" --workspace "$workspace" "$@")||rc=$?;if [[ $rc != 0 && $rc != 3 && $rc != 130 ]];then echo "$text" >&2;return 1;fi;echo "$text"; }
harness(){ printf '%s' "$2" > "$workspace/request.json";run "${3:-harness}" "$1" --request "$workspace/request.json"; }
owned(){ local revision;revision=$(run harness show --project smoke --id "$id"|jq .revision);harness "$1" "$(jq -nc --argjson request "$2" --arg id "$id" --arg token "$token" --argjson revision "$revision" '$request+{project:"smoke",id:$id,owner_token:$token,expected_revision:$revision}')"; }
run project create --name smoke >/dev/null
target=$(run target import --project smoke --file "$fixture")
system=$(harness create "$(jq -nc --arg id "$(jq -r .id <<<"$target")" '{project:"smoke",manifest:{os:"linux",architecture:"mixed",components:[{name:"fixture",target_id:$id,role:"program",path:"bin/fixture"}],launches:[{name:"entry",component:"fixture"}]}}')" system)
inv=$(harness create "$(jq -nc --arg manifest "$(jq -r .id <<<"$system")" '{project:"smoke",system_manifest:$manifest,workbench_mutations:true,derived_artifacts:{max_artifacts:1,max_bytes:1},objective:"Inventory synthetic executable",required_facts:["file inventory"],owner:{mode:"external",name:"offline fixture"},budget:{max_actions:5,wall_ms:50000,output_bytes:327680}}')")
id=$(jq -r .id <<<"$inv");token=$(jq -r .owner_token <<<"$inv")
action=$(owned propose '{"key":"inventory","proposal":{"gap":"file inventory","expected_evidence":"Native format","prediction":"PE or ELF","fallback":"Report missing inventory"},"request":{"backend":"xair","operation":"inventory","budget":{"wall_ms":10000,"output_bytes":65536,"memory_bytes":2147483648,"max_items":128}}}')
args=$(jq -nc --arg id "$(jq -r .id <<<"$action")" '{action_id:$id}')
result=$(owned run "$args");jq -e '(.status=="completed" or .status=="partial") and (.result.evidence_ids|length>0)' <<<"$result" >/dev/null
again=$(owned run "$args");[[ $(jq -r .job_id <<<"$again") == $(jq -r .job_id <<<"$result") ]]
packet=$(harness context "$(jq -nc --arg id "$id" '{project:"smoke",id:$id,output_bytes:8192}')");[[ ${#packet} -le 8192 && $packet != *"$token"* ]]
proposal='{"gap":"byte hypothesis","expected_evidence":"knowledge receipt or counterexample","prediction":"finite bytes equal","fallback":"retain mismatch"}'
note=$(owned propose "$(jq -nc --argjson proposal "$proposal" '{key:"note",proposal:$proposal,request:{backend:"workbench",operation:"knowledge.put",arguments:{kind:"summary",title:"Synthetic byte hypothesis",body:{text:"Expected byte zero is deliberately wrong"}}}}')")
noted=$(owned run "$(jq -nc --arg id "$(jq -r .id <<<"$note")" '{action_id:$id}')")
jq -e '.result.state=="inferred" and (.result.knowledge_ids|length>0)' <<<"$noted" >/dev/null
comparison=$(owned propose "$(jq -nc --argjson proposal "$proposal" --arg subject "$(jq -r '.result.knowledge_ids[0]' <<<"$noted")" --arg sha "$(jq -r .artifact_sha256 <<<"$inv")" '{key:"compare",proposal:$proposal,request:{backend:"workbench",operation:"validate.compare",arguments:{subject:$subject,cases:[{actual_artifact:$sha,expected_hex:"00"}]}}}')")
compared=$(owned run "$(jq -nc --arg id "$(jq -r .id <<<"$comparison")" '{action_id:$id}')")
jq -e '.status=="completed" and .result.passed==false and (.result.counterexamples|length>0)' <<<"$compared" >/dev/null
revision=$(owned propose "$(jq -nc --argjson proposal "$proposal" --arg subject "$(jq -r '.result.knowledge_ids[0]' <<<"$noted")" '{key:"revise",proposal:$proposal,request:{backend:"workbench",operation:"knowledge.revise",arguments:{id:$subject,expected_revision:1,state:"contradicted",body:{text:"The zero-byte expectation failed its finite comparison; behavior remains unknown"}}}}')")
revised=$(owned run "$(jq -nc --arg id "$(jq -r .id <<<"$revision")" '{action_id:$id}')")
jq -e --arg subject "$(jq -r '.result.knowledge_ids[0]' <<<"$noted")" '.status=="completed" and .result.record_revision==2 and .result.knowledge_ids[0]==$subject' <<<"$revised" >/dev/null
derive=$(owned propose "$(jq -nc --argjson proposal "$proposal" '{key:"derive",proposal:$proposal,request:{backend:"workbench",operation:"transform.run",arguments:{offset:0,size:1,spec:{method:"slice"}}}}')")
derived=$(owned run "$(jq -nc --arg id "$(jq -r .id <<<"$derive")" '{action_id:$id}')")
jq -e '.status=="completed" and .result.derived_artifact.admitted==true and .result.derived_artifact.bytes==1' <<<"$derived" >/dev/null
scoped=$(harness scope "$(jq -nc --arg id "$id" '{project:"smoke",id:$id}')")
jq -e '(.components|length)==2 and .root_components_mutable==false' <<<"$scoped" >/dev/null
report=$(owned finish "$(jq -nc --argjson refs "$(jq .result.evidence_ids <<<"$result")" '{status:"partial",answer:"Native inventory collected; behavior not investigated",claims:[{fact:"file inventory",text:"Native backend returned file inventory",evidence_ids:$refs,limitations:["Not behavioral proof"]}],gaps:["Behavior uninvestigated"]}')")
jq -e '.report.verified_solve==false' <<<"$report" >/dev/null
[[ $(jq -r .report.reproducibility.system_manifest.sha256 <<<"$report") == $(jq -r .body.sha256 <<<"$system") ]]
run harness audit --project smoke --id "$id" --limit 4 | jq -e '.status=="citations_current" and .report_modified==false and .verified_solve==false' >/dev/null
first_page=$(run harness actions --project smoke --id "$id" --limit 1)
second_page=$(run harness actions --project smoke --id "$id" --limit 1 --offset 1)
jq -e '(.records|length)==1 and .next_offset==1' <<<"$first_page" >/dev/null
jq -e --arg previous "$(jq -r .records[0].id <<<"$first_page")" '(.records|length)==1 and .records[0].id!=$previous' <<<"$second_page" >/dev/null
owned release '{}' >/dev/null
jq -nc --arg workspace "$workspace" --arg id "$id" '{status:"passed",workspace:$workspace,investigation:$id,checks:"native CLI ownership, action run/reuse, knowledge/validator receipts, derived admission, context, partial report"}'
