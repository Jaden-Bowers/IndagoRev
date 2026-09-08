#!/usr/bin/env bash
set -euo pipefail
exe=${1:?executable}; fixture=${2:?fixture}
workspace=$(mktemp -d /tmp/indago-write-execute.XXXXXX)
run(){ local text rc=0; text=$("$exe" --workspace "$workspace" "$@") || rc=$?; if [[ $rc != 0 && $rc != 3 ]];then echo "$text" >&2;return 1;fi;echo "$text"; }
run project create --name smoke >/dev/null
printf '%s' '{"telemetry":"effects","code_scope":"application"}' > "$workspace/effects.json"
session=$(run runtime instrument --project smoke --file "$fixture" --request "$workspace/effects.json" --max-events 10000 --timeout-ms 3000)
id=$(jq -er .id <<<"$session");common=(--project smoke --session "$id")
for ((i=0;i<300;i++));do state=$(run runtime status "${common[@]}");if [[ $(jq -r .state <<<"$state") != starting && $(jq -r .state <<<"$state") != running ]];then break;fi;sleep 0.05;done
[[ $(jq -r .state <<<"$state") != failed ]]
writes=$(run runtime observations "${common[@]}" --kind write_execute)
write=$(jq -cer '[.observations[]|select(.data.location.mapping_status!="file_identity_only")][0]' <<<"$writes")
jq -e '.data.write_observation!=null' <<<"$write" >/dev/null
feedback=$(run runtime feedback "${common[@]}" --observation "$(jq -r .id <<<"$write")" --backend xair)
jq -e '.data.derivation.regions|length>0' <<<"$feedback" >/dev/null
modules=$(run runtime observations "${common[@]}" --kind module_loaded)
jq -e '.observations|length>1' <<<"$modules" >/dev/null
jq -nc --arg workspace "$workspace" '{status:"passed",workspace:$workspace}'
