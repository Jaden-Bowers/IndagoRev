#!/usr/bin/env bash
set -euo pipefail
executable=${1:?executable}; fixture=${2:?fixture}
workspace=$(mktemp -d /tmp/indago-process-next.XXXXXX)
run(){ local text rc=0; text=$("$executable" --workspace "$workspace" "$@") || rc=$?; if [[ $rc != 0 && $rc != 3 ]];then echo "$text" >&2;return 1;fi;echo "$text"; }
run project create --name smoke >/dev/null
printf '%s' '{"argv":["children"],"follow_children":true}' > "$workspace/follow.json"
session=$(run runtime launch --project smoke --file "$fixture" --request "$workspace/follow.json")
id=$(jq -er .id <<<"$session")
common=(--project smoke --session "$id")
trap 'run runtime terminate "${common[@]}" >/dev/null 2>&1 || true' EXIT
found=false
for ((i=0;i<12;i++)); do
  stop=$(run runtime continue "${common[@]}" --wait true)
  [[ $(jq -r .state <<<"$stop") != exited ]] || break
  processes=$(run runtime processes "${common[@]}")
  if [[ $(jq '[.groups[]|select(.pid!=null)]|length' <<<"$processes") -gt 1 ]];then found=true;break;fi
done
[[ $found == true ]]
while read -r pid;do run runtime select-process "${common[@]}" --pid "$pid" >/dev/null;done < <(jq -r '.groups[]|select(.pid!=null)|.pid' <<<"$processes")
created=$(run runtime observations "${common[@]}" --kind process_created)
jq -e '[.observations[]|select(.data.parent_process_id!=null)]|length>0' <<<"$created" >/dev/null
run runtime terminate "${common[@]}" >/dev/null
jq -nc --arg workspace "$workspace" '{status:"passed",workspace:$workspace}'
