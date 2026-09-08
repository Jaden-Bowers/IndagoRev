#!/usr/bin/env bash
set -euo pipefail
exe="$(realpath "${1:?indago executable}")"
fixture="$(realpath "${2:?trusted telemetry fixture}")"
backend="${3:-xair}"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/indago-frida-XXXXXXXX")"
call() {
  local raw code=0
  raw="$("$exe" --workspace "$workspace" "$@")" || code=$?
  if [[ $code != 0 && $code != 3 && $code != 130 ]]; then echo "$raw" >&2; return 1; fi
  printf '%s\n' "$raw"
}
wait_run() {
  local value
  for ((i=0;i<300;i++)); do
    value="$(call runtime status --project smoke --session "$1")"
    case "$(jq -r .state <<<"$value")" in exited|failed|cancelled) printf '%s\n' "$value"; return;; esac
    sleep .025
  done
  return 1
}
call project create --name smoke >/dev/null
run="$(call runtime instrument --project smoke --file "$fixture" --backend frida --recipe code --max-events 256 --timeout-ms 3000 | jq -r .id)"
wait_run "$run" | jq -e '.result_status=="completed"' >/dev/null
capture="$(call runtime observations --project smoke --session "$run" --kind code_capture | jq -er '.observations[0].id')"
call runtime reanalyze --project smoke --session "$run" --observation "$capture" --backend "$backend" | jq -e '.data.analyses|all(.status!="failed")' >/dev/null
call runtime identities --project smoke --session "$run" | jq -e '.identities|length>0' >/dev/null
io="$(call runtime instrument --project smoke --file "$fixture" --backend frida --recipe io --max-events 256 --timeout-ms 3000 | jq -r .id)"
wait_run "$io" >/dev/null
call runtime observations --project smoke --session "$io" --kind api_enter | jq -e '.observations|length>0' >/dev/null
for recipe in config network; do
  extra=$(call runtime instrument --project smoke --file "$fixture" --backend frida --recipe "$recipe" --max-events 512 --timeout-ms 3000 | jq -r .id)
  wait_run "$extra" >/dev/null
  expected=getenv; [[ $recipe != network ]] || expected=connect
  call runtime observations --project smoke --session "$extra" --kind api_enter | jq -e --arg api "$expected" '[.observations[]|select(.data.native.payload.api==$api)]|length>0' >/dev/null
  if [[ $recipe == network ]];then
    call runtime identities --project smoke --session "$extra" --kind socket --limit 100 | jq -e '(.identities|length)>=2 and (.identities|all(.kind=="socket" and .record.creation_observed==true and .record.validity=="creation_api_succeeded"))' >/dev/null
    call runtime observations --project smoke --session "$extra" --kind api_leave --limit 1000 | jq -e '[.observations[]|select(.data.socket_event=="close_api_success")]|length>=2' >/dev/null
    call runtime network --project smoke --session "$extra" --limit 1 | jq -e '(.events|length)==1 and .next_offset!=null and .packet_capture==false and (.events[0].observation_sha256|length)==64' >/dev/null
    cursor=$(call runtime network --project smoke --session "$extra" --from 0 --limit 1)
    jq -e '(.events|length)==1 and .next_from!=null and .scanned_observations<=256' <<<"$cursor" >/dev/null
    call runtime network --project smoke --session "$extra" --from "$(jq -r .next_from <<<"$cursor")" --to "$(jq -r .snapshot_to <<<"$cursor")" --limit 1 | jq -e --argjson previous "$(jq .events[0].sequence <<<"$cursor")" '(.events|length)==1 and .events[0].sequence>$previous' >/dev/null
    socket_id=$(call runtime identities --project smoke --session "$extra" --kind socket --limit 1 | jq -er '.identities[0].record.id')
    call runtime network --project smoke --session "$extra" --id "$socket_id" --limit 100 | jq -e --arg id "$socket_id" '(.events|length)>0 and (.events|all(.socket.id==$id))' >/dev/null
    calls=$(call runtime identities --project smoke --session "$extra" --kind api_call --limit 100)
    jq -e '[.identities[]|select(.record.pair_complete==true)]|length>=2' <<<"$calls" >/dev/null
    pair=$(jq -c '[.identities[]|select(.record.pair_complete==true)][0].record' <<<"$calls")
    call runtime identities --project smoke --session "$extra" --kind api_call --id "$(jq -r .id <<<"$pair")" | jq -e --arg id "$(jq -r .id <<<"$pair")" '(.identities|length)==1 and .identities[0].record.id==$id' >/dev/null
    call runtime observations --project smoke --session "$extra" --id "$(jq -r .entry_observation <<<"$pair")" | jq -e --arg id "$(jq -r .id <<<"$pair")" '.observations[0].kind=="api_enter" and .observations[0].data.call_id==$id' >/dev/null
    call runtime observations --project smoke --session "$extra" --id "$(jq -r .return_observation <<<"$pair")" | jq -e --arg id "$(jq -r .id <<<"$pair")" '.observations[0].kind=="api_leave" and .observations[0].data.call_id==$id' >/dev/null
  fi
done
limited="$(call runtime instrument --project smoke --file "$fixture" --backend frida --recipe modules --max-events 2 --timeout-ms 3000 | jq -r .id)"
wait_run "$limited" | jq -e '.result_status=="partial"' >/dev/null
jq -n --arg workspace "$workspace" --arg session "$run" --arg capture "$capture" '{status:"passed",workspace:$workspace,session:$session,capture:$capture}'
