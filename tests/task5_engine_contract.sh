#!/usr/bin/env bash
# Source-backed benign fixture; no host policy changes or arbitrary targets.
set -euo pipefail
exe=$(realpath "${1:?indago}"); fixture=$(realpath "${2:?fixture}"); shift 2
root=$(mktemp -d "${TMPDIR:-/tmp}/indago-engine-inputs.XXXXXX")
"$exe" --workspace "$root/state" project create --name engines >/dev/null
invoke() {
  printf '%s' "$2" > "$root/request.json"
  timeout --kill-after=2 15 "$exe" --workspace "$root/state" runtime "$1" --request "$root/request.json"
}
result=0
for engine in "${@:-debugger}"; do
  op=instrument; [[ $engine != debugger ]] || op=launch; [[ $engine != rr ]] || op=record
  req=$(jq -nc --arg op "$op" --arg engine "$engine" --arg file "$fixture" '{operation:$op,project:"engines",file:$file,argv:["--fixture"],input_hex:"7965730a",files:{payload:"626f756e64"},environment:{EXPERIMENT_VALUE:"explicit"},timeout_ms:3000} + (if $engine=="debugger" then {lifetime_ms:8000,terminate_on_expiry:true} elif $engine=="rr" then {backend:"rr",trace_bytes:16777216} else {backend:$engine,max_events:64} end)')
  state=$(invoke "$op" "$req") || true
  printf '%s' "$state" > "$root/$engine-start.json"
  session=$(jq -r '.id // empty' <<<"$state")
  if [[ -z $session ]];then result=1;continue;fi
  for attempt in {1..12}; do
    status=$(jq -r '.state // "failed"' <<<"$state")
    case "$status" in completed|failed|exited|terminated|cancelled|detached) break;; esac
    if [[ $engine == debugger && $status == stopped ]];then
      invoke continue "$(jq -nc --arg s "$session" '{operation:"continue",project:"engines",session:$s,wait:true,timeout_ms:1000}')" >/dev/null || true
    fi
    state=$(invoke status "$(jq -nc --arg s "$session" '{operation:"status",project:"engines",session:$s}')") || true
    sleep .05
  done
  output="$root/state/runtime-artifacts/$session/inputs/delivery.txt"
  delivered=false; if [[ -f $output && $(<"$output") == accepted:explicit:bound ]];then delivered=true;else result=1;fi
  jq -nc --arg engine "$engine" --arg root "$root" --arg session "$session" --argjson delivered "$delivered" --argjson state "$state" '{engine:$engine,root:$root,session:$session,delivered:$delivered,state:$state}' > "$root/$engine-result.json"
  jq '{engine,root,session,delivered,state:.state.state,diagnostic:.state.diagnostic}' "$root/$engine-result.json"
  if [[ $engine == rr && $(jq -r '.replay_ready // false' <<<"$state") == true ]];then
    replay=$(invoke replay "$(jq -nc --arg s "$session" '{operation:"replay",project:"engines",session:$s,timeout_ms:3000,trace_bytes:16777216}')") || true
    replay_id=$(jq -r '.id' <<<"$replay")
    for attempt in {1..30}; do
      case $(jq -r '.state' <<<"$replay") in exited|failed|cancelled)break;;esac
      sleep .1;replay=$(invoke status "$(jq -nc --arg s "$replay_id" '{operation:"status",project:"engines",session:$s}')") || true
    done
    printf '%s' "$replay" > "$root/rr-replay-result.json"
    jq '{id,state,result_status,diagnostic,replay_ready}' <<<"$replay"
    [[ $(jq -r '.result_status' <<<"$replay") == completed ]]||result=1
  fi
  cleanup=cancel;[[ $engine != debugger ]]||cleanup=terminate
  invoke "$cleanup" "$(jq -nc --arg s "$session" --arg op "$cleanup" '{operation:$op,project:"engines",session:$s,timeout_ms:1000}')" >/dev/null || true
done
exit "$result"
