#!/usr/bin/env bash
# Small development smoke check. Requires jq; no production qualification implied.
set -euo pipefail
executable=${1:?native Linux indago path required}
fixture=${2:?ELF fixture path required}
workspace=$(mktemp -d "${INDAGO_SMOKE_ROOT:-${TMPDIR:-/tmp}}/indago-runtime-smoke.XXXXXX")
run() {
    local result rc=0
    result=$("$executable" --workspace "$workspace" "$@") || rc=$?
    if [[ $rc != 0 && $rc != 3 ]]; then echo "$result" >&2; return 1; fi
    if [[ $(jq -r '.status // .state // ""' <<<"$result") == failed ]]; then echo "$result" >&2; return 1; fi
    echo "$result"
}
run project create --name smoke >/dev/null
run target import --project smoke --file "$fixture" >/dev/null
inventory=$(run query --project smoke --backend xair --operation inventory --max-items 4096)
address=$(jq -er '.data.symbols[] | select(.name == "runtime_probe") | .location.address' <<<"$inventory" | head -1)
session=$(run runtime launch --project smoke --file "$fixture")
id=$(jq -er '.id' <<<"$session")
common=(--project smoke --session "$id")
cleanup() { "$executable" --workspace "$workspace" runtime terminate "${common[@]}" >/dev/null 2>&1 || true; }
trap cleanup EXIT
[[ $(jq -r .state <<<"$session") == stopped ]]
resolved=$(run runtime resolve "${common[@]}" --static-address "$address")
[[ $(jq -r '.location.artifact_sha256' <<<"$resolved") == $(jq -r '.artifact_sha256' <<<"$inventory") ]]
run runtime breakpoint "${common[@]}" --static-address "$address" >/dev/null
stop=$(run runtime continue "${common[@]}" --wait true)
[[ $(jq -r '.last_event.kind' <<<"$stop") == breakpoint ]]
registers=$(run runtime registers "${common[@]}")
sp=$(jq -r '.values.rsp // .values.esp' <<<"$registers")
jq -n --arg address "$(printf '0x%x' "$((sp-128))")" '{memory:[{address:$address,size:1024}]}' > "$workspace/capture-request.json"
capture=$(run runtime capture "${common[@]}" --request "$workspace/capture-request.json")
capture_id=$(jq -er .id <<<"$capture")
memory=$(run runtime memory "${common[@]}" --static-address "$address" --size 16)
[[ $(jq -r .size <<<"$memory") == 16 ]]
if [[ $(jq -r .arch <<<"$registers") == x86 ]]; then
    jq -n --arg address "$(printf '0x%x' "$((sp+4))")" '{symbolic_memory:[{address:$address,size:1}]}' > "$workspace/symbolic-request.json"
else
    jq -n '{symbolic_registers:["rdi"]}' > "$workspace/symbolic-request.json"
fi
symbolic=$(run runtime symbolic "${common[@]}" --observation "$capture_id" --mode solve_branch --request "$workspace/symbolic-request.json")
jq -e '.data.producer == "XAIR/XAIR_SYM" and (.data.results | length > 0)' <<<"$symbolic" >/dev/null
jq -e '[.data.results[0].branches[] | select(.native_verdict == "sat")] | length == 2' <<<"$symbolic" >/dev/null
run runtime step "${common[@]}" >/dev/null
trace=$(run runtime trace "${common[@]}" --max-steps 2)
jq -e '.observation_ids | length > 0' <<<"$trace" >/dev/null
evidence=$(run runtime observations "${common[@]}" --kind capture)
jq -e '.observations | length == 1' <<<"$evidence" >/dev/null
run runtime detach "${common[@]}" >/dev/null
trap - EXIT
jq -n --arg workspace "$workspace" --arg fixture "$fixture" --arg session "$id" '{status:"passed",fixture:$fixture,workspace:$workspace,session:$session}'
