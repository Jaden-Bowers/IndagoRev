#!/usr/bin/env bash
# Focused development check, not production qualification.
set -euo pipefail
executable=${1:?indago executable}; fixture=${2:?fixture}
workspace=$(mktemp -d /tmp/indago-workbench.XXXXXX)
run(){ local text rc=0; text=$("$executable" --workspace "$workspace" "$@") || rc=$?; if [[ $rc != 0 && $rc != 3 ]]; then echo "$text" >&2; return 1; fi; echo "$text"; }
run project create --name smoke >/dev/null
run target import --project smoke --file "$fixture" >/dev/null
inventory=$(run query --project smoke --backend xair --operation inventory --max-items 4096)
probe=$(jq -er '.data.symbols[]|select(.name=="runtime_probe")|.location.address' <<<"$inventory"|head -1)
session=$(run runtime launch --project smoke --file "$fixture")
id=$(jq -er .id <<<"$session")
request(){ printf '%s' "$2" > "$workspace/request.json"; run runtime "$1" --project smoke --session "$id" --request "$workspace/request.json"; }
trap 'run runtime terminate --project smoke --session "$id" >/dev/null 2>&1 || true' EXIT
bp=$(request breakpoint "$(jq -nc --arg address "$probe" '{static_address:$address,one_shot:false}')")
stop=$(request continue '{"wait":true}')
jq -e '.last_event.kind=="breakpoint"' <<<"$stop" >/dev/null
jq -e '.breakpoints|length>0' <<<"$(request breakpoints '{}')" >/dev/null
request remove-breakpoint "$(jq -nc --arg id "$(jq -r .native_breakpoint_id <<<"$bp")" '{breakpoint_id:$id}')" >/dev/null
jq -e '.frames|length>0' <<<"$(request stack '{}')" >/dev/null
regs=$(request registers '{}')
jq -e '.extended|length>0' <<<"$regs" >/dev/null
sp=$(jq -r '.values.rsp//.values.esp' <<<"$regs"); pc=$(jq -r '.values.rip//.values.eip' <<<"$regs")
capture=$(request capture "$(jq -nc --arg sp "$(printf '0x%x' "$((sp-128))")" --arg extra "$(printf '0x%x' "$((pc+128))")" '{memory:[{address:$sp,size:1024}],code_regions:[{address:$extra,size:32}]}')")
if [[ $(jq -r .arch <<<"$regs") == x86 ]]; then
  inputs=$(jq -nc --arg address "$(printf '0x%x' "$((sp+4))")" '{symbolic_memory:[{address:$address,size:1}]}')
else inputs='{"symbolic_registers":["rdi"]}'; fi
symbolic=$(request symbolic "$(jq -c --arg observation "$(jq -r .id <<<"$capture")" '.+{observation:$observation}' <<<"$inputs")")
validation=$(request validate-witness "$(jq -nc --arg observation "$(jq -r .id <<<"$symbolic")" '{observation:$observation,timeout_ms:10000}')")
jq -e '.verdict=="predicted destination observed"' <<<"$validation" >/dev/null
watch=$(request watchpoint '{"expression":"*(unsigned int*)&runtime_output","size":4,"access":"write"}')
stop=$(request continue '{"wait":true}'); jq -e '.last_event.kind=="breakpoint"' <<<"$stop" >/dev/null
request remove-breakpoint "$(jq -nc --arg id "$(jq -r .native_breakpoint_id <<<"$watch")" '{breakpoint_id:$id}')" >/dev/null
request step-out '{}' >/dev/null
analysis=$(request reanalyze "$(jq -nc --arg observation "$(jq -r .id <<<"$capture")" '{observation:$observation,backend:"xair",timeout_ms:10000}')")
jq -e '.data.derivation.regions|length==2' <<<"$analysis" >/dev/null
request detach '{}' >/dev/null
jq -nc --arg workspace "$workspace" --arg arch "$(jq -r .arch <<<"$regs")" '{status:"passed",workspace:$workspace,arch:$arch}'
