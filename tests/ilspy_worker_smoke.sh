#!/usr/bin/env bash
set -euo pipefail
worker="$(realpath "${1:?worker}")"
fixture="$(realpath "${2:?source-built managed fixture}")"
digest="$(sha256sum "$fixture" | cut -d' ' -f1)"
call() {
  local operation="$1" token="${2:-}" output code=0
  output="$(timeout --kill-after=2s 10s "$worker" "$(jq -nc --arg path "$fixture" --arg hash "$digest" --arg operation "$operation" --arg token "$token" '{path:$path,sha256:$hash,operation:$operation,token:$token,wall_ms:5000,output_bytes:65536,limit:32}')")" || code=$?
  [[ "$code" == 0 || "$code" == 3 ]] || { printf '%s\n' "$output" >&2; return 1; }
  jq -e '.target_executed==false and .dependency_resolution=="disabled"' <<< "$output" >/dev/null
  printf '%s\n' "$output"
}
call inventory | jq -e '.method_count>=3' >/dev/null
call types | jq -e '.types[0].location.address_space=="managed_metadata"' >/dev/null
token="$(call methods | jq -er '.methods[]|select(.name=="Select")|.token')"
call decompile "$token" | jq -e '.pseudocode|contains("Select")' >/dev/null
call assembly "$token" | jq -e '.tokens | any(.kind=="il_offset_reference" and .is_definition==true)' >/dev/null
jq -nc --arg fixture "$digest" '{status:"passed",fixture_sha256:$fixture,target_executed:false}'
