#!/usr/bin/env bash
set -euo pipefail
exe="$(realpath "${1:?indago executable}")"
fixture="$(realpath "${2:?ELF or PE fixture}")"
workspace="$(mktemp -d /tmp/indago-ghidra-smoke-XXXXXX)"
"$exe" --workspace "$workspace" project create --name smoke >/dev/null
"$exe" --workspace "$workspace" target import --project smoke --file "$fixture" >/dev/null
query() {
  local status=0
  "$exe" --workspace "$workspace" query --project smoke --backend ghidra --max-items 32 "$@" || status=$?
  test "$status" = 0 -o "$status" = 3
}
functions="$(query --operation functions --search runtime_probe)"
address="$(jq -er '.data.functions[0].entry' <<< "$functions")"
query --operation pcode --address "$address" | jq -e '.data.pcode.operations | length > 0' >/dev/null
query --operation tokens --address "$address" | jq -e '.data.decompilation.tokens | length > 0' >/dev/null
query --operation session | jq -e '.data.session.saved_program' >/dev/null
query --operation close >/dev/null
sleep 1
query --operation functions --search runtime_probe | jq -e '.data.functions | length > 0' >/dev/null
query --operation close >/dev/null
printf 'Ghidra basic smoke passed: %s\n' "$workspace"
