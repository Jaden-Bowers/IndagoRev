#!/usr/bin/env bash
set -euo pipefail
executable=${1:?indago path}
fixture=${2:?fixture path}
workspace=$(mktemp -d "${INDAGO_SMOKE_ROOT:-${TMPDIR:-/tmp}}/indago-attach.XXXXXX")
"$executable" --workspace "$workspace" project create --name attach >/dev/null
"$fixture" wait &
target=$!
trap 'kill "$target" 2>/dev/null || true; wait "$target" 2>/dev/null || true' EXIT
sleep 0.1
session=$("$executable" --workspace "$workspace" runtime attach --project attach --pid "$target")
id=$(jq -er '.id' <<<"$session")
[[ $(jq -r '.state' <<<"$session") == stopped ]]
common=(--workspace "$workspace" runtime)
"$executable" "${common[@]}" registers --project attach --session "$id" | jq -e '.values' >/dev/null
"$executable" "${common[@]}" continue --project attach --session "$id" >/dev/null
"$executable" "${common[@]}" pause --project attach --session "$id" | jq -e '.state == "stopped"' >/dev/null
"$executable" "${common[@]}" detach --project attach --session "$id" | jq -e '.state == "detached"' >/dev/null
jq -n --arg workspace "$workspace" '{status:"passed",operation:"attach-pause-detach",workspace:$workspace}'
