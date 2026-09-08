#!/bin/sh
set -eu
exe=$1
fixture=$2
workspace=$(mktemp -d "$HOME/.cache/indago/instrument-smoke.XXXXXX")
run() {
    set +e
    response=$("$exe" --workspace "$workspace" "$@")
    code=$?
    set -e
    case "$code" in 0|3|130) ;; *) printf '%s\n' "$response" >&2; exit 1;; esac
    printf '%s\n' "$response"
}
wait_run() {
    for iteration in $(seq 1 200); do
        state=$(run runtime status --project smoke --session "$1")
        case "$(printf '%s' "$state" | jq -r .state)" in
            starting|running) sleep 0.05;;
            *) printf '%s\n' "$state"; return;;
        esac
    done
    return 1
}
run project create --name smoke >/dev/null
session=$(run runtime instrument --project smoke --file "$fixture" --max-events 8 --timeout-ms 2000 | jq -r .id)
state=$(wait_run "$session")
test "$(printf '%s' "$state" | jq -r .result_status)" = partial
blocks=$(run runtime observations --project smoke --session "$session" --kind instrumentation_block)
printf '%s' "$blocks" | jq -e '.observations | length == 8' >/dev/null
printf '%s' "$blocks" | jq -e '.observations[0].data.location.anchor_id' >/dev/null
# Process arguments use the existing JSON runtime request interface.
request="$workspace/wait.json"
printf '{"argv":["wait"]}\n' > "$request"
cancelled=$(run runtime instrument --project smoke --file "$fixture" --max-events 8 --timeout-ms 5000 --request "$request" | jq -r .id)
run runtime cancel --project smoke --session "$cancelled" >/dev/null
state=$(wait_run "$cancelled")
test "$(printf '%s' "$state" | jq -r .result_status)" = cancelled
printf '{"status":"passed","workspace":"%s","bounded_session":"%s","cancelled_session":"%s"}\n' "$workspace" "$session" "$cancelled"
