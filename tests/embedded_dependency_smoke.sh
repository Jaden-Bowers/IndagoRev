#!/usr/bin/env bash
# Tiny native regression: same payload path/length, different embedded bytes.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
build=$(mktemp -d /tmp/indago-embedded-dependency.XXXXXX)
cmake -S "$root/tests/fixtures/embedded_payload" -B "$build" -G Ninja -DPAYLOAD_TEXT=alpha > "$build/configure-first.log" 2>&1
cmake --build "$build" > "$build/build-first.log" 2>&1
[[ $("$build/embedded_dependency") == alpha ]]
stamp=$(stat -c %Y "$build/payload.S")
sleep 1
cmake -S "$root/tests/fixtures/embedded_payload" -B "$build" -DPAYLOAD_TEXT=bravo > "$build/configure-second.log" 2>&1
[[ $(stat -c %Y "$build/payload.S") == "$stamp" ]]
cmake --build "$build" > "$build/build-second.log" 2>&1
[[ $("$build/embedded_dependency") == bravo ]]
jq -nc --arg logs "$build" '{status:"passed",same_path:true,same_length:true,assembly_source_unchanged:true,embedded_bytes_updated:true,logs:$logs}'
