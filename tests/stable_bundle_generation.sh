#!/usr/bin/env bash
# Reconfigure an existing build and verify unchanged bundle metadata/source.
# No payload copy, deletion, download or hash-cache bypass.
set -euo pipefail
build=${1:?existing native build directory}
root=$(cd "$(dirname "$0")/.." && pwd)
[[ -f $build/CMakeCache.txt ]]
files=(engine_payload.hpp engines.S bundle-profile.json)
before=()
for name in "${files[@]}"; do
  before+=("$(stat -c %Y "$build/generated/$name"):$(sha256sum "$build/generated/$name")")
done
report=$(mktemp -d /tmp/indago-stable-generation.XXXXXX)
start=$SECONDS
timeout --kill-after=5s 480s cmake -S "$root" -B "$build" > "$report/configure.log" 2>&1
for i in "${!files[@]}"; do
  current="$(stat -c %Y "$build/generated/${files[$i]}"):$(sha256sum "$build/generated/${files[$i]}")"
  if [[ $current != "${before[$i]}" ]]; then
    echo "Generated input changed: ${files[$i]}" >&2
    exit 1
  fi
done
jq -nc --argjson elapsed "$((SECONDS-start))" --arg report "$report" \
  '{status:"passed",unchanged_files:3,elapsed_seconds:$elapsed,logs:$report,integrity_hashing:"unchanged"}'
