#!/usr/bin/env bash
# Bounded development parity check, not broad qualification. Invoke with timeout 480s.
set -euo pipefail
exe=${1:?absolute Linux indago binary required}
root=$(cd "$(dirname "$0")/.." && pwd)
free=$(df -B1 --output=avail /mnt/c | tail -n1 | tr -d ' ')
((free>21474836480+536870912)) || { echo '20 GiB floor plus 512 MiB reservation required' >&2; exit 1; }
report=$(mktemp -d "$root/out/reliability-linux.XXXXXX")
suite(){
  local name=$1 start rc=0;shift;start=$(date +%s)
  timeout --kill-after=5s 90s "$@" > "$report/$name.stdout.log" 2> "$report/$name.stderr.log" || rc=$?
  jq -nc --arg name "$name" --arg report "$report" --argjson rc "$rc" --argjson elapsed "$(($(date +%s)-start))" \
    '{suite:$name,status:(if $rc==0 then "passed" else "failed" end),elapsed_seconds:$elapsed,exit_code:$rc,logs:$report}'
  if ((rc));then cat "$report/$name.stdout.log" "$report/$name.stderr.log";return "$rc";fi
}
for bits in 64 32;do
  gcc -m"$bits" -g -O0 -rdynamic "$root/tests/runtime_fixture.c" -o "$report/fixture$bits"
  sha256sum "$root/tests/runtime_fixture.c" "$report/fixture$bits" > "$report/fixture$bits.sha256"
  suite "harness_elf$bits" bash "$root/tests/harness_cli_smoke.sh" "$exe" "$report/fixture$bits"
  suite "runtime_elf$bits" bash "$root/tests/runtime_workbench_smoke.sh" "$exe" "$report/fixture$bits"
done
