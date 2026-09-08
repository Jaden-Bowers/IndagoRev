#!/usr/bin/env bash
# Each individual suite has a 180s deadline; invoke this driver with timeout 480s.
set -euo pipefail
exe=${1:?absolute indago executable}
root=$(cd "$(dirname "$0")/.." && pwd)
report=$(mktemp -d /tmp/indago-linux-qualification.XXXXXX)
gcc -g -O0 -rdynamic "$root/tests/runtime_fixture.c" -o "$report/fixture64"
gcc -m32 -g -O0 -rdynamic "$root/tests/runtime_fixture.c" -o "$report/fixture32"
suite(){
  local name=$1 start rc=0;shift
  start=$(date +%s)
  timeout --kill-after=5s 180s "$@" > "$report/$name.stdout.log" 2> "$report/$name.stderr.log" || rc=$?
  jq -nc --arg name "$name" --arg report "$report" --argjson rc "$rc" --argjson elapsed "$(($(date +%s)-start))" '{suite:$name,status:(if $rc==0 then "passed" else "failed" end),exit_code:$rc,elapsed_seconds:$elapsed,timeout_seconds:180,logs:$report}'
  if [[ $rc != 0 ]];then cat "$report/$name.stdout.log" "$report/$name.stderr.log";return "$rc";fi
}
suite knowledge bash "$root/tests/knowledge_cli_smoke.sh" "$exe" /mnt/c/Users/Jaden/Desktop/Projects/IR/xair/tests/corpus/phase3
suite harness_pe bash "$root/tests/harness_cli_smoke.sh" "$exe" "$root/xair/XAIR/tests/corpus/phase3/control-flow.pe64"
for arch in 64 32;do
  suite "harness_elf$arch" bash "$root/tests/harness_cli_smoke.sh" "$exe" "$report/fixture$arch"
  suite "runtime_elf$arch" bash "$root/tests/runtime_workbench_smoke.sh" "$exe" "$report/fixture$arch"
done
