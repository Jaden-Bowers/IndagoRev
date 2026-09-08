#!/usr/bin/env bash
# Only compiles/runs the adjacent benign source fixture. No target argument,
# recording of unrelated programs, kernel policy changes or CPU spoofing.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
case "${2:-release}" in
  release) rr=/home/jaden/.cache/indago/rr-5.9.0/bin/rr;;
  source) rr=/home/jaden/.cache/indago/rr-build/bin/rr;;
  *) echo 'Probe tool must be release or source' >&2;exit 2;;
esac
bits=${1:-64}
case "$bits" in 64) flags=();;32) flags=(-m32);;*) echo 'Probe architecture must be 32 or 64' >&2;exit 2;;esac
free=$(df -B1 --output=avail /mnt/c | tail -n 1 | tr -d ' ')
((free>21474836480+134217728)) || { echo 'Insufficient replay-probe space' >&2;exit 1; }
mkdir -p "$root/out/qualification-rr"
report=$(mktemp -d "$root/out/qualification-rr/probe.XXXXXX")
# rr's shared-memory scratch must be a native Linux filesystem, even when the
# persistent trace lives in the user's Windows-mounted project workspace.
native_tmp=$(mktemp -d /tmp/indago-rr-shmem.XXXXXX)
export RR_TMPDIR="$native_tmp"
trap 'rmdir -- "$native_tmp" 2>/dev/null || true' EXIT
ulimit -c 0
ulimit -f 65536
gcc "${flags[@]}" -O0 -g "$root/tests/fixtures/rr/main.c" -o "$report/fixture"
sha256sum "$report/fixture" > "$report/fixture.sha256"
rc=0
timeout --kill-after=2s 20s "$rr" record -o "$report/trace" "$report/fixture" > "$report/record.stdout" 2> "$report/record.stderr" || rc=$?
if ((rc!=0));then
  jq -nc --arg report "$report" --argjson rc "$rc" '{status:"not_qualified",phase:"record",native_exit_code:$rc,replay_attempted:false,logs:$report,kernel_policy_changed:false,cpu_spoofing:false}'
  head -c 4096 "$report/record.stderr"
  exit 3
fi
[[ $(cat "$report/record.stdout") == 'indago-rr-fixture:42' ]] || { echo 'Recorded fixture output mismatch' >&2;exit 1; }
timeout --kill-after=2s 20s "$rr" pack "$report/trace" > "$report/pack.stdout" 2> "$report/pack.stderr"
timeout --kill-after=2s 20s "$rr" replay -a "$report/trace" > "$report/replay.stdout" 2> "$report/replay.stderr"
cmp "$report/record.stdout" "$report/replay.stdout"
timeout --kill-after=2s 10s "$rr" traceinfo "$report/trace" > "$report/traceinfo.json"
jq -e 'type=="object"' "$report/traceinfo.json" >/dev/null
bytes=$(du -sb "$report" | cut -f1)
((bytes<=134217728)) || { echo 'Replay-probe artifact budget exceeded' >&2;exit 1; }
jq -nc --arg report "$report" --arg bits "$bits" --argjson bytes "$bytes" '{status:"passed",phase:"record_and_autopilot_replay",bits:$bits,logs:$report,artifact_bytes:$bytes,kernel_policy_changed:false,cpu_spoofing:false,scope:"one source-backed ELF fixture; not product replay qualification"}'
