#!/usr/bin/env bash
# Inspect/stage an upstream native package privately; no package installation,
# sysctl, PMU, ptrace policy, service or VM configuration changes.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
archive=/mnt/c/Users/Jaden/.cache/indago/rr/rr-5.9.0-Linux-x86_64.tar.gz
destination=/home/jaden/.cache/indago/rr-5.9.0
free=$(df -B1 --output=avail /mnt/c | tail -n 1 | tr -d ' ')
((free>21474836480+134217728)) || { echo 'Insufficient rr staging storage' >&2;exit 1; }
[[ $(sha256sum "$archive" | cut -d' ' -f1) == 1e229f0b24ca4f6feb325895ae57eb8792b92c0250ec2e68d292d2fe97e71864 ]] || { echo 'rr package hash mismatch' >&2;exit 1; }
bad=$(tar -tf "$archive" | awk '$0 !~ /^rr-5\.9\.0-Linux-x86_64\// || $0 ~ /(^|\/)\.\.(\/|$)/ {print;exit}')
[[ -z "$bad" ]] || { echo 'Unexpected rr package path' >&2;exit 1; }
if [[ -e "$destination" ]];then echo 'rr staging directory exists; inspect rather than overwrite' >&2;exit 1;fi
mkdir -p "$destination"
tar -xf "$archive" --strip-components=1 -C "$destination"
timeout --kill-after=2s 10s "$destination/bin/rr" --version
ldd "$destination/bin/rr"
printf 'Upstream rr staged privately; execution compatibility not yet established.\n'
