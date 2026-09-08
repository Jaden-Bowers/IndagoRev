#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
ghidra="$(realpath "${1:?Ghidra distribution}")"
jdk="$(realpath "${2:?OpenJDK distribution}")"
stage="$root/out/runtime-payload/linux/ghidra"
test ! -e "$stage/java" || { echo 'Java stage exists; explicitly move it before restaging' >&2; exit 1; }
mkdir -p "$stage/distribution"
cp -rL "$ghidra/." "$stage/distribution/"
mkdir -p "$stage/java"
# Preserve the full JDK and materialize legal-file symlinks for immutable payloads.
cp -rL "$jdk/." "$stage/java/"
echo 'Private Ghidra and OpenJDK staged; rebuild indago to embed them.'
