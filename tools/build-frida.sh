#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
build="${1:-$HOME/.cache/indago/frida-worker}"
cmake -S "$root/workers/frida" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DFRIDA_DEVKIT="$root/vendor/frida/linux"
cmake --build "$build" -j4
install -D "$build/indago_frida_host" "$root/out/runtime-payload/linux/frida/indago_frida_host"
cp "$root/vendor/frida/COPYING" "$root/out/runtime-payload/linux/frida/COPYING"
echo 'Frida staged. Rebuild indago to embed it.'
