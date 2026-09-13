#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
build="${1:-$repo/out/emulation-linux}"
payload="${2:-$repo/out/runtime-payload/linux}"
cmake -S "$repo/workers/emulation" -B "$build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$payload"
cmake --build "$build" --parallel 4
cmake --install "$build"
echo 'Reconfigure and rebuild Indago to embed the emulation worker and notices.'
