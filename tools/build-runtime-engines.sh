#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_root=${INDAGO_ENGINE_BUILD_ROOT:-"$HOME/.cache/indago"}
jobs=${INDAGO_BUILD_JOBS:-6}
test "$(cat "$root/vendor/dynamorio/INDAGO_UPSTREAM_REVISION")" = 59352ff71fefdb8542fc5bd2ae3b76181a50072e
for bits in 64 32; do
    engine="$build_root/dr-native$bits"
    worker="$build_root/dr-worker$bits"
    cmake -S "$root/vendor/dynamorio" -B "$engine" -G Ninja \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-m$bits -std=gnu11" -DCMAKE_CXX_FLAGS="-m$bits" \
      -DDR_DO_NOT_DEFINE_bool:INTERNAL= -DHAVE_DR_DO_NOT_DEFINE_bool:INTERNAL=FALSE \
      -DDISABLE_WARNINGS=ON -DBUILD_TESTS=OFF -DBUILD_DOCS=OFF -DBUILD_SAMPLES=OFF -DBUILD_CLIENTS=OFF -DBUILD_EXT=OFF
    cmake --build "$engine" --target dynamorio drinjectlib drconfiglib -j "$jobs"
    cmake -S "$root/workers/dynamorio" -B "$worker" -G Ninja \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-m$bits" -DDynamoRIO_DIR="$engine/cmake" -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    cmake --build "$worker" -j "$jobs"
    payload="$root/out/runtime-payload/linux/dynamorio"
    install -D "$engine/lib$bits/release/libdynamorio.so" "$payload/lib$bits/release/libdynamorio.so"
    install -D "$worker/indago_dr_host" "$payload/bin$bits/indago_dr_host"
    install -D "$worker/libindago_dr_client.so" "$payload/lib$bits/libindago_dr_client.so"
done
install -m 644 "$root/vendor/dynamorio/License.txt" "$payload/License.txt"
printf 'Runtime payload staged: %s. Rebuild indago to embed it.\n' "$payload"
