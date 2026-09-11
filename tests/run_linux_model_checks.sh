#!/usr/bin/env bash
# Reuse the native build without turning on every test target and rescanning payloads.
set -euo pipefail
build=${1:?native CMake build directory}
shift
root=$(cd "$(dirname "$0")/.." && pwd)
names=("$@")
if ((${#names[@]}==0));then names=(model_http_tests model_tests harness_tests knowledge_tests airece_worker_tests);fi
for name in "${names[@]}";do
  case "$name" in model_http_tests|model_tests|harness_tests|knowledge_tests|airece_worker_tests) ;; *) echo 'Unknown native test selection' >&2;exit 2;; esac
done
# Linux statically linked tests can each contain the full worker payload. Keep
# only one generated executable at a time instead of five multi-GiB copies.
# Reserve the main binary's size plus 256 MiB for the selected test/linker delta.
reserve=$(( $(stat -c %s "$build/indago") + 268435456 ))
free=$(df -B1 --output=avail /mnt/c | tail -n 1 | tr -d ' ')
((free>21474836480+reserve)) || { echo 'Insufficient native-test storage reservation' >&2;exit 1; }
temporary_free=$(df -B1 --output=avail /tmp | tail -n 1 | tr -d ' ')
((temporary_free>reserve)) || { echo 'Insufficient temporary test-filesystem space' >&2;exit 1; }
mkdir -p "$root/out/qualification-linux-native"
report=$(mktemp -d "$root/out/qualification-linux-native/checks.XXXXXX")
binaries=$(mktemp -d /tmp/indago-model-binaries.XXXXXX)
# /tmp can be an 8 GiB tmpfs: keep receipt workspaces on the native build
# filesystem so the production 20 GiB storage floor is exercised, not bypassed.
workspaces=$(mktemp -d "$build/test-workspaces.XXXXXX")
active_binary=''
cleanup(){
  if [[ -n "$active_binary" ]];then
    case "$active_binary" in "$binaries/model_http_tests"|"$binaries/model_tests"|"$binaries/harness_tests"|"$binaries/knowledge_tests"|"$binaries/airece_worker_tests") rm -f -- "$active_binary";; *) echo 'Refusing unexpected test cleanup path' >&2;return 1;; esac
  fi
}
trap cleanup EXIT
libraries=("$build/libindago_core.a" "$build/libindago_sqlite.a" "$build/libindago_airece.a"
 "$build/build-xair-sym/libxair_sym.a" "$build/build-xair-cfg/libxair_cfg.a" "$build/build-xair/libxair.a"
 "$build/build-xair/zydis/libZydis.a" "$build/build-xair/zydis/zycore/libZycore.a" "$build/build-xair-sym/z3/libz3.a"
 /usr/lib/x86_64-linux-gnu/libssl.a /usr/lib/x86_64-linux-gnu/libcrypto.a
 /usr/lib/x86_64-linux-gnu/libjitterentropy.a /usr/lib/x86_64-linux-gnu/libz.a /usr/lib/x86_64-linux-gnu/libzstd.a)
if grep -q '^LIEF_DIR:PATH=' "$build/CMakeCache.txt";then
  libraries+=("$root/out/lief-sdk/linux/lib/libLIEF.a")
fi
if [[ -f "$build/zstd/lib/libzstd.a" ]];then
  # Resolve the codec from the same source-built archive as the application,
  # before any transitive host OpenSSL static-library dependency fallback.
  libraries=("$build/zstd/lib/libzstd.a" "${libraries[@]}")
fi
for name in "${names[@]}";do
  free=$(df -B1 --output=avail /mnt/c | tail -n 1 | tr -d ' ')
  ((free>21474836480+reserve)) || { echo 'Native-test storage floor reached' >&2;exit 1; }
  active_binary="$binaries/$name"
  cc "$root/tests/io_fixture.c" -o "$binaries/indago_io_fixture"
  c++ -std=c++20 -O0 -DINDAGO_HAS_XAIR=1 -DINDAGO_SOURCE_ROOT=\""$root"\" -I"$root/include" -I"$root/vendor" -I"$root/vendor/sqlite3" -I"$root/xair/XAIR/include" \
    "$root/tests/$name.cpp" -Wl,--start-group "${libraries[@]}" -Wl,--end-group -ldl -pthread -o "$active_binary"
  # Existing XAIR worker discovery uses a sibling indago executable in tests.
  ln -sf "$build/indago" "$binaries/indago"
  TMPDIR="$workspaces" timeout --kill-after=5s 60s "$active_binary" > "$report/$name.stdout.log" 2> "$report/$name.stderr.log" || {
    cat "$report/$name.stdout.log" "$report/$name.stderr.log";exit 1;
  }
  sha256sum "$active_binary" > "$report/$name.executable.sha256"
  test_bytes=$(stat -c %s "$active_binary")
  cleanup;active_binary=''
  jq -nc --arg test "$name" --arg report "$report" --argjson test_bytes "$test_bytes" '{test:$test,status:"passed",timeout_seconds:60,live_inference:false,logs:$report,temporary_executable_bytes:$test_bytes,temporary_executable_removed:true}'
done
