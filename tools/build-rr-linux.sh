#!/usr/bin/env bash
# Private source build; no system install, kernel changes, or tracee environment overrides.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
sdk=/home/jaden/.cache/indago/rr-source-sdk/root
build=/home/jaden/.cache/indago/rr-build
free=$(df -B1 --output=avail /mnt/c | tail -n 1 | tr -d ' ')
((free>21474836480+536870912)) || { echo 'Insufficient rr build reservation' >&2;exit 1; }
test -f "$sdk/usr/lib/x86_64-linux-gnu/libcapnp.a"
# The private capnp compiler uses private shared libraries only during the build.
mkdir -p "$build/tools"
install -m 755 "$root/tools/rr-capnp.sh" "$build/tools/capnp"
export PATH="$build/tools:$sdk/usr/bin:$PATH"
export LD_LIBRARY_PATH="$sdk/usr/lib/x86_64-linux-gnu"
cmake -S "$root/vendor/rr/upstream" -B "$build" \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTS=OFF -DWILL_RUN_TESTS=OFF \
  -DINSTALL_TESTSUITE=OFF -Dstaticlibs=ON -Ddisable32bit=OFF \
  -Dbpf=OFF -Dintel_pt_decoding=OFF -Dstrip=ON -DSKIP_PKGCONFIG=ON \
  -DCAPNP="$sdk/usr/bin/capnp" \
  -DCAPNP_STATIC_CFLAGS="-I$sdk/usr/include" \
  -DZLIB_LDFLAGS=/usr/lib/x86_64-linux-gnu/libz.a \
  -DLIBZSTD_LDFLAGS=/usr/lib/x86_64-linux-gnu/libzstd.a \
  -DCMAKE_EXE_LINKER_FLAGS="-L$sdk/usr/lib/x86_64-linux-gnu -static-libgcc"
cmake --build "$build" --parallel 4
unset LD_LIBRARY_PATH
ldd "$build/bin/rr"
if ldd "$build/bin/rr" | grep -E 'lib(capnp|kj|zstd|z|stdc\+\+|gcc_s)\.';then
  echo 'rr unexpectedly requires a non-system dynamic library' >&2;exit 1
fi
"$build/bin/rr" --version
