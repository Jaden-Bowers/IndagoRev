#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cache="${INDAGO_ENGINE_BUILD_ROOT:-$HOME/.cache/indago}"
archive="$root/vendor/gdb/gdb-17.1.tar.xz"
mkdir -p "$cache"
test "$(sha256sum "$archive" | cut -d' ' -f1)" = 14996f5f74c9f68f5a543fdc45bca7800207f91f92aeea6c2e791822c7c6d876
test -d "$cache/gdb-17.1" || tar -xf "$archive" -C "$cache"
mkdir -p "$cache/gdb-build"
cd "$cache/gdb-build"
"$cache/gdb-17.1/configure" --disable-binutils --disable-ld --disable-gas --disable-gprof --disable-gprofng --disable-sim --disable-nls --disable-werror --without-python --without-guile --without-debuginfod --with-expat=no --with-lzma=no --with-babeltrace=no --disable-tui --with-system-readline=no LDFLAGS='-static-libstdc++ -static-libgcc'
make -j"${INDAGO_BUILD_JOBS:-6}" all-gdb
stage="$root/out/runtime-payload/linux/gdb"
mkdir -p "$stage/bin" "$stage/lib" "$stage/licenses"
install -m755 gdb/gdb "$stage/bin/gdb"
strip "$stage/bin/gdb"
for library in libtinfo.so.6 libmpfr.so.6 libgmp.so.10; do
  install -m644 "/usr/lib/x86_64-linux-gnu/$library" "$stage/lib/$library"
done
cp "$cache/gdb-17.1/COPYING3" "$stage/licenses/GDB-GPLv3.txt"
cp "$archive" "$stage/gdb-17.1-source.tar.xz"
for package in libtinfo6 libmpfr6 libgmp10; do
  cp "/usr/share/doc/$package/copyright" "$stage/licenses/$package.copyright"
done
