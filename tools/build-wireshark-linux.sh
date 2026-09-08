#!/usr/bin/env bash
set -euo pipefail
sdk=/home/jaden/.cache/indago/wireshark-sdk
build=/home/jaden/.cache/indago/wireshark-build
export PATH="$sdk/root/usr/bin:$PATH"
export PKG_CONFIG_SYSROOT_DIR="$sdk/root"
export PKG_CONFIG_LIBDIR="$sdk/root/usr/lib/x86_64-linux-gnu/pkgconfig"
export BISON_PKGDATADIR="$sdk/root/usr/share/bison"
export M4="$sdk/root/usr/bin/m4"
free=$(df -B1 --output=avail /mnt/c | tail -n 1 | tr -d ' ')
((free>21474836480+2147483648)) || { echo 'Insufficient source-build storage reservation' >&2;exit 1; }
options=(-DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH="$sdk/root/usr" -DBUILD_SHARED_LIBS=OFF -DUSE_STATIC=ON
  -DGLIB2_STATIC_m_LIBRARY:FILEPATH=/usr/lib/x86_64-linux-gnu/libm.so.6
  "-DCMAKE_C_FLAGS=-I$sdk/root/usr/include/x86_64-linux-gnu" "-DCMAKE_CXX_FLAGS=-I$sdk/root/usr/include/x86_64-linux-gnu")
# Match the native application's glibc baseline. Mixing this host's static libm
# with dynamic glibc introduces unresolved private CPU-dispatch symbols; all
# actual Wireshark/GLib/parser/crypto dependencies still use static archives.
for tool in wireshark stratoshark strato rawshark dumpcap text2pcap mergecap reordercap editcap capinfos captype randpkt dftest dcerpcidl2wrs androiddump sshdump ciscodump dpauxmon randpktdump wifidump etwdump sdjournal udpdump sharkd mmdbresolve;do options+=("-DBUILD_$tool=OFF");done
# Preserve native dissectors; these disable plugin execution, capture privileges
# and optional integrations not present in this initial offline profile.
for feature in PCAP PLUGINS LUA CAP NETLINK SMI GNUTLS KERBEROS SBC SPANDSP BCG729 AMRNB ILBC OPUS SINSP ZLIBNG MINIZIP MINIZIPNG LZ4 BROTLI SNAPPY NGHTTP2 NGHTTP3 XXHASH;do options+=("-DENABLE_$feature=OFF");done
cmake -S "$sdk/wireshark-4.6.8" -B "$build" -G Ninja "${options[@]}"
cmake --build "$build" --target tshark -j6
printf 'Linux source-built offline TShark completed.\n'
