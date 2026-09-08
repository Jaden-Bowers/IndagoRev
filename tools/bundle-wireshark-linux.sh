#!/usr/bin/env bash
# Generated staging outputs only; never installs packages or capture privileges.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
sdk=/home/jaden/.cache/indago/wireshark-sdk
build=/home/jaden/.cache/indago/wireshark-build
destination="$repo/out/runtime-payload/linux/network"
free=$(df -B1 --output=avail /mnt/c | tail -n 1 | tr -d ' ')
((free>21474836480+536870912)) || { echo 'Insufficient payload storage reservation' >&2;exit 1; }
[[ $(sha256sum "$sdk/wireshark-4.6.8.tar.xz" | cut -d' ' -f1) == c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0 ]] || exit 1
# Refuse unexpected shared dependencies instead of relying on a private SDK at run time.
dependencies=$(ldd "$build/run/tshark")
if printf '%s\n' "$dependencies" | grep -Ev 'linux-vdso|libm\.so\.6|libc\.so\.6|ld-linux-x86-64\.so\.2|^[[:space:]]*$';then
  echo 'Unexpected offline worker dependency' >&2;exit 1
fi
mkdir -p "$destination/notices"
install -m 755 "$build/run/tshark" "$destination/tshark"
# Strip only the new private payload copy; preserve the source build and all tools.
strip --strip-unneeded "$destination/tshark"
install -m 644 "$sdk/wireshark-4.6.8/COPYING" "$destination/COPYING"
install -m 644 "$sdk/wireshark-4.6.8/README.md" "$destination/README.md"
install -m 644 "$repo/vendor/wireshark/PROVENANCE.md" "$destination/PROVENANCE.md"
install -m 644 "$repo/tools/build-wireshark-linux.sh" "$destination/build-recipe.sh"
for package in libglib2.0-dev libpcre2-dev libgcrypt20-dev libgpg-error-dev libc-ares-dev libxml2-dev libsysprof-capture-4-dev;do
  install -m 644 "$sdk/root/usr/share/doc/$package/copyright" "$destination/notices/$package-copyright"
done
for package in zlib1g-dev libzstd-dev;do
  install -m 644 "/usr/share/doc/$package/copyright" "$destination/notices/$package-copyright"
done
timeout 20s "$destination/tshark" --version > "$destination/build-profile.txt"
printf '%s\n' "$dependencies" >> "$destination/build-profile.txt"
(cd "$sdk/packages" && sha256sum ./*.deb) > "$destination/sdk-packages.sha256"
dpkg-query -W zlib1g-dev libzstd-dev libc6 libgcc-15-dev >> "$destination/build-profile.txt"
(cd "$destination" && find . -type f ! -name payload-files.sha256 -print0 | sort -z | xargs -0 sha256sum) > "$destination/payload-files.sha256"
printf 'Linux offline payload staged; no system package or capture support installed.\n'
