#!/usr/bin/env bash
# Private headers/tools only: no sudo, apt install, capture permissions or services.
set -euo pipefail
sdk=${1:-/home/jaden/.cache/indago/wireshark-sdk}
case "$sdk" in /home/jaden/.cache/indago/wireshark-sdk) ;; *) echo 'Use the explicit private development SDK path' >&2;exit 2;; esac
free=$(df -B1 --output=avail /mnt/c | tail -n 1 | tr -d ' ')
((free>21474836480+2147483648)) || { echo 'Insufficient disk reservation for source build' >&2;exit 1; }
mkdir -p "$sdk/packages" "$sdk/root"
packages=(libglib2.0-dev libgio-2.0-dev libglib2.0-dev-bin libglib2.0-0t64 libpcre2-dev libpcre2-8-0 libgcrypt20-dev libgcrypt20 libgpg-error-dev libgpg-error0 flex bison libc-ares-dev libcares2 libxml2-dev libxml2-16 libsysprof-capture-4-dev m4)
for package in "${packages[@]}";do
  metadata=$(apt-cache show --no-all-versions "$package")
  filename=$(printf '%s\n' "$metadata" | sed -n 's/^Filename: //p' | head -n 1)
  digest=$(printf '%s\n' "$metadata" | sed -n 's/^SHA256: //p' | head -n 1)
  [[ "$filename" == pool/* && "$filename" != *..* && "$digest" =~ ^[0-9a-f]{64}$ ]] || exit 2
  archive="$sdk/packages/${filename##*/}"
  if [[ ! -f "$archive" ]];then curl --fail --location --max-time 30 --max-filesize 6000000 "https://archive.ubuntu.com/ubuntu/$filename" -o "$archive";fi
  [[ $(sha256sum "$archive" | cut -d' ' -f1) == "$digest" ]] || { echo 'SDK package hash mismatch' >&2;exit 1; }
  dpkg-deb --extract "$archive" "$sdk/root"
  printf '%s %s\n' "$digest" "${filename##*/}"
done
source_archive="$sdk/wireshark-4.6.8.tar.xz"
if [[ ! -f "$source_archive" ]];then curl --fail --location --max-time 120 --max-filesize 60000000 https://www.wireshark.org/download/src/wireshark-4.6.8.tar.xz -o "$source_archive";fi
[[ $(sha256sum "$source_archive" | cut -d' ' -f1) == c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0 ]] || { echo 'Wireshark source hash mismatch' >&2;exit 1; }
if [[ ! -d "$sdk/wireshark-4.6.8" ]];then
  # Official pinned source; require its expected single archive root before extraction.
  bad=$(tar -tf "$source_archive" | awk '$0 !~ /^wireshark-4\.6\.8\// || $0 ~ /(^|\/)\.\.(\/|$)/ {print;exit}')
  [[ -z "$bad" ]] || { echo 'Unexpected source archive path' >&2;exit 1; }
  tar -xf "$source_archive" -C "$sdk"
fi
printf 'Private Linux Wireshark SDK/source staged; no system package installed.\n'
