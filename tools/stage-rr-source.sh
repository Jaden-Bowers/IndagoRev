#!/usr/bin/env bash
# Private, hash-pinned development dependencies; never apt install or sudo.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
sdk=/home/jaden/.cache/indago/rr-source-sdk
archive=/mnt/c/Users/Jaden/.cache/indago/rr/rr-aaed29dc0324444e36503a26dcec96731d1942b0.tar.gz
free=$(df -B1 --output=avail /mnt/c | tail -n 1 | tr -d ' ')
((free>21474836480+536870912)) || { echo 'Insufficient rr source-build reservation' >&2;exit 1; }
[[ $(sha256sum "$archive" | cut -d' ' -f1) == 8470254912b7fb0fd728222e07206ddd978b1128e5795388de16e14b627eab53 ]] || exit 1
mkdir -p "$sdk/packages" "$sdk/root"
packages=(libcapnp-dev capnproto libcapnp-1.1.0)
digests=(f0d30cf17e72bd3fead941d84de89526c550c5da66271dfd761f098e2e480943 cfcd039768947680dbafc0cbd4ac2233b75dc58f2b3ad63d4df00988ab9dd8d4 cb3c8b06c2d3f4494d008ccc286190f9223a54853e496f1050df3ba3206ce5cc)
for i in "${!packages[@]}";do
  file="${packages[$i]}_1.1.0-2.1_amd64.deb"
  if [[ ! -f "$sdk/packages/$file" ]];then curl --fail --location --max-time 30 --max-filesize 10000000 "https://archive.ubuntu.com/ubuntu/pool/universe/c/capnproto/$file" -o "$sdk/packages/$file";fi
  [[ $(sha256sum "$sdk/packages/$file" | cut -d' ' -f1) == "${digests[$i]}" ]] || { echo 'CapnProto SDK integrity mismatch' >&2;exit 1; }
  dpkg-deb --extract "$sdk/packages/$file" "$sdk/root"
done
destination="$root/vendor/rr/upstream"
if [[ -e "$destination" ]];then echo 'rr source already exists; inspect rather than overwrite' >&2;exit 1;fi
bad=$(tar -tf "$archive" | awk '$0 !~ /^rr-aaed29dc0324444e36503a26dcec96731d1942b0\// || $0 ~ /(^|\/)\.\.(\/|$)/ {print;exit}')
[[ -z "$bad" ]] || exit 1
mkdir -p "$destination"
tar -xf "$archive" --strip-components=1 -C "$destination"
printf 'Pinned rr source and private CapnProto SDK staged.\n'
