#!/usr/bin/env bash
# Optional distribution-built QEMU payload. Guest OS images are never included.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
stage="${1:-$root/out/runtime-payload/linux/qemu}"
mkdir -p "$stage/bin" "$stage/lib" "$stage/firmware" "$stage/licenses"
for tool in qemu-system-x86_64 qemu-img; do
  binary="$(command -v "$tool")"
  install -m755 "$binary" "$stage/bin/$tool"
  while read -r library; do
    test -f "$library" && install -m644 "$library" "$stage/lib/$(basename "$library")"
  done < <(ldd "$binary" | awk '/=> \// {print $3}')
done
install -m644 /usr/share/seabios/bios-256k.bin "$stage/firmware/bios-256k.bin"
install -m644 /usr/share/qemu/kvmvapic.bin "$stage/firmware/kvmvapic.bin"
for package in qemu-system-x86 qemu-utils qemu-system-common qemu-system-data seabios; do
  cp "/usr/share/doc/$package/copyright" "$stage/licenses/$package.copyright"
done
# Include the distribution's notices for each copied shared dependency.
for library in "$stage"/lib/*; do
  package="$(dpkg-query -S "/usr/lib/x86_64-linux-gnu/$(basename "$library")" 2>/dev/null | head -1 | sed 's/: \/.*//;s/:amd64$//' || true)"
  if test -n "$package" && test -f "/usr/share/doc/$package/copyright"; then
    cp "/usr/share/doc/$package/copyright" "$stage/licenses/$package.copyright"
  fi
done
cp "$root/workers/qemu/PROVENANCE.md" "$stage/PROVENANCE.md"
dpkg-query -W qemu-system-x86 qemu-utils qemu-system-common qemu-system-data seabios > "$stage/package-versions.txt"
(cd "$stage" && find bin lib firmware licenses -type f -print0 | sort -z | xargs -0 sha256sum) > "$stage/files.sha256"
printf '%s\n' 'Reconfigure Indago to embed this optional payload. Audit source redistribution obligations before publishing a binary release.'
