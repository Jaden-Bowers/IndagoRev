#!/bin/bash
# Downloads stay in ignored out/. Nothing is installed in system directories.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
stage="$root/out/macBuild"
mkdir -p "$stage/downloads" "$stage/deps"
if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
  echo "This setup requires an Apple Silicon Mac." >&2
  exit 1
fi
fetch() {
  local url="$1" file="$2" expected="$3"
  if [[ ! -f "$file" ]]; then
    curl --fail --location --retry 2 "$url" --output "$file.part"
    mv "$file.part" "$file"
  fi
  local actual
  actual="$(shasum -a 256 "$file" | cut -d ' ' -f 1)"
  if [[ "$actual" != "$expected" ]]; then
    echo "Checksum mismatch: $file. Remove this archive and retry." >&2
    exit 1
  fi
}
# Release hashes are pinned, not computed from an unverified download at setup.
fetch 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.3_build/ghidra_12.0.3_PUBLIC_20260210.zip' \
  "$stage/downloads/ghidra.zip" \
  90d3fffb20b00030dcef8d2a24dd0f422d3a61e432b3ad43f77233ac6d667981
fetch 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_aarch64_mac_hotspot_21.0.12.1_1.tar.gz' \
  "$stage/downloads/jdk.tar.gz" \
  3623232f33a9c3baadf304480b2535f9a3cba8a58d42ecbb438ba267315d9998
if [[ ! -d "$stage/deps/ghidra_12.0.3_PUBLIC" ]]; then
  unzip -q "$stage/downloads/ghidra.zip" -d "$stage/deps"
fi
if [[ ! -d "$stage/deps/jdk-21.0.12.1+1" ]]; then
  tar -xzf "$stage/downloads/jdk.tar.gz" -C "$stage/deps"
fi
chmod +x "$stage/deps/ghidra_12.0.3_PUBLIC/Ghidra/Features/Decompiler/os/mac_arm_64/decompile"
chmod +x "$stage/deps/ghidra_12.0.3_PUBLIC/GPL/DemanglerGnu/os/mac_arm_64/"demangler_gnu_*
echo "Pinned Ghidra 12.0.3 and Temurin ARM64 JDK are ready in out/macBuild/deps."
