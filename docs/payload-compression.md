# Lossless native payload storage

Optional staged Zstandard frames reduce embedded worker bytes without changing
the files presented to Ghidra, Frida, ILSpy, Wireshark or other engines. The decoder
is statically linked from pinned upstream C source; no installed codec, DLL,
Python package or command-line decompressor is required at runtime.

Build the development packer after `tools/bootstrap-zstd.ps1` has staged source:

```
cmake -S tools/payload-codec -B out/payload-codec-windows -A x64
cmake --build out/payload-codec-windows --config Release
./tools/pack-runtime-payloads.ps1 -Platform both -MaxFiles 64
cmake --build out/build --config Release
```

The packer selects only staged tool files of 1–512 MiB and requires at least five
percent savings. It uses level 3, a bounded 8 MiB window, declared content size
and frame checksum. Each result is decoded with the production decoder and
compared against the original SHA-256 before publication. Source identity is
checked again after packing. Failed scratch outputs are removed; existing packed
bytes are verified, not silently replaced. Identical raw hashes share a packed
cache entry across platforms. The staging script has per-file 30s deadlines,
a 1 GiB free-space reservation above the 20 GiB floor, and a 768 MiB cache cap.

CMake verifies the metadata/source hash, original size, packed length and packed
hash before selection. Missing metadata falls back to the original raw file;
invalid metadata fails configuration. Newly staged metadata triggers reconfigure.
`INDAGO_ENABLE_PAYLOAD_COMPRESSION=OFF` explicitly selects all raw representations.
The same files remain in the manifest either way. `OBJECT_DEPENDS` tracks the
selected `.incbin` inputs on Linux, including same-path, same-length changes.

Extraction accepts exactly one complete frame with known size and no dictionary.
It rejects trailing frames/bytes, truncation, checksum corruption, oversized output
or a window beyond 8 MiB. The output buffer is 128 KiB; output is streamed to a
new temporary file, not a file-sized decompression allocation. Original length and
SHA-256 are verified before immutable publication. Group identities depend on raw
names/hashes, not storage encoding, so compression alone does not duplicate cache
groups. Added or updated notice/tool files still legitimately change that group.

`runtime payloads` separates `embedded_payload_bytes` from
`expanded_payload_bytes`; group entries include both sizes and `compressed_files`.
The expanded size is not a quota or total installed footprint: old caches, SDKs,
source archives and build outputs are outside this inventory. Compression reduces
the executable, not the size of extracted tool files. No old cache is deleted.

## Bounded development verification

Codec tests pass on Windows and Linux. Windows also verifies excessive decoder
windows and unknown frame sizes. Native packing/round-trip reuse, corrupted frames,
metadata conflict and CMake selection/refusal tests pass on both platforms.
See `out/payload-codec-*-checks.log` and `out/payload-codec-window-checks.log`.

The initial 64-file selection considered 49 compressible platform files (36 unique
raw hashes) and kept 15 already-compressed files raw. The shared packing cache is
527,808,116 bytes including metadata. The Windows build embeds 1,135,634,192 bytes
representing 1,572,172,448 original bytes: **436,538,256 bytes saved**, with 24
compressed files. Its payload inventory, packet/index/harness checks, native 4/4
regression and source-backed Frida smoke pass. Frida completed in 7.87s under a 60s
watchdog. See `out/compressed-payload-*-windows-checks.log`.

Linux now embeds 1,177,335,771 bytes representing 1,723,273,609 original bytes:
**545,937,838 bytes saved**, with 25 compressed files. Its inventory, packet and
split-HTTP CLI checks, native knowledge/model/harness checks (3/3) and source-backed
Frida smoke pass (`out/compressed-payload-*-linux-checks.log`). Linux test executables
now peak near 1.23 GiB rather than 1.78 GiB and are still removed sequentially.
Persistent native-test logs/hashes are under `out/qualification-linux-native`;
temporary executables remain on native Linux temporary storage.

Do not treat these bounded checks as product qualification. Full release
build reproduction, long-running stress and transitive distribution/license audit
remain separate gates. Source/license provenance: `vendor/zstd/PROVENANCE.md` and
[upstream release](https://github.com/facebook/zstd/releases/tag/v1.5.7).
