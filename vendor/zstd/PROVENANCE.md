# Native payload compression codec

Zstandard 1.5.7, unmodified upstream C source from
https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz
SHA-256 `eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3`,
verified against the official release `.sha256` asset. The detached signature
trust chain has not been independently qualified. Upstream source/LICENSE/COPYING
remain in `upstream/`; use the BSD-3-Clause license option. This integrates the
existing compression format, not a new codec or an installed system dependency.

Compression is only an embedded-file storage representation. Original tool bytes,
raw SHA-256 checks and group cache identity must be preserved after decompression.
Packing must validate every compressed frame by round trip before it is selected
for embedding; extraction must enforce original size and verify the raw digest.
