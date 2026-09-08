# rr replay integration preparation

Upstream rr 5.9.0 release tag points to commit
`aaed29dc0324444e36503a26dcec96731d1942b0`.
Official native package:
https://github.com/rr-debugger/rr/releases/download/5.9.0/rr-5.9.0-Linux-x86_64.tar.gz
Downloaded package SHA-256:
`1e229f0b24ca4f6feb325895ae57eb8792b92c0250ec2e68d292d2fe97e71864`.
The release API supplied no publisher asset digest. This is a locally pinned
official HTTPS retrieval, not an independently authenticated binary attestation
or a locally reproduced source build. Source/license/dependency reconciliation is
required before distribution. Staging alone is not an implemented product backend.

Private staging does not install a system package or change kernel/PMU/ptrace/VM
settings. Compatibility must retain native failures rather than spoofing CPU
support or assuming that WSL contains hostile programs. Only source-backed benign
fixtures may execute during development; arbitrary samples require the separately
provisioned disposable lab. Live inference remains unconfigured.

Primary upstream references:
[release](https://github.com/rr-debugger/rr/releases/tag/5.9.0),
[build and hardware requirements](https://github.com/rr-debugger/rr/wiki/Building-And-Installing).

## Local source-build follow-up — 2026-09-07

The complete pinned source archive is retained under `upstream/`:
https://codeload.github.com/rr-debugger/rr/tar.gz/aaed29dc0324444e36503a26dcec96731d1942b0
SHA-256 `8470254912b7fb0fd728222e07206ddd978b1128e5795388de16e14b627eab53`.
`tools/stage-rr-source.sh` pins private CapnProto 1.1.0-2.1 SDK packages;
`tools/build-rr-linux.sh` builds both target-bitness helpers with CapnProto,
zlib, zstd and C++ support linked statically. `ldd` on the resulting rr lists
only libc, libm and the ELF loader. No system installation or kernel changes.

Local modification: `upstream/src/kernel_abi.cc` obtains legacy `termio` from
the Linux UAPI in a separate namespace on glibc >=2.43, retaining rr's ABI
assertion after libc removed that declaration. This is not an unmodified upstream
build. The capnp build-only wrapper supplies the private schema include path.
Native version output has no Git revision because the source came from an archive;
the commit pin above is recorded separately, not invented in native output.

The source-built tool passed record, pack and autopilot replay on the adjacent
benign x86/x64 ELF fixtures (`out/rr-source-{x86,x64}-probe.log`). Full dependency
notice/source delivery and release qualification remain pending. The product
adapter's source is present but its payload has not been staged into the final
executable, nor has its CLI session/cancellation path passed end-to-end testing.
