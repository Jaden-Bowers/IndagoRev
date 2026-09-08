# Source-tag dependency notice inventory

The LIEF 1.0.0 source tree bundles the archives listed in
`dependency-archives.json`. `tools/stage-lief-notices.ps1` checks their pinned Git
blob identities and extracts standalone license/notice files without extracting
the source trees. These are Git object identities from the upstream tag, not
independent signed attestations of the SDK's exact compiled dependency closure.

- tl::expected 1.3.1: CC0, preserved COPYING.
- frozen 61dce5a: preserved LICENSE.
- nlohmann/json 3.12.0: MIT; the compact source archive lacks a standalone file.
  `json-LICENSE.MIT` is from upstream's exact v3.12.0 tag, SHA-256
  `46a65cffd1ea955132d95a8dd921640714a8d6b537d2e4e482d31145ae95b603`.
- mbedtls 4.0.0/ec4044008d and bundled tf-psa-crypto/framework: preserved LICENSE
  files from the LIEF archive. File-specific source notices remain in that archive.
- spdlog 1.17.0: preserved MIT LICENSE; bundled fmt's copyright/permission text
  from `include/spdlog/fmt/bundled/format.h` is preserved in `fmt-LICENSE.txt`.
- tcb::span b70b0ff: Copyright Tristan Brindle 2018, distributed under Boost
  Software License 1.0. Inline copyright is present in the SDK's
  `LIEF/third-party/internal/span.hpp`. `Boost-1.0.txt` is the standard license
  from boostorg/boost's boost-1.89.0 tag, SHA-256
  `c9bff75738922193e67fa726fa225535870d2aa1059f91452c411736284ad566`.
- utfcpp 4.0.9: preserved LICENSE.

Catch2, Melkor and nanobind are test/fuzzer/binding source dependencies and are not
part of this C++ SDK adapter's selected input artifacts. The full upstream source
tree and SDK build must still be reconciled for a distributable release; this
inventory does not claim to replace that audit or establish an exact binary SBOM.
