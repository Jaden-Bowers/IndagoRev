# Offline Wireshark worker staging

Pinned Windows upstream TShark/Wireshark 4.6.8 from the official x64 MSI:
https://www.wireshark.org/download/win64/Wireshark-4.6.8-x64.msi
SHA-256 `779ee66f846376942a3b631a78bba8c3d509697d07743349e1893056211d05e3`.
The hash is published in https://www.wireshark.org/download/SIGNATURES-4.6.8.txt;
the detached OpenPGP trust chain has not been independently qualified here.
Windows Authenticode checks on tshark.exe/libwireshark.dll passed during staging.

`tools/stage-wireshark-package.ps1 -Extract` inventories the MSI read-only and
extracts selected files with a private archive utility, never running the MSI.
It preserves upstream native dissectors and required support libraries; no GUI,
capture helper, Npcap installer/driver, updater, service or host configuration is
installed. Selected MSI file keys, sizes and SHA-256 hashes accompany the payload.
The archive utility is a private Ubuntu 7zip 26.00 package, pinned to Ubuntu's
package SHA-256 in the staging script; it is not an application dependency.

Source: https://gitlab.com/wireshark/wireshark/-/tree/v4.6.8
Wireshark is GPL-2.0-or-later. Upstream COPYING/README are retained. Source delivery,
the exact dependent DLL/CRT notice closure and redistributability reconciliation
remain release gates. This prototype is not a completed distribution/SBOM audit or
a locally reproduced Windows Wireshark build.

The unmodified Windows worker crashes on cleanup when a plugin init.lua explicitly
sets enable_lua=false. A bounded native DbgEng diagnostic captured the failure;
upstream v4.6.8 init_wslua.c calls wslua_deregister_protocols(L) in early cleanup
after disabling Lua clears L. The selected configuration instead uses fresh empty
global/personal plugin and preference directories. No scripts/plugins are loaded,
but the Lua runtime is present. No binary patch or suppression of failed exit codes
is used.

## Linux source-built offline profile

Official source archive https://www.wireshark.org/download/src/wireshark-4.6.8.tar.xz
SHA-256 `c0f1ccf217bc0d3b51a9c03ea178b0f7df682e475da26a2d21cd4a1bdd9579d0`,
checked against the same published release digest list. The unmodified source is
built with `tools/build-wireshark-linux.sh`. Wireshark and its parser/crypto/support
libraries are linked statically; the result uses baseline host glibc, libm and ELF
loader (not a portable older-glibc guarantee). Only the staged payload copy is
stripped; the original development build remains available.

Lua, external plugins and libpcap are compiled out. The Linux optional feature
profile is narrower than the upstream Windows package: no GnuTLS, Kerberos,
nghttp2/3, brotli, LZ4 or Snappy. Native protocol dissectors remain upstream code;
do not infer support for disabled optional decoding/decryption features. The
embedded `build-profile.txt` contains actual upstream version/features, dependency
inspection and host static-package versions; `build-recipe.sh` records options.

Private Ubuntu SDK packages were extracted without installing them and verified
against apt metadata SHA-256. `sdk-packages.sha256` inventories exact downloaded
packages; selected SDK and host static-library copyright files accompany the
payload. These are provenance records, not a reproduced transitive source/SBOM or
completed GPL/LGPL distribution compliance audit. Corresponding source delivery
and the exact compiled dependency/license closure remain release gates.
