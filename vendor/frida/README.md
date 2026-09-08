# Frida native devkits

Pinned upstream version: 17.17.0. Unmodified native static libraries and headers
from https://github.com/frida/frida/releases/tag/17.17.0 (x86_64 host devkits,
including target injection support). No installed Frida server, CLI or Python.

Release archive SHA-256:

- windows-x86_64.tar.xz: `84767bf9e2c55956c6c337071fe928de02a34f17f1dee4e9832b52a0798b8c1d`
- linux-x86_64.tar.xz: `483e1a25945cebaa69e61c09d7804692c42d234cab0c58261a73382163027a2e`

`COPYING` is upstream frida-core's wxWindows Library Licence 3.1, obtained from
https://github.com/frida/frida-core/blob/17.17.0/COPYING. Preserve upstream and
transitive notices; public redistribution/license packaging remains a release
gate. Authored host and fixed recipes are in `workers/frida`. Build with
`tools/build-frida.ps1` or `.sh`, then rebuild the main executable. CMake does
not download anything; the product extracts hash-verified private helpers.
