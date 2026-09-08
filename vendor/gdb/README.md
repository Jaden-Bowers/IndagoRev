# Private Linux debugger engine

`gdb-17.1.tar.xz` is the unmodified GNU source archive. Its URL and SHA-256 are
pinned in `config/toolchain.lock.json`. `tools/build-gdb.sh` verifies it, builds
GDB without Python/Guile and stages the engine and its non-libc shared libraries.
CMake embeds that payload in the native IndagoRev executable. No installed GDB
or Python is used at runtime. The OS loader, libc and libm remain OS dependencies.

The corresponding source archive and GPL notice are included in the private
payload alongside dependency notices. Preserve these when redistributing the
binary. This is process-level GDB/MI integration, not linking GPL debugger code
into the platform library. Distribution/license review is still a release gate.
