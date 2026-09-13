# Repository consolidation

The current publication integrates the bounded helper, experiment, input-solving,
artifact, reconstruction and guest work previously recorded as local increments.
The XAIR_SYM gitlink and toolchain lock now identify published commit `c9569b3`.

Added required full-analysis presets and a post-build capability manifest check.
The Windows full build reports all nine static backends available, with private
Ghidra, Frida and DynamoRIO. The native-only build passes its own profile and is
correctly rejected as a full build. This is not release qualification.

Public docs use relative links or neutral placeholders, with a portability check.
Historical status pages link to the current contract rather than silently serving
as contradictory current inventories. The application/control plane is C/C++.

The two rr test symlinks are unchanged in Git. A Windows checkout may use
`git config core.symlinks false` when Linux reparse points cannot be read by Git;
Linux checkouts retain native symlinks. No upstream rr source was replaced.

Verification: full Windows build/capability gate and native static smoke passed.
Local generated logs and binaries are ignored; personal paths, credentials, corpus
files and raw investigation reports are not part of this publication.
