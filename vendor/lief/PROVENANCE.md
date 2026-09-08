# LIEF C++ format library

LIEF 1.0.0, upstream release 2026-07-12:
https://github.com/lief-project/LIEF/releases/tag/1.0.0
Source: https://github.com/lief-project/LIEF/tree/1.0.0

`tools/bootstrap-lief.ps1` selects official win64 and Linux-x86_64 SDK archives,
verifies the GitHub release asset SHA-256 digests, and stages only headers, static
archives and CMake import metadata. Shared libraries, example programs and extended
commercial services are not application dependencies. The integration
links the static C++ library into the same executable; parsing runs in a bounded
same-executable worker. These SDK libraries are upstream builds, not local source
builds. Reproducible source-build qualification remains separate.

Windows archive SHA-256:
`1ad0799a5e699505f7e4ad31fd196105867cf29fd8b74485f32d02cfaba94fe2`

Linux archive SHA-256:
`81b86bcc69d311a01ec1914d26c31ebbb605ac761ec02f10bc5b588de74a8e91`

LIEF uses Apache-2.0. Preserve upstream and transitive notices with distribution;
integration of the SDK alone is not completion of license qualification.
Selected source-tag dependency notices and archive identities are preserved in
`THIRD-PARTY.md`, `dependency-archives.json`, and `notices/`; these files are embedded
with the adapter. The exact compiled SDK dependency closure remains unqualified.
