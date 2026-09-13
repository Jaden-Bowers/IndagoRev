# Optional QEMU distribution payload

QEMU is a separate GPL-2.0 tool, not linked into the MIT controller. The staging
script copies the operator's distribution-built QEMU and shared libraries, their
copyright notices, exact file hashes and package versions. It does not download
or bundle guest operating systems. The tested distribution version is Ubuntu
QEMU 10.2.1 (`1:10.2.1+ds-1ubuntu3.1`), machine `pc-i440fx-10.2`.

Upstream: https://www.qemu.org/ and https://gitlab.com/qemu-project/qemu
Distribution source: https://launchpad.net/ubuntu/+source/qemu

This is a local development staging route, not a completed source-compliance
release package. Before redistributing binaries, retain/provide corresponding
distribution sources and patches for GPL/LGPL components under their licenses.
Do not imply that a file manifest substitutes for corresponding source.

KVM and trusted TCG development profiles are distinct. TCG is not a QEMU-supported
security boundary. Both currently disable all NICs, passthrough, host directories,
remote monitors and automatic guest dependency installation. See the guest
lifecycle document for limits and qualification boundaries.
