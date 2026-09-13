# Bounded QEMU guest experiments

The native CLI integrates QEMU rather than implementing CPU/device emulation.
The implemented profile is deliberately specific: Linux/WSL, QEMU 10.2-compatible
`pc-i440fx-10.2`, x86 boot disks in **raw** format, 32 MiB guest RAM, one qemu64 CPU,
and **no NIC**. It supports assessed trusted development fixtures; it does not
authorize unattended hostile collections or provision a full Windows/Linux OS.

QEMU's [security policy](https://www.qemu.org/docs/master/system/security.html)
distinguishes supported virtualization profiles from TCG, which must not be relied
on for guest isolation. This implementation keeps trusted KVM and trusted TCG
profiles explicit. Namespace/cgroup restrictions do not establish a universal
sandbox guarantee. [Record/replay](https://www.qemu.org/docs/master/system/replay.html)
uses instruction counting and recorded nondeterministic events, not a promise that
every machine/device configuration is replayable.

## Tool and asset identity

`tools/stage-qemu-linux.sh` optionally stages the installed distribution binaries,
dependencies, firmware, package versions, hashes and notices. Reconfigure/rebuild
to embed the optional `qemu` payload. The pinned tools can instead be supplied by
the operator. No download occurs inside the product. Source redistribution
obligations are documented in `workers/qemu/PROVENANCE.md`; local staging is not
itself a completed distributable source-compliance package.

Guest images stay outside the executable. Create a profile:

```json
{
  "image":{"path":"/absolute/boot.raw","sha256":"EXACT_SHA256"},
  "machine":"pc-i440fx-10.2",
  "accelerator":"kvm",
  "trusted_guest":true
}
```

With bundled tools, their paths/hashes are resolved automatically. Otherwise
provide `qemu`, `qemu_img`, `bios` and `rom`, each `{path,sha256}`. Optional
`transfer:{path,sha256}` exposes a read-only firmware file (max 1 MiB) named
`opt/indago/transfer` through QEMU's
[fw_cfg interface](https://www.qemu.org/docs/master/specs/fw_cfg.html). It never
shares a host folder. Images are capped at 16 MiB in this boot-disk profile;
larger OS profiles need separate resource/dependency assessment. Tool/firmware,
library payload, package database, image and configuration identities are pinned
and rechecked. Ordinary runs do not virtualize host-clock nondeterminism.

## Lifecycle

```
indago guest create --request profile.json
indago guest run --request experiment.json
indago guest reset --request cold-reset.json
indago guest list
indago guest show --request run-id.json
indago guest cancel --request run-id.json
indago guest reconcile --request run-id.json
indago guest export --request export.json
indago guest prune --request run-id.json
```

An experiment specifies `profile` and up to eight actions. Supported actions are
`observe`, `pause`, `resume`, `warm_reset`, `snapshot`, `restore`, `registers`.
Each `duration_ms` is at most 1,000; total observation waits are at most 5,000 ms.
Every run starts a new process with a fresh disposable qcow2 overlay backed by the
hash-pinned raw disk, then stops. Sessions are bounded experiments, not indefinitely
running desktop VMs. QMP is a private Unix socket with an internal whitelist;
arbitrary monitors, passthrough and network endpoints are never model arguments.

One bounded checkpoint is allowed per run. Warm reset does not clear disk writes.
`reset` with `previous:RUN_ID` starts a **new** overlay/process and records base
integrity, new epoch, and complete selected boot-output agreement. It does not
certify every aspect of an application's initial state.

`registers` uses the existing bundled GDB against QEMU's private Unix GDB stub,
not a new debugger. GDB was rebuilt with XML/Expat target-description support.
Full guest-OS process/Frida tooling requires an OS-specific image/agent profile;
this boot profile does not pretend to have such an OS agent.
Rebuilding the optional Linux GDB with `tools/build-gdb.sh` now requires the
distribution's `libexpat1-dev` development package in addition to its existing
GMP/MPFR/build prerequisites; Expat's runtime and notices are staged with GDB.

The outer cgroup limits the worker to 512 MiB, 32 tasks and 20 seconds. File size
is limited to 128 MiB; a monitored aggregate staging limit and file-count bound
cancel excessive output (polling may permit overshoot). Only complete, stopped,
regular non-symlink/single-link outputs are collected. Serial output retains at
most 4 KiB with truncation explicit. Up to four overlays are retained; further
runs require explicit pruning. Receipts survive pruning; removed binary outputs
are not recoverable through Indago.

Cancellation and forced-parent interruption retain uncertainty. A named worker
unit has a service-manager deadline. After that deadline, `reconcile` checks unit
termination before marking an interrupted run stopped; it does not invent lost
observations or automatically retry. Explicit pruning also removes leftover
private staging after checking its exact temporary path, ownership marker and
terminal worker unit. It is not treated as trustworthy output.

`export` publishes hash-checked serial bytes through existing artifact storage and
records guest/profile/base lineage. It does not establish semantic equivalence or
automatically expand investigation scope.

## Replay profile

For an explicit trusted `tcg` profile, `mode:record`/`mode:replay` uses fixed
`icount shift=3` with a `blkreplay` disk wrapper and no network. Replay references
a completed recording using `previous`, requiring identical profile and intact
recording hash. This profile permits observation only: no checkpoint operations
or a transfer file. Replay logs retained are capped at 16 MiB.

## Harness authority and tests

Operator-created investigations may grant up to four `guest_profiles` IDs. The
model may then propose `workbench guest.run` on that exact imported disk. It cannot
create profiles or provision images. Results become native, immutable knowledge
products; recovered publication summaries retain the guest status and stop state.

`tests/guest_lifecycle.cjs` covers KVM boot, pause, snapshot/restore, bundled GDB,
cold reset and trusted TCG record/replay. `tests/guest_harness.cjs` covers optional
bundled tools, denied/granted harness execution, scoped output lineage and invalid
operations/pins. The fixture is a 512-byte source-built boot sector that prints
`IG`, then halts. No archive executable or large guest image is used.
`tests/guest_transfer.cjs` separately boots a source-built firmware-file reader and
checks an admitted read-only file byte reaches serial output, while
rejecting the same profile when its transfer artifact is outside investigation
scope. `tests/guest_interruption.cjs` force-kills the controller and verifies
deadline-based termination reconciliation without inventing a successful outcome.
