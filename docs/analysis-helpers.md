# Bounded analysis helpers

Current expanded contract: [pre-Task 8 helpers and protection analysis](pre-task8-and-protection.md).
The newer profile adds Python/Unicorn, content-pinned standard libraries, scoped
multi-artifact inputs, file receipts and aggregate cgroup limits. Historical
one-slice examples below remain valid; their original smaller limits are
superseded by the current contract.

An investigation's single model can now propose `workbench/helper.run` actions.
The implementation and controller remain C/C++. There is no terminal UI, shell
tool, second model, package installer, or unrestricted execution fallback.

## Enable and use

The initial execution profile is **Linux x86-64**, including the native Linux CLI
inside WSL. Windows-native calls retain a `capability_blocked` receipt. Running
the Windows CLI does not silently launch WSL or acquire new host authority.

Install the operator-managed build tools: `gcc`, `g++`, `libc6-dev`, `binutils`,
`util-linux` (prlimit), and `bubblewrap`. Bubblewrap must support `--size`,
`--disable-userns`, and unprivileged user/PID/network namespaces. Development
checks used bubblewrap 0.11.1 and GCC 15.2. No host kernel policy is changed; if
namespace setup fails, the action fails closed. This profile currently uses
installed toolchain packages, not an embedded compiler or attested root image.
The kernel must support `close_range`; the helper stage closes all inherited
non-stdio descriptors before compilation or solving and fails closed if that
sanitization is unavailable.

Build the ordinary Linux executable using the [native preset](building.md).
When creating an investigation, the operator must set both:

```json
{"workbench_mutations": true, "analysis_helpers": true}
```

The model cannot add this grant. Imported portable investigations lose it.
Helpers consume ordinary action reservations: **20 seconds**, 64 KiB result
reservation, and a declared 768 MiB compilation allowance per action. Ownership,
revision checks, idempotency, cancellation, and uncertain-outcome handling are
the existing investigation mechanisms. An interrupted action without a committed
receipt is not silently replayed.

Use `harness read` with `family:helper,operation:capabilities` to inspect the
platform/grant. The model proposes an ordinary `analyze` decision:

```json
{
  "proposal": {
    "gap": "Cross-check the selected bytes",
    "expected_evidence": "A bounded helper receipt",
    "prediction": "Output equals the original slice",
    "fallback": "Inspect the failure receipt without claiming a solve"
  },
  "request": {
    "backend": "workbench",
    "operation": "helper.run",
    "arguments": {
      "language": "c17",
      "source_code": "#include <stdio.h>\nint main(void){int c;while((c=getchar())!=EOF)putchar(c);}",
      "input": {"offset": 0, "max_bytes": 4},
      "validation": {
        "kind": "artifact_bytes",
        "expected": {"offset": 0, "max_bytes": 4}
      }
    }
  }
}
```

The offsets above illustrate the protocol, not a challenge solution. Select real
ranges from evidence. `input` and `expected` also accept `address` instead of
`offset`, and optional `raw_sha256`. XAIR maps only file-backed virtual addresses.
The selected component is pinned; neither field accepts a host path. Inputs are
limited to 1 KiB and source to 16 KiB (also subject to the capsule's 32 KiB JSON
argument ceiling). There are no caller-supplied compiler flags, executables,
environment entries, mount paths, include paths, or dependency downloads.

`c++20` supports small input generators and algorithms using the standard library.
`python3` uses the operator-installed `/usr/bin/python3` in the same Linux
namespace and seccomp boundary. `-I -S -B` disables environment/user-site loading,
site initialization and bytecode writes. The proposal seals the interpreter hash;
each execution checks it and records the version. The system standard library is
still operator-managed, not a separately attested or bundled Python distribution.
No package installation or network is granted. Source revisions are separate
actions; bounded exception tracebacks remain in `stderr_hex` for inspection and
repair. Python retains the existing 256 MiB address-space, 1.2-second execution,
4 KiB output and 1 KiB input limits. Larger multi-artifact helpers remain pending.

`smt2` evaluates SMT-LIB through the **already linked Z3**, with a million-unit
solver effort limit and an external wall deadline. Include `check-sat` and desired
model/value queries in the source. The artifact slice is retained as provenance;
it does not automatically become a solver constraint. Model-declared constraints
are not proof that the target implements them.

## Execution boundary

Each observation starts in a fresh bubblewrap user/PID/network/IPC/UTS namespace.
The sandbox exposes read-only `/usr/bin`, `/usr/lib`, `/usr/libexec` where present, `/usr/include`, library
directories, two staged input files, and the native helper engine. The root is
read-only. Only a **64 MiB tmpfs `/tmp`** is writable; `/dev/null` is the sole
exposed device. No project database, controller profile, credential environment,
home directories, `/etc`, `/proc`, `/usr/local`, `/mnt`, or host workspace is
mounted. The environment is replaced by fixed PATH/locale/timezone/epoch values.

The compiler has a 768 MiB address-space ceiling and a three-second CPU limit.
Generated native execution has a 256 MiB address-space ceiling and a 1.2-second
wall deadline. Seccomp denies process/thread creation, sockets, namespace/mount
changes, ptrace/process-memory access, pidfd access, process-group escape, and
selected privileged kernel interfaces. Output is capped at 4 KiB per stream.
Compilation has a three-second wall deadline; each enclosing namespace has seven
seconds. The trusted native stage and embedded SMT engine additionally need room
for the executable's read-only bundle mapping, with a 768 MiB allowance; this is
not a claim of a 256 MiB aggregate limit for every process in the action.

There are **two fresh compilations/namespaces**, not two runs sharing mutable
scratch. The receipt compares output, compiled image hashes, and dependency
metadata. `repeatable_observed` means these two observations agreed; clocks,
randomness, and unspecified language behavior are not made mathematically
deterministic. Timeout, missing EOF, truncated output, compile failure, and
nonzero exits cannot pass validation.

This is a constrained local helper sandbox, **not** a disposable malware VM or
a defense against kernel/toolchain vulnerabilities. The operator-managed system
toolchain is trusted. Compiler version/hash, engine hash, Z3 version, bubblewrap
version/hash, and Debian package-database hash are recorded where available.
The package-database hash is provenance, not attestation of every installed file.

## Evidence and validation

An immutable `product` knowledge revision contains source, source hash, original
artifact/slice hashes and mapping, input bytes, compile diagnostics, dependency
metadata, compiled hashes, both output streams, exit/timeout/completeness fields,
wall duration, and output hashes. Its transactional publication pointer binds the
investigation/action/request. Scratch files are removed; receipts remain in the
evidence workspace. Interrupted staging may remain local but is never mounted by
a later action. No helper output is automatically admitted as a new target.

Validation kinds:

- `artifact_bytes`: exact equality with another pinned slice of the same scoped
  original artifact.
- `calculation`: compare with the existing finite native calculator, using
  `program:{iterations,variables,body,emit}` on the same input bytes. This checks
  consistency with a model-declared transform, not target-semantic equivalence.
- `none`: retain an unvalidated candidate, including solver answers.

All records remain `state:unknown`, `verified_solve:false`, and
`behavior_verified:false`. Downstream evidence/acceptance/independent grading
requirements are unchanged. Two helpers agreeing does not make either an oracle.
`target_execution:false` means the selected original artifact is not launched.
A helper may reproduce target logic; its code is still treated as untrusted and
confined to the helper sandbox.

For bounded model retrieval use `family:helper,operation:read` with
`request:{id:KNOWLEDGE_ID,revision:1,pointer:"/output_hex",offset:0,max_bytes:1024}`.
Other useful pointers are `/source_code`, `/status`, `/validation_passed`, and
`/stages/0/result/compile/stderr_hex`. Pages retain the receipt hash, revision,
freshness and original pointer. Follow `next_offset`; large objects require a
narrower pointer. Helper stdout/stderr remain untrusted hex, never instructions.

## Catalogue research and native-operation priorities

The frozen 2014–2024 catalogue has 116 available challenges. Its member hints
include 99 PE candidates, 62 script candidates, 11 packet captures, four Android
archives, two nested archives, and 170 unknowns. These are **member hints, not
challenge-family counts**: the script set includes HTML and bundled JavaScript
libraries. All environment requirements still need target-level assessment.
Nothing here changes the frozen benchmark or consumes 2025 holdouts.

The [Task 3 development evaluation](general-investigation-evaluation.md) already
demonstrates a rolling rotate/subtract/XOR decoder expressed through the finite
calculator. That is evidence for keeping bounded integer/byte operations native,
not for adding a general Python runtime to the core.

Initial environments justified by this evidence:

1. Finite native calculator for simple byte arithmetic and stateful decoders.
2. C17/C++20 for bounded table reconstruction, permutations, candidate generation,
   binary parsing experiments, and algorithms outside the calculator grammar.
3. Existing Z3 for bit-vector/integer constraints and bounded candidate solving.

Additional isolated Python/JavaScript, .NET/C#, Java/Android, crypto-library, or
emulation profiles should require concrete unsupported cases and pinned
dependencies. Script-file prevalence alone does not establish that executing
those languages is necessary. ILSpy, Ghidra, XAIR, and packet tools remain the
first sources of semantics; helpers should not reproduce those engines.

Promote recurring validated helpers into native operations in this order:

1. Wider byte-table/index/permutation and rolling-state calculations with exact
   input/output bounds and forward-reencoding checks.
2. Finite constraint templates whose variable widths, source mappings and
   acceptance predicates are independently tied to evidence.
3. Demonstrated crypto/hash/string-decoder families using established libraries,
   after retaining counterexamples and distinguishing recognition from proof.
4. Structured candidate generators and format parsers once repeated helper
   receipts establish stable contracts. Do not promote arbitrary generated C
   into a supposedly authoritative target IR.

The isolation design follows the upstream [bubblewrap interface](https://github.com/containers/bubblewrap/blob/main/bubblewrap.c)
and [namespace/mount documentation](https://manpages.debian.org/experimental/bubblewrap/bwrap.1.en.html).

## Bounded development checks

```sh
cmake --build out/native-Linux --target indago indago_helper_tests --parallel 4
TMPDIR="$PWD/out" timeout 90 ./out/native-Linux/indago_helper_tests
```

The suite covers scoped input rejection, grant enforcement, tampered pins,
compilation, generation, solver execution, exact and negative validation,
transactional receipt reuse, fresh scratch, credential/descriptor isolation,
host filesystem/network/process restrictions, timeout, output and memory bounds.
Windows builds exercise fail-closed behavior. These are bounded development checks,
not adversarial sandbox or full-catalogue qualification.

Development verification on 2026-09-12 passed all four affected suites (helper
workspace, process supervision, harness, and model controller) on Linux in
24.36 seconds and Windows in 17.68 seconds. The controller regression uses an
offline scripted provider; live-model helper use has not yet been evaluated.
