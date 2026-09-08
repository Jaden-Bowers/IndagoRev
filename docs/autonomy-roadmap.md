# Closing the autonomy gap — working backlog

Updated 2026-09-07. This supplements the final development plan; it does not
replace its scientific limits. The implementation is primarily C/C++, with one
native entry point and bundled engine workers. A usable autonomous product must
close the observation → hypothesis → experiment → counterexample → revised claim
loop, not merely accumulate tool adapters. No finite implementation can guarantee
complete understanding of every program or unavailable external system.

## Current iteration

Latest operator authorization (after the overnight wrap-up): use the local
LM Studio model `huihui-qwen3.8-27b-abliterated` for harness testing. Endpoint
`http://127.0.0.1:1234/v1/chat/completions` was discovered on loopback; no cloud
fallback or credentials. Older "live inference unconfigured" entries below
describe earlier snapshots. Unknown targets remain static-only on this host.
Live testing found and fixed LM Studio's rejection of named-object tool_choice;
the local adapter now uses required with its single investigate tool. Windows
rebuild and offline controller regression pass. Initial real runs reached native
analysis and hash-verified evidence retrieval but exhausted their generation
budgets without a cited finish; do not call those runs successful solves.
The [live validation record](local-harness-validation-2026-09-07.md) documents
all target runs, the compact loaded-context profile, passing native regressions,
and subsequent operator-authorized model-specific template/context repairs.
The local model now serves structured calls, but one cited report hallucinated
ARM64 Mach-O for a PE/x86 target. Bounded native-observation retention and a
finish-only final-turn protocol address demonstrated gaps; citation validity
alone remains insufficient to qualify semantic correctness. Current loaded
context is 12288 tokens; the original serving defaults are backed up.
Final local fixture and FLARE-On C3 smoke runs now produce cited partial reports
with correct native format/architecture labels in under 40 seconds each. The
fixture's incomplete-source audit remains visible; address arithmetic errors
still fail semantic review. The follow-up [reliability iteration](reliability-iteration-2026-09-07.md)
adds explicit numerical/structural checks, cross-backend guidance, bounded recovery
history, interrupted Ghidra-import recovery and source-backed PE/ELF dynamic
feedback checks. These improve the tool loop, not universal autonomous solving.

Implemented in this iteration:

- Explicit 1–32 imported-component investigation scope, pinned to target IDs and
  content hashes. Primary-target compatibility remains for existing investigations.
  New imports do not silently expand scope. Per-component analysis and citations
  use one shared action budget and one reasoning owner.
- Shared bounded `harness read` packets for built-in and external owners; scoped
  knowledge show/list, transitive dependency checks and component-scope paging.
- Artifact filtering retained through graph expansion and runtime coverage summaries.
- Each SSE model declaration must match the pinned model, not just the last event.
- Storage preflight/poll guards for Windows qualification and a read-only, bounded
  FLARE-On file catalogue. This is **not** a challenge solve/qualification run.
- Opt-in durable knowledge assertions and finite byte/transform validators now
  reuse harness proposal/run in both ownership modes. Dependencies are pinned,
  negative results retain counterexamples, uncertain mutations are not replayed,
  and portable bundles drop mutation grants. See [contract and remaining limits](harness-mutations.md).
- Separate bounded derived-artifact grants allow existing transforms to publish,
  verify and admit their outputs through a durable ledger while retaining immutable
  roots and the pinned primary. Static reanalysis/finite validation uses the same
  action path. Unknown receipts do not auto-replay or expand scope; imported bundles
  retain historical lineage but strip new publication grants. See [derived contract](harness-derived.md).
- Native workbench children are now killable by timeout/cancellation. Exact action
  publication pointers commit with knowledge revisions and recover lost receipts
  without replay; unlinked staging/import effects remain unknown. This is not an
  OS memory quota or hostile-code sandbox. See [worker contract](harness-workers.md).
- Native `system create/show/list/preflight` declarations now pin component
  identity, validate launch dependencies and bounded guest policies, and perform
  byte-budgeted integrity preflight. A declaration can bind static harness roots
  and report provenance. Execution remains blocked without a provider-attested
  disposable lab. See [system manifest contract](system-manifest.md).
- Frida socket observations now retain collection-local handle generations,
  bounded API byte windows, explicit native outcomes and incomplete-identity
  labels. `runtime network` pages source-hashed observations and filters by socket;
  `runtime identities --kind socket` exposes their lifetimes. This is not packet
  capture or complete connection identity. See [network evidence](network-evidence.md).
- Guarded `knowledge.revise` updates only an investigation's own untouched
  assertions with exact predecessor revisions, immutable history and transactional
  action dependency checks. Computed records/operator edits remain protected;
  offline controller checks now include counterexample-driven assertion revision.
- Read-only report audits flag changed/superseded/incomplete citations and later
  Ghidra Program revisions without rewriting saved answers. The audit does not
  rehash raw sources or establish semantic entailment. See [report audits](report-audit.md).
- Unchanged generated payload inputs preserve their timestamps across native
  reconfiguration. Both platforms verified identical hashes/timestamps; no tools,
  payload bytes or integrity checks were removed. See [build-churn checks](build-churn.md).

Live inference remains unconfigured, per the operator's explicit choice. GUI work
remains deferred. These scoped read capabilities do not constitute a disposable lab,
runtime system manifest, independent validator or complete harness.

Managed-code inventory/decompilation passed native job/index/harness gates on
Windows and Linux. The bounded IL/reference view passed native integration and
direct-worker checks on both platforms. See [managed analysis and explicit remaining limits](managed-analysis.md).
Hash-pinned [evidence paging](evidence-paging.md) now navigates large native JSON
and UTF-8 text through the shared read envelope; Windows/Linux development checks
pass, including scoped index-to-native-evidence navigation. Bundled capa/FLOSS
enrichment now passes native adapter/index/harness verification on Windows PE and
Linux ELF. .NET capa and selected x86/x64 PE decoder-emulation fixtures pass too;
see [enrichment scope and release limits](enrichment.md).
LIEF's C++ metadata adapter now passes native service/index/harness checks on PE
and ELF, including a byte-verified PE resource → granted derived artifact → finite
fixture validation loop. See [format metadata](format-metadata.md). Group-local
engine cache identities avoid duplicating unchanged tools on unrelated updates;
Frida smoke checks pass on both platforms. Legacy caches have not been deleted.
The Windows and source-built Linux offline Wireshark adapters now pass capture-
import/native-byte/index/harness microchecks on fabricated PCAP/PCAPNG, including
truncated captures and caller-profile isolation. Native TCP/UDP stream grouping
and TCP reassembly/ACK frame references preserve profile-scoped identities, page-
local membership, upstream pointers and explicit projection limits. Both CLI
workers pass a fabricated split-HTTP reassembly fixture, including a final-frame-
only page. This is not live capture, proven connection/process attribution or
complete stream reconstruction; see [offline network evidence](offline-network.md).
Linux Lua/plugins/libpcap are compiled out; optional decoder feature differences,
host glibc baseline and outstanding source/license delivery are documented.

Shared-index follow-up: publication status now survives separately from native
verdict vocabulary and normalization limits. Failed retries do not advance heads
or become layouts for later queries; reindex uses saved evidence status. Historical
native evidence is not rewritten. Windows native regression passes 4/4
(`out/index-completeness-final-windows-checks.log`, 9.93s); Linux knowledge/model/
harness checks pass 3/3 (`out/index-completeness-linux-checks.log`, each test <=60s,
outer watchdog 240s). Both packet/index/harness CLI regressions pass, including
source-status propagation (`out/index-packet-final-{windows,linux}-checks.log`).
Reassembly passes on the updated Linux CLI (`out/index-reassembly-final-linux-checks.log`).
Generated Linux native-test copies of approximately 1.7 GiB each are now removed
sequentially after preserving hashes/logs; application and old caches are untouched.
Subsequent [lossless payload compression](payload-compression.md) reduces embedded
worker storage by 436,538,256 bytes on Windows and 545,937,838 bytes on Linux,
without changing expanded tool bytes. Codec/refusal tests pass on both platforms;
native Windows 4/4, Linux 3/3 and both Frida/packet CLI regressions pass. Linux
generated test copies now peak near 1.23 GiB; their persistent logs are under
`out/qualification-linux-native`, separate from temporary executables.

Replay preparation: pinned upstream rr 5.9.0 recorded, packed and autopilot-replayed
small source-backed x86 and x64 ELF fixtures in WSL without changing kernel policy
or spoofing CPU support. A Windows-mounted `RR_TMPDIR` failed natively; keeping only
shared-memory scratch on native Linux temporary storage permits traces to persist
in the project. See `out/rr-native-tmp-{x86,x64}-probe.log`. This is not yet an
implemented product replay backend, and no unknown target was executed.

Wrap-up 2026-09-07: rr was subsequently built from the pinned source with static
non-system dependencies and a documented glibc 2.43 legacy-termio compatibility
change. Source-built x86/x64 record/pack/autopilot probes pass. Initial native
`runtime record/replay` session, schema, bounded launcher and trace-manifest code
is now written. Linux enabled-branch syntax checks and focused trace identity /
size / link-refusal tests pass. **The new rr payload is not yet staged in the
main binaries; product relink, session/timeout/cancellation tests and dependency
notice closure remain pending.** Do not count rr as a shipped CLI capability.
See [overnight wrap-up and current state](overnight-state-2026-09-07.md).

## Ordered work and completion gates

1. **Finish the deterministic harness action envelope.** Reuse knowledge publication,
   transforms and finite validators through durable proposals, shared budgets,
   cancellation and crash-safe dispatch. Give derived artifacts explicit lineage
   and bounded admission rules, not an implicit all-project grant. Preserve failed
   approaches and counterexamples. Make evidence retrieval navigable rather than
   silently truncating large answers. Gate: a scripted offline controller can
   derive bytes, analyze the admitted result, test a deliberately wrong hypothesis,
   revise it and resume without repeating an uncertain side effect.
2. **Target-system manifest and disposable-lab lifecycle.** Describe imported
   components, entry points, launch order, services, runtimes, files, environment,
   accounts/keys supplied by the operator, expected dependencies and reset policy.
   Allocate → attest/preflight → run → collect → reset → verify reset → release;
   quarantine failed resets. Static scope is an input to this layer, not proof of
   containment. Default disconnected/simulated networking; enforce it outside the
   guest. WSL is useful for Linux builds, **not the hostile-code containment boundary**.
   Gate: restart/orphan/cancel exercises against source-backed lab fixtures.
3. **Runtime/helper actions under predeclared grants.** Connect existing DbgEng/GDB,
   Frida, DynamoRIO, capture/reanalysis and symbolic tools to the harness. Provide
   bounded ordinary-software decoder/compiler helpers in a separate sandbox with
   no controller credentials or undeclared network access. Never add another LLM
   owner. Track output artifacts, effects and cleanup even on failure. Gate: benign
   two-component fixture with a hidden decoder and independent behavior oracle.
4. **Experiments and causal identities.** Persist process incarnation, thread/module
   lifetime, endpoint/socket generation, IPC request/buffer identities and code epochs.
   Join API arguments/results, byte captures and static locations only when the
   evidence supports the join. Record clock domains, offsets/uncertainty, missing
   events and observer effects. Allow one-variable controlled experiments and
   explicit counterfactuals. Gate: seeded cross-process request/response chain,
   including handle/PID reuse and dropped telemetry.
5. **Network debugging**, specified below. Gate: source-backed local client/server
   fixtures with intentionally fragmented, retried and truncated conversations;
   a packet-derived claim can be traced to bytes and a process/API observation,
   while absent/decrypted content remains explicitly unknown.
6. **Enrichment, managed code and replay.** Integrate the previously planned
   capa/FLOSS, ILSpy and LIEF capabilities where demonstrated missing; integrate
   supported Linux rr recording/replay. Keep their native verdicts, provenance,
   compatibility limits and licenses. No Python rewrite of the native application;
   an upstream runtime, if unavoidable, is a declared bundled worker footprint.
   Gate each adapter on small benign cases and failure contracts before packaging.
7. **Task-focused semantic recovery.** Improve missing external-call models,
   constrained symbolic slicing, concrete witnesses, input constraints, unpacking
   and runtime-generated code, finite state/protocol reconstruction and partial
   VM-handler recovery. Prioritize measured failures rather than another x86 IR,
   universal devirtualizer or invented solver success. Triton/libipt remain
   demonstrated-need choices. Gate: held-out implementations and counterexamples,
   not recognition of public challenge solutions.
8. **Selected protected-system observation profiles.** PANDA/whole-system replay,
   kernel/VMI/DRAKVUF or hardware tracing only behind provisioned lab capabilities.
   Start with a source-backed user/service/driver surrogate. Measure missing events,
   timing changes and unavailable server/device behavior. This is an understanding
   and observation-fidelity track, not invisible-debugging, anti-cheat bypass or
   live-service manipulation functionality.
9. **Behavioral acceptance and honest stopping.** Machine-readable question/product
   obligations, independently supplied verifiers, finite tested-equivalence labels,
   contradiction reopening, stale-claim invalidation and explicit environment gaps.
   Model-authored expected output is not independent truth. Keep `verified_solve`
   false until an applicable independent verifier actually succeeds. Live model
   probes/tokenizer qualification wait for explicit configuration; the offline
   implementation and contract tests can continue meanwhile.
10. **Optimization after the harness implementation.** Profile cold/warm startup,
    hashing, query plans, repeated serialization and payload extraction before
    changing behavior. Measure installed, cached and build footprints separately.
    Prefer cache reuse, deduplicated immutable blobs, bounded indexes, compression
    and build-artifact retention policy. Preserve all tools, worker isolation,
    source/license obligations and raw-evidence access. Do not delete source,
    challenge archives or user work to make benchmark room.

## Network-debugging design

The existing Frida network recipe supplies API-level observations; it is not a
packet capture engine or complete protocol debugger.

First implement **offline PCAP/PCAPNG ingestion** using a pinned existing native
decoder (Wireshark wiretap/dissectors or a privately bundled TShark worker), rather
than constructing another protocol semantic stack. Preserve file hash, interface,
packet ordinal, byte ranges, timestamp resolution, captured/original length,
native fields and reassembly provenance. Apply worker time/memory/output limits
even to offline captures: packet parsers process untrusted input.

Then add a **lab-scoped capture worker** with an explicit interface/filter, packet,
byte, duration and ring-buffer limit. Capture and dissection use separate privilege
domains, following Wireshark's existing separation. Persist loss/overrun/rotation
and shutdown status rather than equating a stopped capture with complete coverage.
[Wireshark capture architecture](https://www.wireshark.org/docs/wsdg_html_chunked/ChWorksCapturePackets.html),
[dumpcap limits](https://www.wireshark.org/docs/man-pages/dumpcap.html).

Normalized flow identity includes experiment, observer, namespace/interface,
transport, endpoints and connection incarnation—not just a reusable five-tuple.
Correlate connect/accept/send/receive/close API events and process lifetimes with
packet streams. Keep packet loss, asynchronous completion, partial writes, socket
reuse and clock uncertainty visible. Offer bounded flow listing, stream windows,
protocol fields, API/packet cross-reference and observation-triggered breakpoints
in an authorized lab. A hostname or plaintext string is a lead, not proof that a
remote action occurred.

Controlled DNS/HTTP/TCP services and transcript replay may supply repeatable inputs
inside the lab. Do not contact sample-derived destinations or capture unrelated
host traffic. TLS decryption requires explicitly supplied session keys or approved
instrumentation; no claim that arbitrary encrypted traffic is recoverable. Do not
install a host-wide certificate authority or capture driver implicitly.

For Windows, Npcap bundling is a separate packaging decision: its vendor offers a
specific OEM redistribution license. Do not assume source availability permits
shipping it, and do not buy/install it automatically. Offline capture analysis and
Linux lab-side capture can progress without that decision.
[Npcap redistribution information](https://npcap.com/oem/redist).

## Target tracks and grading

- **FLARE-On:** local input root is
  `C:/Users/Jaden/Desktop/Projects/IndagoRev/flare-on-chals/Flare-On-Challenges/Challenges`.
  The sibling `Write-ups` tree is excluded. Current directory names cover 2014–2024;
  this is not asserted to be the complete official archive. Record exact artifact
  hashes, environment dependencies and independent challenge verifiers before a
  frozen run. Keep public-target contamination separate from private success rates.
- **Malware:** classify/explain observable behavior and recovered configuration
  within isolated experiments. Unknown samples do not execute on this workstation.
  Missing C2, keys or victim state are environment gaps, not permission to reach
  live infrastructure or fabricate behavior.
- **EDR/anti-cheat style systems:** start with controlled surrogates for services,
  IPC, drivers, integrity/timing checks and observer interference. Analyze authorized
  real systems only in a prepared environment. Do not promise every physical device,
  remote service or hidden kernel path is observable.

## Low-storage development policy

At the start of this iteration C: had approximately 45 GiB free. Recheck before
every material build/test batch; this is a snapshot, not a capacity guarantee.

- Default development-test floor: **20 GiB free**, plus **512 MiB scratch reservation**.
  `tests/bounded_qualification.ps1` checks admission and polls available space while
  running; it terminates only its own child process tree on time/storage breach.
  Volume deltas include unrelated writers and are a conservative stop signal,
  **not a hard filesystem quota**. Worker-enforced trace/blob quotas remain work.
- Prefer microfixtures and a small explicit challenge shard. Do not extract an
  entire edition/archive or duplicate engine payloads for a broad benchmark.
  Tests that intentionally copy the full executable need a separately sized
  scratch reservation; the default should stop them rather than exhaust disk.
- Every test process has a deadline below ten minutes; default suite watchdog
  eight minutes, microchecks normally at most one minute. Do not chain unbounded
  corpus runs under the name of one test.
- `tests/corpus_catalogue.ps1` lists metadata, never extracts or executes. It
  excludes write-ups/document sidecars and reparse points, limits traversal/time,
  hashes at most 64 MiB per invocation by default and labels unhashed files.
  Its report is at most 2 MiB. Do not mistake listing completion for complete hashes
  or challenge qualification.
- Retain concise evidence and failure diagnostics. Do not delete existing logs,
  caches, samples or build trees without resolving ownership and recoverability.

## Resume checklist

Latest completed development checks (2026-09-07):

Report-audit native checks passed Windows 4/4 (8.17 seconds) and Linux 5/5;
the updated CLI revision/audit smoke passed Windows (1.51 seconds) and Linux
PE/ELF32/ELF64 within the six-suite regression (`out/harness-audit-linux-cli-checks.log`).
The real bundled-worker static gate passed PE before the combined 180-second
watchdog expired. ELF was then run as a separate shard and passed in 146.32 seconds,
also under 180 seconds (`out/post-audit-elf-static-gate.log`). Both format gates
persisted 21 evidence records each and checked independent views/indexed relations.
The combined timeout is retained, not relabeled a pass (`out/post-audit-static-gate.log`).
No target execution occurred. Approximately 42.8 GiB remained free afterward.

Returned network-address windows now respect entry capacity as well as returned
length. Native API-call pairing checks passed Windows 4/4 and Linux 5/5; embedded
Frida smokes passed both platforms after correcting Linux payload dependencies.
The bundled-worker static checks above preceded this network-only refinement.

Current worker/recovery/system-declaration increment: Windows native 4/4 passed
in 7.79 seconds (`out/system-binding-windows-checks.log`, individual timeout 60s).
Windows CLI harness/manifest binding passed in 1.76 seconds
(`out/qualification-harness-557a01c83e044e35b35f19b4eb0256cc/`); knowledge/system
preflight passed in 3.51 seconds (`out/qualification-knowledge-3224e590e2f5487aa64009f4b9143ff4/`).
Both CLI suites used 60-second watchdogs and storage guards. Linux rebuild succeeded:
native HTTP/model/harness/knowledge/process tests passed 5/5
(`out/system-binding-linux-checks.log`, each deadline 60s, outer watchdog 240s), and
CLI knowledge/PE/ELF32/ELF64 harness/source-backed runtime passed 6/6
(`out/system-binding-linux-cli-checks.log`, outer watchdog 120s).
About 45.2 GiB remains free. Earlier entries below describe their then-current
in-process implementation; the new mutation worker replaces that limitation.

Lab environment check: Hyper-V management tools exist, but `Get-VM` failed because
this session lacks management permission. No VM was changed or started. An optional
operator question requests the dedicated lab VM/checkpoint names; continue safe
offline work rather than assuming access or using WSL as containment. No TShark,
dumpcap, QEMU or libvirt command was found on the inspected PATHs; that is not a
whole-machine installation inventory.

Network API increment: Frida now tracks bounded socket generations,
close/reuse uncertainty and attempted/returned byte counts while retaining native
events. Runtime observation/lifetime IDs are scoped to the collection. Mocked
Windows/Linux recipe checks passed; latest Windows embedded smoke passed in
6.12s, including sequence cursors. Linux API/offset/filter smoke passed; its
sequence-cursor native checks passed 5/5 and embedded Frida smoke passed under a
60-second watchdog (`out/network-cursor-linux-checks.log`,
`out/network-cursor-linux-frida-checks.log`). Native guarded-revision checks
passed Windows 4/4 and Linux 5/5; Linux CLI suites passed 6/6. See
`out/harness-revisions-windows-checks.log`, `out/harness-revisions-linux-checks.log`
and `out/harness-revisions-linux-cli-checks.log`. Approximately 44.3 GiB remains free.
See [network evidence contract and precise verification status](network-evidence.md).
No packet capture/protocol decoder is implemented by this increment.

Derived-publication increment: Windows native 3/3 (8.58 seconds), Windows CLI
harness passed (1.65 seconds), Linux native 4/4 and Linux CLI 6/6. Both native
builds succeeded. See `out/harness-derived-windows-checks.log`,
`out/harness-derived-linux-checks.log`, `out/harness-derived-linux-cli-checks.log`
and [verification details](harness-derived.md). The offline controller now performs
transform → admit → native XAIR inventory → counterexample → corrected finite
comparison. Unknown-dispatch non-replay is checked separately. No live inference,
hostile execution or archive extraction; C: retains approximately 45.3 GiB free.
Capsules remain in-process; do not describe their wall reservations as killable
worker deadlines or their byte reservations as filesystem quotas.

Mutation increment: Windows native 3/3 (3.32 seconds), Windows
CLI harness passed (1.06 seconds), Linux native 4/4 and Linux CLI 6/6. See
`out/harness-mutations-windows-checks.log`, `out/harness-mutations-linux-checks.log`,
`out/harness-mutations-linux-cli-checks.log` and [mutation verification details](harness-mutations.md).
Subject pins now reach the workbench publication transaction, rather than relying
only on the harness preflight. No live inference or hostile execution; about
45.3 GiB remained free. Workbench operations are still bounded in-process capsules,
not separately killable workers. Derived-target admission/publication was added
in the following increment; see the verification entry below.

Earlier scoped-read increment:

- Windows scoped harness/model/knowledge regression: 3/3, 2.48 seconds;
  `out/autonomy-windows-checks.log`.
- Windows CLI harness under the new storage guard: passed, 0.71 seconds;
  `out/qualification-harness-091b7e6e95b74f5cb049ed2d214fc728/`.
  An impossible free-space requirement was also rejected before test launch.
- Linux native HTTP/model/harness/knowledge regression: 4/4, each with a 60-second
  deadline; `out/autonomy-linux-checks.log`. Builds on both platforms succeeded.
- Linux bounded CLI knowledge, PE harness, ELF32/64 harness and source-backed
  runtime suites: 6/6; `out/autonomy-linux-cli-checks.log` (outer watchdog 120 seconds).
- Synthetic catalogue checks cover file/hash budgets, exclusions, ordering and
  insufficient-space refusal; no target execution. Local catalogue output is
  `out/flare-catalogue.json`: 107 files, 221,963,719 listed bytes, 67,105,551 hashed
  bytes and 34 unhashed files. The listing is complete within the selected directory;
  hashes and challenge qualification are not. No archive extraction occurred.

The active task-bound continuation is named `Continue IndagoRev autonomy work`,
scheduled every 30 minutes. It preserves the inference, storage, test-duration and
host-execution restrictions above. This is continued development, not an unattended
malware execution grant. Local scheduled work requires the computer on and app running.

Read this file and the latest test logs before continuing. Preserve user changes,
keep inference unconfigured, and do not start hostile execution or large downloads.
Next implementation milestone: provider-bound disposable-lab lifecycle and
attestation, plus richer revision/independent-verifier workflows. Knowledge
publication, finite validators, bounded derived admission, killable mutation
children and exact committed-revision recovery are implemented. Unlinked
pre-publication filesystem effects, OS resource quotas and hostile-code isolation
remain unfinished. System declarations/static binding are implemented; real lab
allocation/reset verification is not. Offline network ingestion is implemented;
next network steps are explicit container timestamp resolution, scoped stream
windows/derived bytes and lab-bound API/packet correlation, not host live capture.
Update implemented status and actual tests after each iteration. Never relabel a
planned capability, mock provider response or finite fixture as a universal solve.
