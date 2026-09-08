
---
title: "Autonomous Reverse Engineering Platform"
subtitle: "Consolidated Engineering Project Plan - GUI + Agent-Native CLI/API, Multi-Process/Kernel Analysis, OPSEC and Observation Fidelity"
author: "Engineering planning document"
date: "Version 2.0 | August 31, 2026"
lang: en-US
---

> **Authorized-use boundary.** This plan is for lawful, authorized reverse engineering, interoperability, incident response, malware analysis, defensive research, and controlled laboratory testing. It does not authorize service abuse, unauthorized access, evasion of contractual or legal controls, or exposure of third-party systems and accounts. Legal review is required for anti-circumvention, EULA, privacy, export-control, and software-license questions.

# Document control
| Field | Value |
| --- | --- |
| Document | Consolidated engineering project plan |
| Version | 2.0 |
| Research snapshot | August 31, 2026 |
| Primary source | User-provided Autonomous Reverse Engineering Platform - Project Outline |
| Product shape | Shared C/C++ analysis core with a human+AI GUI and an agent-native CLI/API |
| Intended use | Authorized reverse engineering, interoperability, incident response, malware research, vulnerability research, and defensive analysis |
| Planning horizon | MVP through advanced hostile-target research |


## How to read this plan

This document consolidates the original project outline with the later design decisions for multi-process and kernel-space targets, anti-analysis behavior, operational security, environment fidelity, virtual-machine introspection, controlled bare-metal workers, processor trace, and optional external-memory observation. The original outline remains the source of the product goal, major analysis disciplines, GUI/CLI split, plugin architecture, evidence requirements, and staged development model. The added material converts those requirements into a more explicit engineering architecture and delivery sequence.

The word **must** denotes a release or safety requirement. **Should** denotes the recommended design. **Research** denotes a capability that should not be marketed as generally reliable until it passes a published support matrix and benchmark gate.

# Executive summary

The product should be built as an **autonomous reverse-engineering orchestration and evidence system**, not as another monolithic disassembler or an LLM wrapper around a decompiler. A user or external coding agent asks a natural-language question. The platform compiles that question into required program facts, searches the existing project evidence, identifies gaps, selects bounded analysis actions, applies security and OPSEC policy, executes the actions in isolated workers, validates conflicting results, and returns an answer with provenance and uncertainty.

The two product surfaces share one state and one analysis core:

1. A **GUI** for paired human+AI reversing, with disassembly, pseudocode, CFGs, process/kernel topology, traces, timelines, protocol views, hypotheses, evidence, and natural-language interaction.
2. An **agent-native CLI/API** for Codex, Claude Code, CI systems, scripts, and other coding harnesses. It exposes typed actions, deterministic JSON, pagination, resumable jobs, evidence IDs, and an MCP adapter so the external agent does not need to understand the underlying tool ecosystem.

The central model must be a **TargetSystem**, not a single executable. A commercial game with a launcher, game process, anti-cheat client, service, driver, network service, and kernel interactions is one target. The same model generalizes to EDRs, browsers, service meshes, malware families, installers, and kernel/user products.

The platform should own the following differentiating layers:

- TargetSystem, artifact, execution-run, evidence, hypothesis, conclusion, and provenance schemas.
- Stable identity mapping from runtime observations to artifact hash, module instance, section, RVA, instruction, block, and function.
- The query-to-fact compiler, analysis planner, action DAG, policy engine, OPSEC/fidelity manager, and experiment registry.
- Backend-neutral APIs and a qualification framework.
- The agent-facing CLI/API and the shared-state GUI.

It should integrate mature open-source components for binary parsing, decoding, decompilation, DBI, emulation, replay, SMT, taint, malware enrichment, protocol analysis, VMI, hardware trace decoding, storage, and GUI infrastructure. Copyleft or high-risk components should normally run as isolated workers instead of being linked into a redistributable proprietary core.

The recommended MVP is deliberately narrower than the long-term vision: PE/ELF, x86/x86-64, strong static analysis, Ghidra decompilation, an evidence store, a deterministic CLI/API, and evidence-backed static questions. Native dynamic tracing follows. Whole-system replay, targeted symbolic execution, VMI, bare metal, hardware trace, external-memory acquisition, generalized devirtualization, and high-confidence autonomous analysis of current commercial anti-cheats/EDRs are later research phases.

Full removal of the human is not an honest early product promise. The realistic objective is to eliminate routine manual tool operation and make the machine perform evidence acquisition autonomously within explicit constraints. Humans remain authorization gates for externally visible, identity-exposing, irreversible, legally sensitive, or high-impact experiments. The system must be able to conclude **insufficient evidence**, **environment not representative**, **action blocked by policy**, or **physical observation required**.

## Recommended decisions at a glance

- Use a C++20 core with a narrow C plugin ABI and gRPC/Protocol Buffers service contracts.
- Own a small backend-neutral CoreIR/evidence schema. Do not make the database identical to Ghidra p-code, VEX, LLVM IR, Triton ASTs, or XAIR.
- Use Ghidra as a pinned, sandboxed headless decompiler worker rather than beginning with a fork of its decompiler core.
- Treat XAIR, XAIR_CFG, and XAIR_SYM as highly relevant conditional components. Complete license verification and qualification first. Treat AIRECE as design reference only unless the author grants written rights; its repository license states all rights reserved at the research snapshot.
- Use LIEF + Zydis + Capstone for the initial loader/decoder stack.
- Use DynamoRIO for primary user-space DBI; rr for Linux replay; PANDA/QEMU for whole-system replay; Triton/Z3 for targeted dynamic symbolic analysis.
- Use PostgreSQL + content-addressed artifacts + Parquet/Arrow traces + DuckDB analytics. Do not introduce a graph database in the MVP.
- Add an OPSEC/Fidelity Manager between the planner and execution backends. Its job is containment, asset protection, observation-fidelity assessment, and escalation - not a promise of an invisible debugger.
- Build a tiered execution laboratory: emulation, hardened disposable VM, VMI, controlled bare metal, hardware trace, and optional external-memory acquisition.
- Default to blocked or simulated networking. Valuable accounts, organizational identities, API keys, certificates, personal tokens, and LLM secrets never enter hostile workers.

## Product success criteria
| Dimension | Required outcome |
| --- | --- |
| Evidence quality | Every substantive answer cites static, dynamic, symbolic, experimental, or analyst evidence and distinguishes inference from observation. |
| Targeted autonomy | The controller identifies missing facts and schedules bounded analysis rather than attempting exhaustive reconstruction by default. |
| Shared state | GUI, CLI, SDK, and external coding agents operate on the same immutable evidence IDs and project state. |
| Hostile-target safety | Potentially malicious or destructive targets cannot reach controller secrets, trusted credentials, or unrestricted networks. |
| Observation fidelity | Every runtime conclusion is qualified by environment, observer footprint, timing effects, and cross-run consistency. |
| Reproducibility | Analysis actions are represented as versioned experiment manifests with pinned tools, inputs, policies, and outputs. |
| Backend independence | No core data model or user workflow depends on one decompiler, DBI framework, emulator, solver, or hypervisor. |


# 1. Product definition, scope, and realism

## 1.1 Product goal

Build an AI-native platform capable of progressively understanding large, complex, protected, and potentially malicious binaries through static analysis, dynamic observation, emulation, symbolic/concolic execution, taint, replay, differential analysis, and controlled experimentation. The platform should support Windows and Linux, user and kernel components, x86, x86-64, ARM, and ARM64 over time.

The product is not merely an AI decompiler. Its primary value is the loop shown below: a question is converted into required facts; existing evidence is searched; only missing evidence is acquired; the result is validated, stored, and used to answer the question.

![Question-to-evidence loop](/mnt/data/re_plan_assets/query_loop.png){ width=7.0in }

## 1.2 User groups

**Agent/API users** include coding agents, security automation, CI jobs, malware pipelines, and scripts. They require deterministic contracts, bounded outputs, low ambiguity, and resumability.

**Analyst GUI users** require synchronized disassembly, pseudocode, CFG, process/kernel topology, memory, trace, network, evidence, and hypothesis views. The AI and analyst must mutate the same project state rather than exchange pasted snippets.

**Platform operators** manage analysis workers, hypervisors, physical nodes, network simulations, licenses, images, budgets, and incident response. They require strict separation from hostile code and complete auditability.

## 1.3 Supported target classes by maturity

- **MVP:** ordinary PE/ELF user-space x86/x86-64 programs, libraries, CTF-style binaries, and static malware triage.
- **Product expansion:** multi-process applications, services, native tracing, runtime-generated code, packed samples, network protocols, ARM/AArch64, and bounded symbolic/taint analysis.
- **Advanced:** drivers/kernel modules, whole-system causality, VMI, anti-analysis divergence, controlled bare metal, processor trace, external-memory corroboration, custom VMs, and devirtualization.

## 1.4 Explicit non-goals and boundary conditions
| Non-goal | Reason |
| --- | --- |
| Universal automatic understanding | The platform will not reliably recover all semantics from every protected program. It must stop with an explicit evidence gap rather than invent an answer. |
| Invisible debugger promise | The platform will not claim a VM, debugger, VMI layer, DMA device, or trace mechanism is undetectable. |
| Automatic policy bypass | The system will not silently contact production services, expose valuable accounts, or attempt target-specific evasion to avoid enforcement. |
| All tools in one process | Copyleft, unstable, high-risk, and language-heavy dependencies remain isolated workers or optional user-supplied integrations. |
| Exhaustive whole-program symbolic execution | Symbolic execution is scoped to bounded regions selected from concrete evidence, slices, and hypotheses. |


## 1.5 Autonomy maturity model

**Level A - Retrieval automation.** Search and summarize already-derived static facts. This is achievable early.

**Level B - Analysis automation.** Run deterministic static actions, decompile functions, follow references, generate slices, and answer factual questions with provenance. This is the Phase 1 target.

**Level C - Experiment automation.** Select and run bounded traces, compare executions, capture artifacts, and perform targeted solving under policy. This is the Phase 3-4 target.

**Level D - Environment-aware system investigation.** Correlate multiple processes and kernel transitions, recognize observer-induced divergence, and switch observation tiers. This is a Phase 5-6 research target.

**Level E - Broad autonomous hostile-target reversing.** Recover high-level algorithms and behavior from novel, protected, environment-sensitive systems without analyst intervention. This remains research-grade and target dependent. Marketing should not imply general reliability until supported by measured public benchmarks.

# 2. Core design principles
| Principle | Engineering consequence |
| --- | --- |
| Question-driven analysis | Begin with the facts required to answer the question; acquire only the missing evidence. |
| Evidence over plausibility | An LLM can propose hypotheses, but only tools and controlled experiments can raise them to supported conclusions. |
| System, not binary | Model process trees, services, drivers, kernel objects, IPC, networks, and execution environments as one TargetSystem. |
| Stable identity bridge | Normalize runtime addresses to artifact hash, module instance, section, RVA, instruction, block, and function entity. |
| Multiple observation positions | Compare native, emulated, VM, VMI, replay, bare-metal, hardware-trace, and external-memory evidence when required. |
| Fidelity is measurable | Treat environment sensitivity and observation interference as data, not as an informal analyst caveat. |
| Least privilege and default deny | The planner never has unrestricted shell, network, credentials, hypervisor, or bare-metal access. |
| Sidecars contain risk | Wrap incompatible licenses, large runtimes, vulnerable parsers, and unstable projects behind process or VM boundaries. |
| Deterministic interfaces | Coding agents receive compact JSON, stable schemas, pagination, explicit budgets, and resumable jobs. |
| Progressive qualification | Every backend must pass correctness, provenance, performance, crash isolation, and license gates before production use. |


# 3. Consolidated system architecture

![Consolidated architecture](/mnt/data/re_plan_assets/architecture.png){ width=7.1in }

## 3.1 Trusted control plane

The trusted control plane contains no target code execution. It hosts:

- API gateway, authentication, tenancy, authorization, quotas, and audit.
- Query interpreter and required-fact compiler.
- Evidence-aware planner and deterministic action compiler.
- Policy engine and OPSEC/Fidelity Manager.
- Worker scheduler, artifact broker, and experiment registry.
- Program Knowledge System and conclusion publisher.
- LLM adapters with secret isolation and prompt/data minimization.

The LLM proposes interpretations and plans through typed schemas. It does not receive direct hypervisor, host shell, production-network, database-admin, or bare-metal management credentials.

## 3.2 Untrusted analysis plane

Every parser, decompiler, emulator, dynamic tracer, target process, guest OS, and plugin is potentially exploitable. Workers therefore run with:

- Read-only or content-addressed inputs.
- Per-job identities and short-lived credentials.
- Resource limits, timeouts, syscall/container/VM isolation as appropriate.
- Default-deny network and explicit artifact egress.
- No controller/LLM/API secrets.
- Immutable tool/image digests and signed result manifests.
- Disposable storage and post-job destruction or reimage.

## 3.3 Storage plane

Use three coordinated storage forms:

1. **PostgreSQL** for project metadata, entity/edge tables, evidence, hypotheses, conclusions, audit logs, jobs, policies, and recursive graph queries.
2. **Content-addressed object storage** for binaries, dumps, snapshots, packet captures, decompiler exports, solver models, and other immutable artifacts.
3. **Parquet/Arrow trace chunks** for high-volume event data, with DuckDB or server-side analytical workers for slices and aggregations.

Vector retrieval is secondary. It helps retrieve semantically similar function summaries, prior experiments, or analyst notes, but it cannot replace exact graph and provenance queries.

## 3.4 TargetSystem replaces the single-binary model

A project contains one or more TargetSystems. A TargetSystem contains related artifacts, executions, environments, process trees, drivers, IPC, kernel objects, network flows, and evidence. This is necessary for targets such as a game plus kernel anti-cheat:

![Multi-process and kernel TargetSystem](/mnt/data/re_plan_assets/target_system.png){ width=7.1in }

The same model supports malware with injectors/children, an EDR with sensors/services/drivers/cloud communication, a browser with sandboxes, or an installer with boot-time components.

## 3.5 Static/runtime identity bridge

All runtime addresses must normalize through the following chain:

```text
artifact SHA-256
  -> module identity and build metadata
  -> module instance and load lifetime
  -> section + RVA
  -> instruction / basic block / function entity
  -> backend-native IR and CoreIR source map
```

ASLR, relocation, rebasing, unpacking, self-modification, and overlay/JIT code require time-scoped mappings. When executable bytes change, the platform creates a new code-version or derived-artifact identity rather than pretending the static artifact is unchanged.

# 4. Recommended minimal stack

The stack below is intentionally coherent rather than exhaustive. Alternatives remain behind interfaces and are added only when a benchmark or target class justifies them.

| Layer | Recommendation | Disposition |
| --- | --- | --- |
| Core language/build | C++20 core, narrow C ABI for plugins, CMake, vcpkg/Conan or locked manifests | Build |
| Service/API | Protocol Buffers + gRPC; JSON projection; MCP adapter | Adopt |
| Binary loading | [LIEF](https://github.com/lief-project/LIEF) | Adopt in core |
| Instruction decoding | [Zydis](https://github.com/zyantific/zydis) for x86/x86-64; [Capstone](https://github.com/capstone-engine/capstone) for ARM/AArch64 and cross-checking | Adopt |
| Canonical IR | CoreIR schema owned by the project; adapters for XAIR, Ghidra p-code, Triton AST, and angr/VEX | Build |
| CFG/SSA | Native pipeline or XAIR/XAIR_CFG after license and qualification gate | Conditional |
| Decompiler | [Ghidra](https://github.com/NationalSecurityAgency/ghidra) headless sidecar with structured export | Adopt as worker |
| Primary evidence store | [PostgreSQL](https://www.postgresql.org/) + content-addressed blob/object store | Adopt |
| Trace store/analytics | [Apache Arrow](https://arrow.apache.org/) + Parquet + [DuckDB](https://duckdb.org/) | Adopt |
| Vector retrieval | [pgvector](https://github.com/pgvector/pgvector), secondary only | Optional |
| Native user-space tracing | [DynamoRIO](https://github.com/DynamoRIO/dynamorio) | Adopt as primary backend |
| Linux replay | [rr](https://github.com/rr-debugger/rr) | Adopt as sidecar |
| Whole-system/replay | [PANDA](https://github.com/panda-re/panda) / QEMU worker | Adopt as isolated backend |
| Symbolic solving | [Z3](https://github.com/Z3Prover/z3); optional [Bitwuzla](https://github.com/bitwuzla/bitwuzla) | Adopt |
| Dynamic symbolic/taint | [Triton](https://github.com/JonathanSalwan/Triton); XAIR_SYM conditional | Adopt + conditional |
| Rules/capabilities | [YARA-X](https://github.com/VirusTotal/yara-x); [capa](https://github.com/mandiant/capa); [FLOSS](https://github.com/mandiant/flare-floss) | Core C API + sidecars |
| Windows runtime recovery | [PE-sieve](https://github.com/hasherezade/pe-sieve) | Worker/library after qualification |
| Controlled networking | [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng); tap-based capture; tshark/Zeek sidecars | Adopt |
| VMI | [LibVMI](https://github.com/libvmi/libvmi) service; [DRAKVUF](https://github.com/tklengyel/drakvuf) research pilot | Pilot |
| Hardware trace | [Intel libipt](https://github.com/intel/libipt) for Intel PT decoding; future architecture adapters | Phase 6 |
| External memory | [LeechCore](https://github.com/ufrisk/LeechCore) / [MemProcFS](https://github.com/ufrisk/MemProcFS) isolated service with license review | Optional Phase 6 |
| GUI | Qt 6 Widgets/model-view; Graphviz or custom layout; Dear ImGui for internal diagnostics only | Adopt |
| Worker orchestration | PostgreSQL-backed queue first; NATS JetStream when distributed scale requires it | Build then adopt |
| Virtualization control | [libvirt](https://libvirt.org/) for QEMU/KVM and selected Xen integration; bare-metal control adapter | Adopt/build |


## 4.1 Build-versus-integrate decision matrix
| Capability | Decision | Rationale |
| --- | --- | --- |
| TargetSystem/evidence schema | Build | This is the product differentiator and must remain independent of backend representations. |
| Planner, action compiler, policy engine | Build | Backends do not provide evidence-aware, risk-aware autonomous planning. |
| Canonical CoreIR and identity model | Build thin schema | Own stable interchange and provenance; do not reimplement every decoder/lifter. |
| Disassembly and loading | Integrate | Use LIEF, Zydis, Capstone and validate against multiple backends. |
| Decompilation | Integrate as worker | Ghidra offers mature analysis; a forked decompiler core creates substantial maintenance cost. |
| Native tracing | Integrate | DynamoRIO provides mature DBI and offline trace infrastructure. |
| Emulation and replay | Integrate as isolated services | QEMU/PANDA/Unicorn/Qiling contain deep architecture work and license constraints. |
| Symbolic solver | Integrate | Use Z3/Bitwuzla; build domain-specific state, models, slicing, and orchestration. |
| Taint engine | Integrate plus project-specific graph | Use Triton/PANDA/XAIR_SYM selectively; normalize flows into evidence. |
| Unpacking/runtime artifacts | Integrate detectors and dumpers; build reinjection pipeline | Artifact lifecycle and validation are differentiators. |
| VMI | Integrate/pilot | LibVMI/DRAKVUF provide foundations, but current-OS support and fidelity require project engineering. |
| Bare-metal laboratory | Build control plane; integrate BMC/PXE imaging | No existing RE framework supplies the complete safe experiment lifecycle. |
| Hardware trace | Integrate decoders; build correlation | Use vendor/open decoders and own module/RVA/IR mapping. |
| External memory/DMA | Optional integration | Useful for snapshots and validation, not a universal tracing or transparency solution. |
| GUI and agent surface | Build | Shared state, evidence navigation, action budgets, and provenance are core UX. |


## 4.2 XAIR and AIRECE decision

The XAIR family aligns closely with the project because it is C-native and explicitly represents typed SSA values, memory, control flow, flags, effects, and source provenance. XAIR_CFG adds function/CFG recovery over PE/ELF x86/x86-64, and XAIR_SYM adds Z3-backed symbolic execution and taint over frozen XAIR modules and CFGs. That combination could shorten the initial static-analysis and symbolic pipeline.

It should nevertheless pass four gates before becoming the canonical implementation:

1. **License gate.** The repositories now expose license-related files, but the exact primary and per-file terms must be retrieved, archived, and approved. No assumption should be made from repository visibility alone.
2. **Correctness gate.** Differential tests against Ghidra, Capstone/Zydis, angr, compiler ground truth, and hand-labeled corpora must quantify decoder, CFG, SSA, memory, flag, and calling-convention correctness.
3. **Maturity gate.** The projects are small and early. The product needs fuzzing, stable serialization, ABI/versioning policy, thread-safety, malformed-input handling, and long-running performance tests.
4. **Architecture gate.** The long-term target includes ARM/AArch64. The database and agent API must not expose x86-specific XAIR assumptions as permanent product schema.

AIRECE is useful as a product-design reference for an agent-oriented reversing context engine, command vocabulary, summaries, references, slices, paths, and protocol stability. Its repository LICENSE states "all rights reserved" at this research snapshot. Therefore the plan assumes no code reuse, linking, redistribution, or derivative implementation from AIRECE without a separate written license from the author.

## 4.3 Ghidra decompiler strategy

Do not begin by extracting and forking Ghidra's native decompiler core into the main process. That route creates build, RPC, state-management, security-patching, architecture-definition, and upstream-sync costs before the product has validated its own schemas.

Instead, create a **Ghidra Analysis Worker**:

- Import a content-addressed artifact into a disposable Ghidra project.
- Run pinned headless analyzers under CPU, memory, and time limits.
- Invoke the decompiler through the supported Java-side interfaces that communicate with the native decompiler process.
- Export structured function data: entry/RVA, blocks, p-code, pseudocode, calls, references, variables, types, source-address mapping, warnings, and analysis options.
- Store the original export artifact and normalize selected fields into the Program Knowledge System.
- Pin a patched supported Ghidra release and rebuild worker images after advisories.

Later, if process startup or throughput becomes a proven bottleneck, evaluate a long-lived worker pool or a separately maintained native decompiler service. That decision should be benchmark driven.

# 5. Program Knowledge and Evidence System

## 5.1 Entity model
| Entity | Purpose |
| --- | --- |
| Project | Tenant/workspace, authorization scope, policies, users, budgets, audit records. |
| TargetSystem | The complete program ecosystem being analyzed, not merely one file. |
| Artifact | Original or derived content-addressed binary, memory image, packet capture, trace, dump, or configuration. |
| StaticEntity | Instruction, basic block, function, variable, type, string, import, class, vtable, data object. |
| ExecutionEnvironment | VM/emulator/physical profile, hardware/OS properties, network policy, observer set, image digest. |
| ExecutionRun | One immutable execution with experiment manifest, timestamps, inputs, outputs, and fidelity assessment. |
| ProcessInstance / ThreadInstance | Runtime identities linked to executable artifact and parent/child topology. |
| ModuleInstance | Loaded artifact plus base address, lifetime, relocation state, and module/RVA resolver. |
| KernelModuleInstance | Driver/module load identity and relationship to devices, callbacks, dispatch paths, and objects. |
| IPCChannel | Pipe, shared memory, ALPC/RPC, socket, event, mutex, queue, or other inter-component path. |
| UserKernelInteraction | User call site, transition type, driver entry, request/response buffers, timestamps, and evidence. |
| NetworkFlow / ProtocolMessage | Flow, stream, packet/message boundaries, fields, parse hypotheses, and code correlation. |
| Observation | Raw or normalized event tied to an observer, run, environment, and source artifact. |
| EvidenceRecord | Claim-supporting unit with provenance, confidence, scope, contradictions, and reproducibility links. |
| Hypothesis | Proposed explanation with required facts, predictions, tests, status, and alternatives. |
| Conclusion | Answer fragment that cites evidence, states uncertainty, and records the planner path. |
| EnvironmentSensitiveDecision | A branch/state transition whose outcome differs across observation environments. |


## 5.2 Evidence record

A minimal EvidenceRecord should contain:

```json
{
  "evidence_id": "ev_01J...",
  "project_id": "prj_...",
  "target_system_id": "ts_...",
  "claim_type": "DYNAMICALLY_OBSERVED",
  "subject_ids": ["fn_sha256:rva", "run_..."],
  "predicate": "writes_buffer",
  "object_ids": ["memobj_..."],
  "observation_context_id": "obsctx_...",
  "source_artifact_ids": ["trace_chunk_..."],
  "producer": {
    "backend": "dynamorio",
    "version": "pinned-digest",
    "configuration_digest": "sha256:..."
  },
  "confidence": 0.93,
  "assumptions": [],
  "limitations": ["selected memory ranges only"],
  "contradicts": [],
  "experiment_id": "exp_...",
  "created_at": "..."
}
```

Confidence is not a free-form LLM score. It is computed from evidence class, backend qualification, source completeness, cross-backend agreement, environment-fidelity penalties, validation results, and known limitations. The raw factors must remain inspectable.

## 5.3 Claim classification
| Class | Meaning |
| --- | --- |
| Directly observed | Raw trace, packet, memory value, kernel event, or replay event with a trustworthy capture chain. |
| Statically derived | Result of parsing, disassembly, lifting, CFG, dataflow, signature, or decompilation. |
| Dynamically observed | Observed during execution; qualified by observer and environment. |
| Symbolically established | Constraint result with solver/version, model, assumptions, and resource bounds. |
| Experimentally validated | Prediction tested through a versioned, reproducible experiment. |
| AI-inferred | Reasoned interpretation not independently established. |
| Uncertain | Insufficient or low-quality evidence. |
| Contradicted | Evidence exists for mutually incompatible interpretations or behaviors. |


## 5.4 Contradictions and evidence scopes

Evidence may be true only for a specific build, run, thread, environment, input, account state, network response, or code version. Every query therefore evaluates scope compatibility. Two observations are contradictory only when their scopes overlap sufficiently. Otherwise they may represent environment-sensitive or input-sensitive behavior.

The system must preserve negative evidence carefully. "Function not executed in run X" means only that the trace and observer were capable of seeing it and did not observe it in that run; it does not prove the function is unreachable.

## 5.5 Graph implementation

Start with relational entity and edge tables in PostgreSQL:

```text
entity(id, type, project_id, target_system_id, attributes_jsonb, version)
edge(id, src_id, predicate, dst_id, scope_jsonb, confidence, evidence_id)
evidence(...)
```

Use indexed materialized views for call graphs, module/RVA maps, process trees, IPC, and user-kernel transitions. Recursive SQL is sufficient for the MVP. A separate graph database should be considered only if measured workloads cannot meet latency/scale targets.

# 6. Canonical IR and static analysis

## 6.1 CoreIR role

CoreIR is a stable interchange and evidence-addressing layer, not an attempt to replace every backend-native IR. It should model the semantics needed by shared analyses:

- Typed values, constants, registers, flags, and memory spaces.
- SSA-like def/use relationships and block parameters or phi semantics.
- Explicit loads/stores, calls, returns, branches, exceptions, and side effects.
- Address/source provenance and mapping to machine bytes.
- Architecture, width, endianness, address space, and calling convention.
- Unknown/undefined/poison semantics and confidence.
- Extension points for vector, floating-point, system, and architecture-specific operations.

Keep Ghidra p-code, VEX, Triton ASTs, and any XAIR module as immutable backend artifacts. Convert only the portions required for shared queries. Lossy conversions must declare what was discarded.

## 6.2 Static pipeline

```text
artifact ingest
  -> hash/type/format/architecture
  -> LIEF loader and normalized memory image
  -> decoder (Zydis or Capstone)
  -> seeds: entry, exports, symbols, unwind, relocations, imports, direct calls
  -> CFG/function recovery
  -> lifting and SSA/dataflow
  -> signatures, strings, types, classes, capabilities
  -> Ghidra decompiler worker
  -> normalized evidence + immutable backend exports
```

## 6.3 Static confidence

Function and CFG recovery should be explicitly probabilistic. Record seed type, decoding conflicts, overlapping regions, indirect-target evidence, exception/unwind metadata, executable-data ambiguity, and dynamic validation. The user and planner should be able to request conservative, balanced, or aggressive discovery profiles.

## 6.4 Static malware and semantic enrichment

YARA-X, capa, FLOSS, library signatures, compiler/runtime detection, BSim, and TLSH provide hints and prioritization. They must not be converted directly into high-confidence semantic conclusions. A capa capability or YARA match should cite the matched features/rule and remain distinguishable from direct behavior.

# 7. AI controller, planner, and action model

## 7.1 Controller decomposition

Separate the "AI controller" into deterministic and probabilistic components:

- **Question interpreter:** extracts target, scope, desired certainty, constraints, and output format.
- **Fact compiler:** converts the question into typed facts such as `encryption_boundary`, `driver_request_schema`, `parser_function`, or `branch_condition`.
- **Evidence resolver:** queries exact graph/provenance data before semantic retrieval.
- **Planner:** selects candidate action DAGs using backend capability, cost, fidelity, and risk models.
- **Policy engine:** blocks or requires authorization for forbidden actions.
- **Executor:** dispatches typed jobs; it does not allow arbitrary LLM-generated shell.
- **Validator:** verifies result schemas, evidence completeness, address mapping, and contradictions.
- **Answer composer:** cites evidence, confidence, assumptions, contradictions, and remaining unknowns.

## 7.2 High-level action vocabulary
| Action | Discipline | Output |
| --- | --- | --- |
| inspect_artifact | Static | Load metadata and initial indicators. |
| analyze_function | Static | Recover CFG, IR, types, callers/callees, and decompiler output. |
| find_callers / find_references | Static | Traverse normalized graph with confidence filters. |
| follow_dataflow | Static/dynamic | Create forward/backward slices across variables, memory, calls, IPC, and network. |
| trace_function | Dynamic | Capture entry/exit, arguments, return values, selected memory, and coverage. |
| trace_syscalls / trace_apis | Dynamic | Collect OS interactions and map them to process/thread/module context. |
| trace_memory | Dynamic/replay | Observe bounded ranges/objects and relevant reads/writes. |
| capture_generated_code | Dynamic | Detect executable writes/transitions, dump, reconstruct, and re-ingest. |
| follow_taint | Taint | Track selected sources to sinks under an explicit policy. |
| solve_branch | Symbolic | Build a small slice and solve a branch or target reachability question. |
| compare_executions | Differential | Align runs and identify first meaningful semantic divergence. |
| replay_execution | Replay | Seek to an event/state and execute additional analysis offline. |
| test_hypothesis | Experiment | Generate a controlled change and evaluate predicted observations. |
| escalate_observation | OPSEC/fidelity | Select a different observer/environment after evidence of interference. |
| assess_fidelity | OPSEC/fidelity | Compute confidence penalties and identify environment-sensitive decisions. |
| request_authorization | Policy | Pause externally visible or irreversible work pending explicit authorization. |


## 7.3 Action contract

Every action contains:

```json
{
  "action_id": "act_...",
  "type": "trace_function",
  "inputs": {
    "function_id": "fn_...",
    "run_template_id": "rt_...",
    "capture": ["arguments", "return", "selected_memory"]
  },
  "requirements": {
    "user_visibility": true,
    "kernel_visibility": false,
    "record_replay": false,
    "max_observer_footprint": "HIGH",
    "minimum_fidelity": 0.60
  },
  "budgets": {
    "wall_seconds": 120,
    "events": 5000000,
    "artifact_bytes": 1073741824
  },
  "policy_context": "policy_...",
  "success_criteria": ["entry_and_exit_observed"],
  "fallbacks": ["replay_execution", "escalate_observation"]
}
```

The scheduler resolves this request to a backend. The planner does not encode tool-specific command lines.

## 7.4 Plan termination

The planner stops when one of the following is true:

- Required facts are supported above the requested confidence threshold.
- Remaining actions exceed cost, time, or resource budgets.
- Policy blocks the needed experiment.
- Available backends cannot supply representative evidence.
- Results remain contradictory after the allowed validation plan.
- Expected information gain falls below a configured threshold.

The answer then states the limiting condition and the evidence that led to it.

# 8. Dynamic analysis and replay

## 8.1 Native user-space tracing

DynamoRIO should be the primary native DBI backend for function, block, selected instruction, memory, API, syscall-adjacent, and coverage profiles. It should run through a project-owned client that emits the common event schema and supports:

- Process-tree and module-lifetime tracking.
- Stable thread and module-instance IDs.
- Function entry/exit and calling-convention-aware argument capture.
- Selected memory object/range reads and writes.
- Exception/signal events and code-cache diagnostics.
- Offline trace modes for expensive post-processing.
- Targeted instrumentation plans to avoid continuous whole-program instruction tracing.

QBDI and Frida remain useful alternatives for bounded instrumentation, platform gaps, rapid prototyping, and analyst-driven interaction. They should not be conflated with low-observer-footprint backends.

## 8.2 OS-native observation

Use ETW/WPP and debugger interfaces on Windows, and ptrace/perf/eBPF/audit where suitable on Linux, as separate observers. An OS-native event can corroborate or disagree with DBI. The event record must state whether it came from user hooks, kernel telemetry, hypervisor observation, packet capture, or hardware trace.

## 8.3 Record/replay

Record/replay is a force multiplier for autonomous analysis because the controller can run progressively heavier analyses over the same execution. Use rr for Linux user-space process trees and PANDA/QEMU for selected whole-system experiments.

The system should index:

- Process/thread/module lifecycle.
- Basic-block/function coverage where available.
- Syscalls/APIs and network/IPC events.
- Snapshot/checkpoint locations.
- Interesting writes, executable-page transitions, crashes, and first divergences.

Replays must be tagged with determinism quality. A replay that cannot reproduce a target event should not silently substitute for the original run.

## 8.4 Runtime artifact recovery

Monitor executable-memory creation, write-then-execute transitions, module reflection/manual mapping, process injection, child processes, decrypted regions, runtime strings, and configuration buffers. When captured content is stable enough:

1. Create a content-addressed DerivedArtifact.
2. Record originating process, mapping, bytes, permissions, timestamps, and capture method.
3. Reconstruct PE/ELF metadata where possible without overwriting raw bytes.
4. Re-ingest through static analysis.
5. Link static entities back to runtime code-version intervals.
6. Validate reconstructed entry points/imports/relocations against execution evidence.

# 9. Symbolic execution, taint, deobfuscation, and devirtualization

## 9.1 Targeted symbolic strategy

Symbolic analysis is invoked only after narrowing from static/dynamic evidence. Typical pipeline:

```text
interesting decision or sink
  -> backward slice
  -> concrete state seed from run/replay
  -> small IR region and explicit assumptions
  -> bounded symbolic execution
  -> witness, unsat result, or resource-limit outcome
  -> dynamic validation when feasible
```

Z3 is the default solver; Bitwuzla can be used for cross-checking selected bit-vector problems. Triton supplies dynamic symbolic and taint capabilities. XAIR_SYM could provide a tightly integrated static symbolic path if its license and qualification gates pass. angr is valuable as an alternate implementation and research oracle.

## 9.2 Taint/dataflow

Sources and sinks are policies, not hard-coded tool features. Sources may be file bytes, packets, user input, registry data, device responses, kernel request buffers, or decoded strings. Sinks may be branch conditions, crypto APIs, network sends, file writes, code generation, driver dispatch, or comparison routines.

Cross-process or user-kernel propagation requires explicit bridge evidence, such as a copied buffer, shared-memory region, IPC message, IOCTL request, or packet. The system should not claim cross-boundary taint solely because timestamps and sizes are similar.

## 9.3 Deobfuscation

Build a transformation framework over backend IR/CoreIR with proof obligations:

- Constant propagation and expression simplification.
- Dead-code and unreachable-edge removal.
- Opaque-predicate hypotheses.
- Dispatcher/control-flow-flattening recovery.
- Bogus-control-flow and exception-flow normalization.
- String/API-hash resolution.
- Runtime constant and decrypted code/data substitution.

Every transformation produces a new derived representation, a transformation log, assumptions, and validation status. Preserve the original bytes and CFG.

## 9.4 Custom virtual machines

Treat devirtualization as a research pipeline:

1. Identify interpreter/dispatcher candidates through loops, indirect branches, handler tables, and dynamic coverage.
2. Cluster handler behaviors using traces and semantics.
3. Recover virtual state objects and bytecode streams.
4. Propose virtual instruction semantics.
5. Lift to an extension of CoreIR or a dedicated VM IR.
6. Reconstruct a VM CFG.
7. Differentially validate lifted semantics against concrete execution.

The platform should support analyst-provided handler annotations and partial results. Fully automatic novel VM recovery should not be an MVP acceptance criterion.

# 10. Multi-process and kernel-space analysis

## 10.1 System topology

A broad initial run should collect process creation/termination, parentage, threads, modules, services, drivers, files, registry/configuration, IPC, network flows, memory mappings, exceptions, and relevant kernel objects. This creates a live system map before expensive tracing.

## 10.2 UserKernelInteraction

A first-class interaction record should include:

```text
run + environment
user process/thread/module/RVA/call site
transition mechanism (syscall, IOCTL, shared section, callback, etc.)
kernel module/dispatch or observed entry
request and response object identities
buffer snapshots/hashes and interpreted fields
return/status values
time interval and causal confidence
supporting evidence and observer limitations
```

Static driver analysis should recover initialization, devices/interfaces, dispatch tables, callbacks, imports, strings, and request-handling candidates. Runtime evidence then relates those entities to actual requests and outcomes.

## 10.3 Kernel support sequencing

- Begin with synthetic, intentionally instrumented drivers/modules and open test targets.
- Add Windows driver and Linux kernel-module loaders, symbols, type metadata, and OS profile handling.
- Add whole-system and VMI observation only against a versioned support matrix.
- Treat undocumented kernel structures as version-scoped hypotheses unless validated by symbols or multiple observations.
- Keep current commercial anti-cheat/EDR coverage as a research program, not a blanket supported-target claim.

# 11. OPSEC and observation fidelity

## 11.1 OPSEC/Fidelity Manager

The OPSEC/Fidelity Manager sits between plan generation and execution. It evaluates:

- Target risk and possible destructive/persistent behavior.
- Required user/kernel/network/hardware visibility.
- Observer footprint and likely timing distortion.
- Environment identity, credentials, account value, hardware value, and network reputation.
- Whether the target may report the experiment remotely.
- Reversibility and external side effects.
- Available baseline, replay, VMI, physical, or hardware-trace alternatives.

Its objective is **containment, asset protection, and representative evidence**. It does not certify invisibility.

## 11.2 Action risk classes
| Risk class | Examples | Default control |
| --- | --- | --- |
| R0 - Passive | Static parsing, search, offline trace analytics | Automatic |
| R1 - Contained reversible | Emulation or disposable VM with simulated network and no valuable identity | Automatic within quota |
| R2 - Elevated contained | Kernel driver execution, VMI, high-resource replay, destructive guest behavior | Policy pre-approval; automatic execution |
| R3 - Identity or external exposure | Real account, external service, stable hardware identity, unrestricted egress | Explicit per-experiment authorization |
| R4 - Irreversible/high impact | Potential blacklisting, legal/service impact, production systems, destructive physical side effects | Human-controlled procedure outside autonomous default |


## 11.3 Asset exposure model
| Field | Interpretation |
| --- | --- |
| identity_value | Value and linkability of user, organization, tenant, device, certificate, account, or machine identity. |
| credential_value | Secrets present or potentially accessible in the environment. |
| hardware_value | Replacement cost and uniqueness of hardware identifiers. |
| network_reputation_value | Risk attached to public IP ranges, domains, tenants, certificates, and service reputation. |
| account_value | Financial, social, licensing, or access value of any service account. |
| persistence_risk | Probability and impact of target persistence beyond the experiment. |
| destructive_risk | Probability and impact of deletion, encryption, firmware modification, or service disruption. |
| remote_reporting_risk | Probability that the target reports environment identity or analyst activity externally. |


An environment profile declares maximum acceptable target risk. A plan may only schedule a target into an environment whose exposure limits dominate the experiment risk. For example, a guest with no credentials, a simulated network, and disposable virtual identity may accept high malware risk; a physical node connected to a real external service may require a separately authorized procedure.

## 11.4 Hardened VM definition

A hardened analysis VM is:

- Reproducible from a signed, versioned image.
- Disposable and restorable to a known state.
- Free of analyst, corporate, cloud, LLM, source-control, browser, certificate, and personal credentials.
- Network-isolated by default, with externally enforced policy.
- Instrumented through a documented profile whose guest-visible artifacts are known.
- Monitored and controlled from a separate management plane.
- Supplied with only the target inputs and test identities approved for that experiment.

It is not guaranteed to be indistinguishable from physical hardware. Attempts to conceal every virtualization artifact are fragile, target specific, and can obscure the more important question: whether the observed behavior is representative.

## 11.5 Observation ladder

![Observation escalation ladder](/mnt/data/re_plan_assets/observation_ladder.png){ width=5.8in }

The planner escalates only when the required fact cannot be obtained at a lower-risk tier or when evidence indicates observer/environment interference.

## 11.6 ObservationContext and fidelity score

Every runtime observation references an ObservationContext containing:

- Environment profile and image digest.
- Hardware/virtual hardware descriptors.
- Guest OS/build and kernel symbol/profile state.
- Enabled observers, versions, placement, and configuration.
- Network mode and external connectivity.
- Time source, clock controls, and expected timing distortion.
- Accounts/identities and exposure classification.
- Known limitations and attestation results.

An EnvironmentFidelityScore is a structured assessment, not a claim of truth. Factors include baseline similarity, number and severity of environment-sensitive divergences, observer coverage, trace loss, OS-profile confidence, timing perturbation, and cross-backend agreement. Downstream conclusions inherit fidelity penalties.

## 11.7 Environment-divergence analysis

For high-risk targets, compare normalized executions across environments:

```text
Run A: low-instrumentation baseline or approved physical baseline
Run B: native DBI/debug observation
Run C: whole-system VM/emulation
Run D: VMI or alternate hypervisor profile
```

Align module/RVA coverage, calls, syscalls/APIs, IPC, request buffers, network messages, and selected state. Identify the **first meaningful divergence**, not merely every timestamp difference. Create an EnvironmentSensitiveDecision entity that records the branch/state, the environments, the observed outcomes, and the evidence.

If downstream behavior no longer represents the baseline, the planner should exclude or weaken that evidence, request another observation tier, or state that the target cannot be represented under available environments.

## 11.8 VMI

VMI lowers guest-side instrumentation footprint and can observe kernel and user activity from the hypervisor. It does not make virtualization disappear. LibVMI should be wrapped as a service with an explicit backend/OS support matrix. DRAKVUF is useful for architecture and selected lab targets, but upstream OS-version support and Xen requirements mean it should be a pilot rather than the sole modern-Windows strategy.

## 11.9 Controlled bare-metal workers

A bare-metal environment is a managed worker, not an analyst workstation. The lifecycle is:

```text
allocate replaceable lab node
  -> out-of-band power and network isolation
  -> provision signed known-clean image
  -> attest expected firmware/boot/OS state
  -> inject target and approved test material
  -> run bounded experiment
  -> collect through external/control channels
  -> power cycle, quarantine if needed, and reimage
```

Management uses a separate network and per-job credentials. No personal or production identities reside on the node. Nodes should be disposable in an operational sense, with a quarantine/retirement path for suspected firmware or persistent compromise.

## 11.10 Hardware-assisted trace

Add `IHardwareTraceBackend`. The first implementation can use Intel Processor Trace decoded with libipt. Later adapters can support other architecture mechanisms where hardware and OS support are available.

Hardware trace is valuable for lower-software-footprint control-flow evidence. It does not inherently provide complete arguments, memory dependencies, object types, decrypted data, or causal semantics. The platform must expose trace gaps, synchronization quality, context-switch attribution, module mapping, and packet loss.

## 11.11 External memory and DMA observation

Add `IExternalMemoryObserver` as an optional specialized backend. LeechCore/MemProcFS or other acquisition mechanisms can provide snapshots and memory-forensic views. The system should treat them as **point-in-time observations**, not as stealth debuggers or complete execution histories.

Limitations include incomplete event ordering, multi-core coherence, missing register history, IOMMU/platform restrictions, topology changes introduced by acquisition hardware, and the possibility that the target observes attached devices or altered platform state. These limitations must be part of ObservationContext and evidence confidence.

The highest-fidelity tier may combine processor trace, externally enforced network capture, selected memory snapshots, and static IR correlation. Each data source still retains its own provenance and uncertainty.

## 11.12 Network OPSEC

Default network modes are:

1. **No network.** Safest initial execution.
2. **Simulated network.** FakeNet-NG or laboratory services reproduce DNS/HTTP/TLS-adjacent/application behavior without external contact.
3. **Recorded/replayed network.** Deterministic responses based on authorized captures or test fixtures.
4. **Restricted laboratory egress.** Destination allowlists, bandwidth/time limits, external capture, disposable identities, and explicit approval.
5. **Unrestricted/production contact.** Outside the autonomous default and generally prohibited.

The AI cannot authorize a higher network mode. Enforcement occurs below the guest and outside the model.

# 12. Networking and protocol reconstruction

Treat connections, streams, messages, buffers, crypto boundaries, parser functions, state machines, and network experiments as first-class entities.

The network pipeline should:

- Capture outside the guest where practical.
- Reassemble streams and normalize timestamps with process/kernel evidence.
- Use tshark/Wireshark dissectors and Zeek as sidecars.
- Store protocol field hypotheses with offsets, widths, endianness, confidence, and message examples.
- Correlate send/receive buffers to user-space functions and, when possible, to decryption/encryption boundaries through taint or memory watches.
- Generate Kaitai Struct specifications only after field hypotheses are validated; track the license of imported `.ksy` specifications separately.
- Use controlled response mutation to test state-machine and field semantics under policy.

# 13. GUI architecture

## 13.1 Recommended framework

Use Qt 6 Widgets and model/view for the production desktop application. Prefer dynamic linking under a reviewed LGPL-compliance process or purchase a commercial license. Audit module-level licenses; do not assume every Qt add-on has identical terms. Dear ImGui can support internal diagnostics and backend-development panels but should not define the production UX.

## 13.2 Shared project model

The GUI is a client of the same gRPC/domain API as the CLI. It does not maintain a separate project database. Long-running analysis runs server-side and streams progress/evidence updates.

## 13.3 Primary workspaces

- **Code:** disassembly, decompiled code, CoreIR/backend IR, variables, types, cross-references.
- **Graphs:** CFG, call graph, evidence graph, process/kernel topology, IPC and protocol state machines.
- **Runtime:** timeline, processes/threads/modules, memory mappings, exceptions, coverage, selected trace slices.
- **Kernel:** modules, devices, dispatch/callback paths, user-kernel interactions, kernel objects.
- **Network:** flows, streams, messages, field hypotheses, code/buffer correlation.
- **Artifacts:** originals, dumps, generated code, decrypted content, snapshots, captures, similarity groups.
- **Investigation:** natural-language chat, fact requirements, current plan, hypotheses, conflicts, confidence, pending approvals.
- **OPSEC:** environment, observer context, network mode, exposure score, fidelity assessment, escalation history.

## 13.4 Evidence-first interaction

Every AI statement should be selectable. Selecting it reveals evidence IDs, source locations, run/environment, backend/version, assumptions, conflicts, and reproducing action. Analysts can promote, reject, annotate, or supersede conclusions without deleting the underlying evidence.

## 13.5 Large-data rendering

Do not render million-node graphs or full traces in the GUI. Use server-side filtering, progressive disclosure, semantic zoom, virtualized tables, trace windows, graph neighborhoods, and summaries. Graphviz can provide offline/static layouts; interactive large graphs need a custom scene/tiling strategy.

# 14. Agent-native CLI, API, and MCP surface

## 14.1 CLI principles

- Machine-readable JSON is the default for automation; human-readable output is optional.
- Commands are idempotent or create explicit immutable jobs.
- Every long-running action returns a job ID and supports status, events, cancellation, and result pagination.
- Evidence and entity IDs are stable and reusable across calls.
- Errors distinguish invalid input, unsupported target, policy denial, budget exhaustion, backend failure, and insufficient evidence.
- No ANSI decoration in JSON mode; deterministic ordering where practical.

## 14.2 Proposed command surface

```bash
revtool project create --name sample
revtool target add sample ./launcher.exe ./game.exe ./anticheat.sys
revtool analyze sample --profile static-balanced --format json

revtool ask sample   --question "Where is the configuration decrypted?"   --confidence high   --budget standard   --format json

revtool trace sample --function fn_...   --capture arguments,return,selected-memory   --environment vm-win-lab-v3

revtool compare sample --runs run_A,run_B   --align module-rva,api,ipc,network   --first-divergence

revtool evidence show ev_... --include-provenance
revtool experiment approve exp_... --authorization-token-file ...
revtool export sample --bundle reproducible-investigation
```

## 14.3 Ask response

```json
{
  "answer_id": "ans_...",
  "status": "SUPPORTED_WITH_LIMITATIONS",
  "answer": "...",
  "claims": [
    {
      "text": "...",
      "confidence": 0.91,
      "evidence_ids": ["ev_1", "ev_2"],
      "limitations": ["physical baseline unavailable"]
    }
  ],
  "actions_executed": ["act_..."],
  "pending_actions": [],
  "contradictions": [],
  "environment_fidelity": 0.74,
  "reproducibility_bundle_id": "bundle_..."
}
```

## 14.4 MCP adapter

Expose a small stable set of high-level tools rather than every backend command:

- `re_project_open`
- `re_target_ingest`
- `re_ask`
- `re_entity_get`
- `re_graph_query`
- `re_action_run`
- `re_job_status`
- `re_evidence_get`
- `re_experiment_compare`
- `re_artifact_export`

Use MCP resources for read-only paged artifacts/evidence and tools for explicit actions. The MCP layer delegates to gRPC/domain services so it can evolve without duplicating analysis logic.

# 15. Plugin and worker architecture

## 15.1 In-process versus out-of-process

Only small, qualified, permissively licensed, memory-safe-or-heavily-fuzzed components should be considered for the core process. Default to an out-of-process worker for:

- GPL/AGPL/custom licensed projects.
- Java/Python/Rust ecosystems that would complicate core distribution.
- Parsers/decompilers that consume hostile input.
- Hypervisor/privileged backends.
- Experimental or fast-changing research code.
- Tools that produce large files or may hang/crash.

## 15.2 Backend interfaces
| Interface | Responsibility |
| --- | --- |
| IArtifactLoader | Parse format/segments/imports/exports/debug metadata and return immutable ArtifactView objects. |
| IDecoder | Decode bytes into normalized instruction records with source provenance. |
| ILifter | Lift instruction/block/function into backend IR and optionally CoreIR. |
| ICFGRecoverer | Discover functions, blocks, direct/indirect edges, confidence, and conflicting interpretations. |
| IDecompiler | Return pseudocode, variable/type information, source mapping, and decompiler diagnostics. |
| ITracer | Collect function/instruction/memory/API/syscall events under a declared observer context. |
| IReplayEngine | Record, index, replay, seek, snapshot, and run analysis plugins on deterministic recordings. |
| IEmulator | Execute bounded code or process models with hooks, snapshots, and controlled inputs. |
| ISymbolicExecutor | Solve targeted reachability/dataflow questions under explicit resource limits. |
| ITaintEngine | Create source/sink policies and return data-dependency explanations with provenance. |
| IUnpacker | Detect and capture runtime-generated/decrypted images; reconstruct and validate artifacts. |
| INetworkAnalyzer | Capture, reconstruct, parse, and correlate flows/messages with code and buffers. |
| IVMIBackend | Observe memory, registers, processes, events, and kernel structures from the hypervisor layer. |
| IHardwareTraceBackend | Acquire/decode processor trace and normalize execution to module/RVA/CoreIR entities. |
| IExternalMemoryObserver | Acquire point-in-time memory through an external or privileged path and expose snapshot semantics. |
| IExecutionEnvironment | Provision, attest, run, reset, and destroy VM, emulator, VMI, or bare-metal environments. |


## 15.3 Capability declaration

Each backend publishes a signed descriptor:

```json
{
  "backend": "panda",
  "version": "image-digest",
  "disciplines": ["whole_system", "record_replay", "taint"],
  "architectures": ["x86", "x86_64", "arm"],
  "operating_systems": ["linux", "windows-version-matrix"],
  "visibility": {"user": true, "kernel": true, "multi_process": true},
  "observer_footprint": "VIRTUALIZED",
  "deterministic_replay": true,
  "licenses": ["GPL-2.0"],
  "deployment": "isolated-worker",
  "qualification_profile": "qual_..."
}
```

The planner selects only qualified capabilities. Marketing support matrices are generated from tested descriptors, not from upstream README claims alone.

# 16. Security and isolation model

## 16.1 Trust zones

- **Zone A - Control:** API, planner, policy, metadata DB. No target bytes are parsed without an isolated service.
- **Zone B - Artifact gateway:** content scanning, hashing, type detection, signed transfer, quotas.
- **Zone C - Static workers:** disposable containers/microVMs with no network by default.
- **Zone D - Dynamic VM/emulation:** dedicated hypervisor hosts and segmented virtual networks.
- **Zone E - VMI/whole system:** privileged hosts separated from general control workloads.
- **Zone F - Bare metal/high fidelity:** physically/logically segregated laboratory with out-of-band management.
- **Zone G - Egress/simulation:** controlled gateways, fake services, packet capture, DNS and destination policy.

## 16.2 Secret isolation

LLM API keys, cloud credentials, source-control credentials, signing keys, operator SSO tokens, and database credentials never enter a target environment. Workers receive short-lived scoped capability tokens usable only for uploading results to a job-specific endpoint.

## 16.3 Artifact transfer

Results cross trust boundaries through an artifact broker that enforces size/type quotas, hashes content, records producer/run/tool metadata, and can route risky outputs through secondary scanning or quarantine. A hostile guest never mounts the object store or control-plane filesystem directly.

## 16.4 Supply-chain security

- Pin tools, containers, VMs, firmware, rule sets, and protocol specs by digest/version.
- Produce SBOMs and third-party notices.
- Monitor advisories and rebuild images promptly.
- Sign worker images and result manifests.
- Fuzz loaders, IR parsers, trace decoders, worker protocols, and import/export paths.
- Separate rule/signature updates from executable code and verify provenance.

## 16.5 Audit and approval

Audit logs cover user question, model/provider/configuration, compiled facts, plan versions, policy decisions, approvals, environment allocation, executed commands inside the worker wrapper, network policy, produced evidence, conclusion versions, and exports. Approval tokens bind to the exact experiment digest and expire; they cannot authorize arbitrary future actions.

# 17. Example end-to-end investigation: game plus kernel anti-cheat

This example is architectural, not a target-specific bypass recipe.

## 17.1 Question

> What role does the kernel component play when the game enters a match, and which user-mode result depends on it?

## 17.2 Static inventory

The platform ingests launcher, game, anti-cheat client modules, service binaries, driver, configuration, signatures, and symbols where authorized. It recovers process-start indicators, service/driver configuration, driver initialization and dispatch candidates, device/interface strings, IPC candidates, imports, CFGs, IR, decompiler output, and preliminary relationships. All are hypotheses until runtime evidence confirms them.

## 17.3 Broad controlled run

A disposable environment collects process/thread/module lifecycle, service/driver loads, files/registry, IPC, network, memory mappings, exceptions, and selected kernel events. The purpose is topology, not exhaustive instruction trace.

The result is a chain such as:

```text
game process/function
  -> request/shared object
  -> anti-cheat service function
  -> user-kernel interaction
  -> driver dispatch/function
  -> response/status
  -> consuming game function/branch
```

Each arrow cites concrete observations and address mappings.

## 17.4 Fidelity assessment

The manager compares a low-instrumentation baseline, DBI run, VM/whole-system run, and VMI or approved physical baseline as available. If a branch or system state first diverges under a particular observer, it creates an EnvironmentSensitiveDecision and limits downstream evidence from that run.

The system does not respond by assuming the VM should be hidden. It first determines whether an alternative observation position can answer the question with less interference. Externally visible tests remain policy gated.

## 17.5 Narrowing

Once the relevant request/driver path is identified, the planner performs targeted tracing or replay around those entities, captures request/response buffers, and maps runtime addresses to static functions. It uses backward slices and bounded symbolic analysis only for the decisions that remain unexplained.

## 17.6 Answer form

The answer states:

- Supported user/service/driver chain.
- What was directly observed versus statically derived or inferred.
- Environments and observer contexts.
- Cross-run agreement and first divergence, if any.
- Confidence and known unknowns.
- Reproducing experiment and evidence IDs.
- Whether a higher-fidelity physical experiment is required and whether policy permits it.

# 18. Licensing and redistribution plan

This section is engineering guidance, not legal advice.

| Category | Packaging rule | Required control |
| --- | --- | --- |
| Permissive in-process | MIT, BSD, Apache-2.0, PostgreSQL-style | Generally acceptable after notice, patent, and third-party review. |
| Weak copyleft library | LGPL variants | Prefer dynamic linking or an out-of-process boundary; meet relinking/source/notice obligations; legal review. |
| Strong copyleft | GPL/AGPL | Use separate worker/service or user-supplied integration unless the product distribution model is compatible. |
| Custom/research license | VSL, noncommercial, source-available, mixed per-file | Legal approval before redistribution, hosted use, or derivative work. |
| No verified grant / all rights reserved | AIRECE and any unresolved repository | No code reuse, linking, redistribution, or derivative work without written permission. |
| Bundled dependencies | LLVM, QEMU components, firmware, signatures, rules, protocol specs | Track per-file and data licenses; generate SBOM and notices for every release. |


## 18.1 License architecture rule

The commercial/product license should not be dictated accidentally by one analysis backend. Keep the core protocol and evidence schemas implementation-independent. GPL/AGPL tools communicate through files/RPC as separately deployed programs where legally appropriate, and users may be required to install some optional backends separately. Distribution design still requires counsel; process boundaries are not a universal cure for license obligations.

## 18.2 Dependency record

For every candidate record:

- Repository and exact commit/release digest.
- SPDX license(s), per-file exceptions, and third-party notices.
- Linking/deployment method and static-linking viability.
- Source-offer/relinking/network-copyleft obligations if applicable.
- Supported OS/architectures and tested subset.
- Maintenance/security status and advisory process.
- API stability and fork burden.
- Data/rule/model/spec licenses, not only executable code.
- Decision: core, sidecar, optional user-supplied, reference only, or rejected.

## 18.3 Immediate license gates

- **XAIR/XAIR_CFG/XAIR_SYM:** archive and inspect LICENSE, LICENSES, REUSE metadata, third-party notices, and file headers. Obtain clarification if terms conflict or are incomplete.
- **AIRECE:** all rights reserved at snapshot; written permission or relicensing is required for code reuse.
- **Qt:** decide commercial versus LGPL deployment early; dynamic linking and user relinking/notice obligations must be designed into packaging.
- **QEMU/PANDA/Unicorn/Qiling/Wireshark/rr/DRAKVUF:** isolate and document GPL deployment/distribution.
- **MemProcFS/Volatility:** custom/AGPL terms require a deliberate external-service or commercial-license decision.

# 19. Testing, benchmarks, and backend qualification

## 19.1 Test corpus layers

1. **Generated microcorpus:** compiled functions covering instructions, flags, ABI, exceptions, switches, indirect calls, TLS, atomics, vectors, and optimization variants.
2. **Open-source reproducible corpus:** multiple compilers/versions/optimization/LTO/stripping across Windows/Linux and architectures.
3. **CTF and obfuscation corpus:** legal, redistributable challenges with known solutions.
4. **Malware-like synthetic corpus:** packing, injection, generated code, persistence, protocol, and destructive-behavior simulations without live harmful payloads.
5. **Driver/kernel lab corpus:** signed test drivers/modules with known IOCTL/syscall/object/IPC behavior.
6. **Environment-sensitivity corpus:** seeded VM, timing, debugger, instrumentation, and hardware/property decisions used to validate divergence detection.
7. **Replay/fidelity corpus:** deterministic and intentionally nondeterministic workloads.
8. **Authorized real-target evaluations:** isolated, nonredistributable test sets with legal and OPSEC controls.

## 19.2 Metrics

- Loader/decoder correctness and disagreement rate.
- Function/CFG precision and recall on labeled data.
- IR semantic equivalence through concrete/differential execution.
- Decompiler mapping completeness and type/call accuracy.
- Runtime event loss, address-map correctness, overhead, and crash isolation.
- Replay determinism and event reproducibility.
- Taint source-to-sink precision/recall on seeded flows.
- Symbolic witness correctness, solver time, paths, and timeout rate.
- Runtime artifact recovery precision and reconstruction validity.
- First-divergence localization accuracy.
- Evidence provenance completeness.
- Answer factuality, citation completeness, calibration, abstention quality, and action cost.
- Policy bypass resistance and unauthorized-egress rate (target: zero in qualification).
- Worker compromise containment and recovery time.

## 19.3 Backend qualification scorecard

A backend is production-qualified only after:

- Supported architecture/OS matrix passes CI/lab tests.
- Malformed-input fuzzing and resource-exhaustion tests.
- Versioned schemas and graceful failure behavior.
- Provenance completeness and deterministic normalization.
- Performance budget characterization by profile.
- Security and supply-chain review.
- License/redistribution approval.
- Cross-backend comparison against at least one independent oracle.
- Documented known gaps and downgrade behavior.

## 19.4 AI evaluation

Create question suites whose answers can be checked against ground truth. Score separately:

- Fact selection: did the controller identify the right required facts?
- Plan efficiency: did it choose the smallest sufficient action set?
- Safety: were policy and exposure constraints obeyed?
- Evidence use: does each claim cite compatible evidence?
- Calibration: does confidence track measured correctness?
- Abstention: does the system stop when evidence is unavailable or unrepresentative?
- Reproducibility: can another worker repeat the analysis from the bundle?

# 20. Delivery roadmap

The estimates below assume an experienced multidisciplinary team and overlap between product and research work. They are planning ranges, not delivery guarantees.

| Phase | Name | Indicative duration | Primary deliverables |
| --- | --- | --- | --- |
| 0 | Foundation and legal/architecture gates | 6-8 weeks | Architecture decision records, threat model, license matrix, benchmark corpus, CoreIR/evidence prototypes, XAIR go/no-go. |
| 1 | Static agent-first MVP | 4-6 months | PE/ELF x86/x86-64 ingestion, CFG/call graph, Ghidra worker, evidence store, CLI/gRPC/MCP ask flow. |
| 2 | Native dynamic analysis | 4-6 months | DynamoRIO backend, process/thread/module topology, API/syscall events, bounded function/memory tracing, runtime artifact capture. |
| 3 | Knowledge-driven automation | 4-6 months | Fact compiler, planner, policy engine, hypotheses, reproducible experiments, run comparison, action budgets. |
| 4 | Replay, symbolic, taint, and unpacking | 6-9 months | rr/PANDA replay, Z3/Triton or XAIR_SYM, targeted taint, artifact reconstruction, deobfuscation transformations. |
| 5 | Multi-process, kernel, and VMI | 9-15 months | System topology, user-kernel interaction graph, synthetic driver corpus, whole-system/VMI pilots, environment divergence detection. |
| 6 | High-fidelity OPSEC laboratory | 12-24 months, parallel research | Bare-metal pool, automated reimage, hardware trace, optional external memory, fidelity scoring, approval workflows. |
| 7 | Full analyst platform and scale | 6-9 months after core stability | Production Qt GUI, multi-user projects, plugin SDK, distributed workers, large-trace operations, enterprise controls. |

## Phase 0 - Foundation and legal/architecture gates

**Objective.** Architecture decision records, threat model, license matrix, benchmark corpus, CoreIR/evidence prototypes, XAIR go/no-go.

**Acceptance criteria**

- Every selected dependency has an owner, version/pin policy, redistribution decision, and security-update process.
- XAIR, XAIR_CFG, XAIR_SYM, and AIRECE receive explicit license decisions before any copied code enters the product.
- CoreIR and EvidenceRecord prototypes represent both static functions and runtime module/RVA events without backend-specific identifiers.
- The hostile-execution threat model covers guest escape, credential theft, network reporting, persistence, destructive behavior, and supply-chain risk.

## Phase 1 - Static agent-first MVP

**Objective.** PE/ELF x86/x86-64 ingestion, CFG/call graph, Ghidra worker, evidence store, CLI/gRPC/MCP ask flow.

**Acceptance criteria**

- A deterministic CLI ingests a representative PE/ELF x86/x86-64 corpus and returns stable artifact/function/block identifiers.
- Answers to the static benchmark cite concrete evidence IDs and never present unsupported model text as fact.
- The Ghidra worker is pinned, sandboxed, resource-limited, and exports pseudocode/p-code/types with address mapping.
- GUI is intentionally deferred or read-only; all core workflows are available through JSON/gRPC for coding harnesses.

## Phase 2 - Native dynamic analysis

**Objective.** DynamoRIO backend, process/thread/module topology, API/syscall events, bounded function/memory tracing, runtime artifact capture.

**Acceptance criteria**

- A process tree, threads, module lifetimes, selected APIs/syscalls, and coverage can be captured and correlated with static entities.
- Dynamic workers contain target crashes and cannot access control-plane credentials or arbitrary external networks.
- Runtime-generated executable content can be dumped, hashed, related to the originating run, and re-ingested automatically.
- Performance overhead and event loss are measured per trace profile; the controller selects the least expensive profile that answers the fact request.

## Phase 3 - Knowledge-driven automation

**Objective.** Fact compiler, planner, policy engine, hypotheses, reproducible experiments, run comparison, action budgets.

**Acceptance criteria**

- The planner converts at least the benchmark question set into typed fact requirements and bounded action DAGs.
- Every experiment has an immutable manifest, policy decision, inputs, environment digest, tool versions, and output evidence.
- Default-deny network and exposure policies block unauthorized actions regardless of LLM output.
- Differential alignment identifies known first-divergence points in seeded test programs.

## Phase 4 - Replay, symbolic, taint, and unpacking

**Objective.** rr/PANDA replay, Z3/Triton or XAIR_SYM, targeted taint, artifact reconstruction, deobfuscation transformations.

**Acceptance criteria**

- Targeted symbolic analysis produces witnesses for seeded branch/reachability cases while respecting time, memory, path, and solver budgets.
- Replay reproduces selected benchmark events sufficiently for repeatable offline analyses and records any nondeterminism.
- Taint/source-sink explanations include source bytes, transformation path, sinks, and uncertainty.
- Recovered artifacts are validated against runtime mappings and do not overwrite the original evidence chain.

## Phase 5 - Multi-process, kernel, and VMI

**Objective.** System topology, user-kernel interaction graph, synthetic driver corpus, whole-system/VMI pilots, environment divergence detection.

**Acceptance criteria**

- The system correlates a user-mode call site, IPC or request structure, driver dispatch path, and return value on a synthetic signed-driver lab corpus.
- Environment comparison detects seeded VM/instrumentation-sensitive branches and marks downstream evidence as nonrepresentative when appropriate.
- VMI observations carry OS-profile confidence and fail closed when kernel semantic reconstruction is unreliable.
- The product reports unsupported current-OS targets rather than extrapolating from stale VMI profiles.

## Phase 6 - High-fidelity OPSEC laboratory

**Objective.** Bare-metal pool, automated reimage, hardware trace, optional external memory, fidelity scoring, approval workflows.

**Acceptance criteria**

- Bare-metal nodes can be provisioned from a known image, attested, executed, collected, power-cycled, and reimaged without analyst credentials on the node.
- Hardware trace maps the agreed proportion of known benchmark branch targets to artifact/module/RVA identities and reports trace gaps explicitly.
- External-memory snapshots are labeled point-in-time observations and are never treated as a complete temporal trace.
- No experiment with external exposure or valuable identity can start without the required authorization token.

## Phase 7 - Full analyst platform and scale

**Objective.** Production Qt GUI, multi-user projects, plugin SDK, distributed workers, large-trace operations, enterprise controls.

**Acceptance criteria**

- GUI and CLI display the same evidence IDs, conclusions, conflicts, and experiment states.
- Large projects remain responsive through pagination, server-side graph queries, trace chunking, and progressive rendering.
- Plugins run under declared capabilities and cannot bypass artifact, network, or credential policies.
- Multi-user audit logs record questions, plans, approvals, executions, evidence changes, and conclusion publication.


## 20.1 Milestone interpretation

A useful static agent-first MVP is plausible in roughly 6-9 months after Phase 0 with a focused team and a constrained scope. A strong multi-discipline product is more likely an 18-30 month program. Current hostile kernel targets, generalized anti-analysis handling, bare-metal operations, and novel devirtualization are a 30-48+ month research/productization program and will remain target dependent.

Do not wait for the GUI to validate the platform. The CLI/API, evidence schema, and benchmark suite should mature first. Begin GUI work once stable entity/evidence APIs and dynamic timelines exist.

# 21. Team, workstreams, and critical path

## 21.1 Suggested staffing
| Workstream | Initial FTE | Responsibilities |
| --- | --- | --- |
| Core analysis/IR | 2-3 | Binary formats, disassembly, CFG, SSA, decompiler integration, identity mapping. |
| Dynamic/runtime | 2-3 | DBI, OS telemetry, replay, artifact recovery, performance. |
| Knowledge/planner/API | 2-3 | Evidence schema, query compiler, policy, orchestration, gRPC/MCP. |
| Security/lab infrastructure | 1-2 initially; 3+ by Phase 5 | Isolation, VM/VMI, bare metal, networking, OPSEC, incident response. |
| GUI/product | 1-2 beginning after Phase 2 | Qt desktop, graph/timeline rendering, project UX. |
| QA/benchmarks | 1-2 | Corpora, reproducibility, fuzzing, performance, backend qualification. |


An 8-12 engineer core team is a reasonable target for parallel progress after the MVP, excluding legal, infrastructure operations, product design, and specialized kernel/hardware consultants. A smaller team can deliver the static MVP but should not attempt all advanced backends concurrently.

## 21.2 Critical path

1. License and architecture gates for XAIR/AIRECE/Ghidra/Qt and sidecar policy.
2. Stable artifact/entity/evidence IDs and CoreIR boundaries.
3. Static ingestion, Ghidra export, and deterministic agent API.
4. Runtime module/RVA identity mapping and event schema.
5. Policy engine and hostile-worker isolation before autonomous dynamic execution.
6. Experiment manifests and differential alignment before advanced planner autonomy.
7. Whole-system/kernel semantic model before VMI product claims.
8. Automated physical-lab lifecycle before hardware trace/external memory becomes operationally safe.

## 21.3 Repository organization

```text
/core                C++ domain, schemas, evidence, CoreIR, query primitives
/proto               protobuf/gRPC contracts and compatibility tests
/cli                 agent-first CLI
/gui                 Qt client
/workers/ghidra      headless decompiler worker
/workers/static      loaders/decoders/CFG adapters
/workers/dynamorio   native trace client and collector
/workers/replay      rr/PANDA/QEMU adapters
/workers/symbolic    Z3/Triton/XAIR_SYM/angr adapters
/workers/network     capture/simulation/dissection
/workers/vmi         LibVMI/DRAKVUF adapters
/workers/hardware    processor trace and external-memory adapters
/control             scheduler, policy, OPSEC/fidelity, environment manager
/storage             migrations, CAS, Parquet schemas, retention
/qual                corpora, oracles, fuzzers, benchmarks, support matrix
/deploy              container/VM images, libvirt/Xen, bare-metal provisioning
/docs                architecture decisions, licenses, operator and SDK docs
```

# 22. Major risks and mitigations
| Risk | Severity | Mitigation |
| --- | --- | --- |
| License ambiguity in XAIR family/AIRECE | Critical | Complete REUSE/SPDX and counsel review; secure explicit permissive grant; keep CoreIR independent; no copied AIRECE code without permission. |
| Decompiler coupling | High | Use a versioned Ghidra worker protocol; persist normalized outputs, not internal Java/C++ object graphs; maintain fallback decompiler adapters. |
| IR scope explosion | High | Keep CoreIR an interchange/evidence schema; preserve backend-native IR for advanced analyses; add operations only against benchmark requirements. |
| LLM hallucination or unsafe plan | Critical | Typed facts/actions, deterministic plan compiler, evidence validators, policy engine, budgets, explicit unknown state, audit logs. |
| Trace volume and performance | High | Profiles, filters, hardware counters, chunked Parquet, compression, sampling, offline replay, retention policies, cost-aware planner. |
| Observer changes target behavior | Critical | ObservationContext, multiple backends, baseline runs, first-divergence alignment, fidelity scores, bare-metal escalation. |
| VM/VMI support lags modern OS versions | High | Do not promise generic current-OS coverage; maintain tested OS image matrix; invest in symbols/profiles; use bare metal and OS-native telemetry when VMI is stale. |
| Guest escape or host compromise | Critical | Dedicated hosts, patched hypervisors, nested isolation where appropriate, no shared credentials, egress controls, immutable images, monitoring and incident procedure. |
| Remote reporting, bans, or blacklisting | Critical | Default simulated/offline networking; disposable research identities only under explicit authorization; exposure scoring; no production accounts. |
| Bare-metal persistence/firmware risk | Critical | Replaceable lab hardware, measured/secure boot policy as appropriate, firmware baselines, power isolation, reimage and quarantine, separate management network. |
| DMA/external device false sense of stealth | High | Treat as observable hardware and point-in-time acquisition; compare topology; document IOMMU/platform limits; never market as invisible. |
| Symbolic path explosion | High | Concrete seeding, slices, bounded regions, targeted questions, solver/time/path budgets, learned models only after validation. |
| Incorrect static recovery | High | Multiple decoder/decompiler cross-checks, confidence/contradictions, dynamic validation, corpus with hand-labeled ground truth. |
| Malicious artifacts exploit parsers | Critical | Sandbox all parsers and decompilers, least privilege, read-only inputs, resource limits, pinned patched versions, fuzzing and supply-chain scanning. |
| Project tries to integrate everything | High | Enforce minimal-stack roadmap and backend qualification scorecard; defer tools without a benchmark-driven need. |


# 23. Architecture decisions to make immediately

1. **Product licensing/distribution model.** Decide whether the core is proprietary, source-available, or open source; this changes Qt and copyleft integration choices.
2. **XAIR family status.** Complete license/maturity review and choose conditional adoption, fork with permission, or project-owned CoreIR/CFG implementation.
3. **Backend protocol.** Freeze the first protobuf entity/evidence/action schemas and compatibility rules.
4. **Ghidra boundary.** Approve headless worker as the initial decompiler architecture.
5. **Storage baseline.** Approve PostgreSQL + CAS + Parquet/Arrow + DuckDB; defer graph DB.
6. **Dynamic platform order.** Recommend Windows and Linux x86/x86-64, with one primary DynamoRIO profile per OS before ARM expansion.
7. **Network policy.** Approve default no-network/simulated modes and the authorization process for restricted egress.
8. **OPSEC authority.** Define which risk classes the system can run automatically and who can issue higher-risk authorization tokens.
9. **Lab target.** Select hypervisor(s), tested guest OS versions, and whether Xen/VMI is a funded Phase 5 path.
10. **Bare-metal research charter.** Define legal targets, hardware budget, facility/network controls, reimage/firmware procedures, and success metrics before purchasing specialized equipment.

# 24. Deferred decisions

- Dedicated graph database.
- Directly embedding/forking the Ghidra native decompiler.
- Generalized Windows 11+ VMI support claims.
- ARM/AArch64 hardware-trace implementation.
- Continuous full-system taint for commercial-scale applications.
- Automated current-commercial anti-cheat/EDR bypass or invisibility features.
- General novel custom-VM devirtualization.
- Hosted external-memory acquisition as a standard product feature.

These are deferred until the evidence model, static/dynamic identity bridge, policy engine, and benchmark infrastructure demonstrate value.

# Appendix A - Detailed open-source tool map

## A.1 User-provided XAIR/AIRECE projects
| Candidate | Fit | API/maturity | License | Recommendation |
| --- | --- | --- | --- | --- |
| [XAIR](https://github.com/Jaden-Bowers/XAIR) | C library/IR; typed SSA, explicit memory/control/flags/effects/provenance for x86/x86-64 | CMake; MSVC/Clang/GCC; Zydis; small and early public project | License files are present, but exact terms require final verification | Strong architectural fit; adopt only after license and qualification gate |
| [XAIR_CFG](https://github.com/Jaden-Bowers/XAIR_CFG) | CFG/function recovery over XAIR for x86/x86-64 PE/ELF | C library; typed edges, overlaps, direct/indirect target recovery | Exact terms require final verification | Conditional primary CFG implementation; preserve alternate backend |
| [XAIR_SYM](https://github.com/Jaden-Bowers/XAIR_SYM) | Symbolic execution, taint, constraints over frozen XAIR modules/CFG; Z3 C API | C library; bounded forking and API models | Exact terms require final verification | Conditional tightly integrated static symbolic engine |
| [AIRECE](https://github.com/Jaden-Bowers/AIRECE) | Agent-oriented static context engine and command surface | C++ CLI concepts for summaries, refs, slices, paths, and protocol stability | All rights reserved in repository LICENSE as of snapshot | Study product/API ideas; do not copy, link, redistribute, or derive without written permission |


## A.2 Static analysis, loading, IR, decompilation, and similarity
| Candidate | Fit | API/platform | License | Recommendation |
| --- | --- | --- | --- | --- |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Decompiler, p-code, types, broad architecture support | Headless Java worker invoking decompiler APIs/native core indirectly | Apache-2.0 project; audit bundled notices | Adopt as pinned sandboxed sidecar |
| [LIEF](https://github.com/lief-project/LIEF) | PE/ELF and other format parsing/modification | C++ API; Python/Rust bindings | Apache-2.0 | Adopt in core for loader/metadata |
| [Zydis](https://github.com/zyantific/zydis) | Fast x86/x86-64 decoding | Small C API; suitable for embedding | MIT | Adopt primary x86 decoder |
| [Capstone](https://github.com/capstone-engine/capstone) | Multi-architecture disassembly | C API; broad bindings | BSD | Adopt ARM/AArch64 and validation path |
| [Rizin](https://github.com/rizinorg/rizin) | Broad RE framework and command/API ecosystem | C core but large/mixed dependency surface | LGPL/GPL mix; audit required | Optional external backend/reference |
| [angr](https://github.com/angr/angr) | VEX lifting, CFG, symbolic/dataflow analyses | Python sidecar; strong research ecosystem | BSD-2-Clause | Use for validation and specialized sidecar analyses |
| [BSim](https://ghidra.re/ghidra_docs/GhidraClass/BSim/BSimTutorial.html) | Function similarity from decompiler features | Inside Ghidra ecosystem | Ghidra licensing/packaging applies | Adopt as one similarity evidence source |
| [TLSH](https://github.com/trendmicro/tlsh) | Coarse fuzzy hash clustering of artifacts | C++/Python | Apache-2.0/BSD options | Optional; never treat as semantic equivalence |


## A.3 Dynamic instrumentation and replay
| Candidate | Fit | API/platform | License | Recommendation |
| --- | --- | --- | --- | --- |
| [DynamoRIO](https://github.com/DynamoRIO/dynamorio) | Native DBI, clients, offline memory/trace tooling | C/C++; Windows/Linux/Android; x86/x64/ARM/AArch64 support varies by feature | Primarily BSD-style; audit extensions | Primary user-space tracing backend |
| [QBDI](https://github.com/QBDI/QBDI) | Targeted binary instrumentation | C/C++/Python/Frida APIs; cross-platform; limitations on signals/new threads/exceptions noted upstream | Apache-2.0 for QBDI source; audit bundled LLVM | Optional targeted backend, not default whole-process tracer |
| [Frida](https://github.com/frida/frida-core) | Rapid API/function instrumentation and interactive inspection | C core, JS agents, multiple platforms | wxWindows Library Licence 3.1 terms and dependency audit | Optional prototyping/interactive backend; high observer footprint |
| [rr](https://github.com/rr-debugger/rr) | Linux process-tree deterministic record/replay | Linux-focused; hardware/PMU constraints | GPL-2.0 | External replay sidecar |
| OS-native telemetry | ETW/WPP/WinDbg interfaces on Windows; ptrace/perf/eBPF/audit on Linux | Native APIs; feature and privilege dependent | Platform terms; own code | Build adapters; use as corroborating evidence |


## A.4 Emulation, whole-system, and VMI
| Candidate | Fit | API/platform | License | Recommendation |
| --- | --- | --- | --- | --- |
| [QEMU](https://www.qemu.org/) | Whole-system and user-mode emulation | C; QMP/libvirt control; broad architectures | GPL-2.0 overall with per-file variation | External worker, controlled through QMP/libvirt |
| [PANDA](https://github.com/panda-re/panda) | Whole-system record/replay, plugins, taint and offline analysis | QEMU-derived; strong research workflow | GPL-2.0 | Isolated whole-system/replay backend |
| [Unicorn](https://github.com/unicorn-engine/unicorn) | CPU emulation for bounded code regions | C API; broad architectures | GPL-2.0 | Separate service or compatible distribution only |
| [Qiling](https://github.com/qilingframework/qiling) | OS/API-aware emulation built on Unicorn | Python framework; broad binaries/OS models | GPL-2.0 | Prototype/research sidecar |
| [LibVMI](https://github.com/libvmi/libvmi) | Virtual-machine memory and event introspection | C; Xen strongest; other backends vary | LGPL-3.0+ | Separate VMI service and tested support matrix |
| [DRAKVUF](https://github.com/tklengyel/drakvuf) | Agentless black-box VMI analysis on Xen | Kernel/user observation; upstream OS support is version bounded | GPL-2.0 and component terms | Research pilot; not baseline for modern Windows coverage |


## A.5 Symbolic execution and taint
| Candidate | Fit | API/platform | License | Recommendation |
| --- | --- | --- | --- | --- |
| [Z3](https://github.com/Z3Prover/z3) | SMT solving | Mature C/C++ APIs and bindings | MIT | Default solver |
| [Bitwuzla](https://github.com/bitwuzla/bitwuzla) | Bit-vector/floating-point/array SMT solving | C/C++ APIs | MIT | Optional alternate/cross-check solver |
| [Triton](https://github.com/JonathanSalwan/Triton) | Dynamic symbolic execution, taint, ASTs, deobfuscation/devirtualization research | C++/Python; x86/x64/ARM/AArch64/RISC-V support described upstream | Apache-2.0 | Adopt targeted backend; qualify per architecture |
| [angr](https://github.com/angr/angr) | Symbolic exploration and analyses over VEX | Python; strong modeling ecosystem | BSD-2-Clause | Sidecar and differential oracle |


## A.6 Malware enrichment and runtime artifacts
| Candidate | Fit | API/platform | License | Recommendation |
| --- | --- | --- | --- | --- |
| [YARA-X](https://github.com/VirusTotal/yara-x) | Pattern/rule matching and scanning | Rust core with stable C API | BSD-3-Clause | Adopt C API; pin current patched releases |
| [capa](https://github.com/mandiant/capa) | Capability classification from static and dynamic features | Python/library/CLI | Apache-2.0 | Sidecar semantic enrichment, never sole proof |
| [FLOSS](https://github.com/mandiant/flare-floss) | Static/runtime-decoded string recovery | Python/CLI | Apache-2.0 | Sidecar |
| [PE-sieve](https://github.com/hasherezade/pe-sieve) | Windows process image/injection/shellcode detection and dumping | C++ DLL/CLI | BSD-2-Clause | Windows worker after fuzzing/qualification |
| CAPE and sandbox ecosystems | Behavior collection, unpacking, signatures, sample workflows | Large Python/VM stack | Mixed components | Study/integrate selected ideas; avoid making core dependent on full sandbox |


## A.7 Network and protocol analysis
| Candidate | Fit | API/platform | License | Recommendation |
| --- | --- | --- | --- | --- |
| [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng) | Controlled network simulation and redirection | Windows/Linux deployment modes | Apache-2.0 | Use in isolated lab profiles |
| [Wireshark/tshark](https://www.wireshark.org/) | Packet capture, dissection, stream analysis | C/C++; extensive dissectors | GPL-2.0+ | External sidecar/process; do not hard-link closed core |
| [Zeek](https://zeek.org/) | Stateful, high-level network metadata and scripting | Service-oriented analysis | BSD | Optional network-analysis service |
| [Kaitai Struct](https://kaitai.io/) | Declarative binary protocol formats/code generation | Compiler plus generated parsers | Compiler GPL; generated outputs/specs have separate terms | Build-time generator with per-spec license audit |
| [Netzob](https://github.com/netzob/netzob) | Protocol inference and state-machine research | Python | GPL-3.0 | Isolated research sidecar |


## A.8 Storage, analytics, and GUI
| Candidate | Fit | API/platform | License | Recommendation |
| --- | --- | --- | --- | --- |
| [PostgreSQL](https://www.postgresql.org/) | Transactional metadata, graph edges, audit, jobs | Server; mature SQL/JSON/recursive queries | PostgreSQL License | Primary metadata/evidence database |
| [pgvector](https://github.com/pgvector/pgvector) | Vector similarity inside PostgreSQL | Exact/HNSW/IVFFlat options | PostgreSQL-style | Secondary retrieval only |
| [Apache Arrow](https://arrow.apache.org/) + Parquet | Columnar event interchange and compressed trace chunks | Strong C++ support | Apache-2.0 | Primary trace file representation |
| [DuckDB](https://duckdb.org/) | Local analytical SQL over Parquet/Arrow | Embedded C++ API | MIT | Worker/local trace analytics |
| Qt 6 | Production desktop GUI, docking, model/view, accessibility | C++ | Commercial or LGPL/GPL depending module | Dynamic-link LGPL-compliant build or commercial license; audit modules |
| [Dear ImGui](https://github.com/ocornut/imgui) | Fast internal/debug panels | C++ immediate-mode | MIT | Internal tools, not primary production UX |
| [Graphviz](https://graphviz.org/) | Graph layout algorithms | Library/CLI | EPL-2.0 | External layout service or legal-reviewed library usage |


## A.9 Infrastructure, hardware trace, and external memory
| Candidate | Fit | API/platform | License | Recommendation |
| --- | --- | --- | --- | --- |
| [gRPC](https://grpc.io/) | Typed RPC, streaming, multi-language clients | Protocol Buffers; strong C++ support | Apache-2.0 | Primary internal/external service protocol |
| [Model Context Protocol](https://modelcontextprotocol.io/specification) | Agent tool/resource interface | JSON-RPC ecosystem | Specification/SDK terms vary; official spec is open | Adapter over stable domain API, not core internal protocol |
| [NATS](https://nats.io/) | Distributed messaging and JetStream work queues | Multi-language clients | Apache-2.0 | Phase 7; pin patched releases |
| [libvirt](https://libvirt.org/) | VM lifecycle for QEMU/KVM/Xen and related platforms | C API and bindings | LGPL-2.1+ | Control-plane adapter |
| [Firecracker](https://firecracker-microvm.github.io/) | Lightweight Linux microVM isolation | KVM/Linux host+guest focus | Apache-2.0 | Use for helper services, not Windows target fidelity |
| BMC/Redfish/PXE imaging | Physical node power, boot, image, attestation lifecycle | Vendor/platform adapters | Standards/vendor terms | Build bare-metal environment adapter |
| [Intel libipt](https://github.com/intel/libipt) | Intel Processor Trace decoding | C library | BSD-3-Clause | Adopt for Intel PT decoding in Phase 6 |
| [LeechCore](https://github.com/ufrisk/LeechCore) | Physical/virtual memory acquisition API | C/C++/Python/C# ecosystem | Review repository/component terms | Optional isolated acquisition service |
| [MemProcFS](https://github.com/ufrisk/MemProcFS) | Memory analysis and virtual filesystem/API | C/C++ and bindings | AGPL-3.0; alternative licensing may be available | Isolated service or commercial agreement only |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | Memory forensics framework | Python | Custom Volatility Software License | External tool; legal review before redistribution |


# Appendix B - Reference links and research notes

Research snapshot: August 31, 2026. Upstream feature, support, security, and license status must be revalidated against pinned versions before implementation or release.

## B.1 Primary project source

- User-provided **Autonomous Reverse Engineering Platform - Project Outline**, supplied with this planning request.

## B.2 User-referenced repositories

- XAIR: <https://github.com/Jaden-Bowers/XAIR>
- XAIR_CFG: <https://github.com/Jaden-Bowers/XAIR_CFG>
- XAIR_SYM: <https://github.com/Jaden-Bowers/XAIR_SYM>
- AIRECE: <https://github.com/Jaden-Bowers/AIRECE>
- GitHub repository licensing guidance: <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository>

## B.3 Core analysis

- Ghidra: <https://github.com/NationalSecurityAgency/ghidra>
- Ghidra decompiler API: <https://ghidra.re/ghidra_docs/api/ghidra/app/decompiler/DecompInterface.html>
- Ghidra SLEIGH/p-code documentation: <https://ghidra.re/ghidra_docs/languages/html/sleigh.html>
- Ghidra BSim tutorial: <https://ghidra.re/ghidra_docs/GhidraClass/BSim/BSimTutorial.html>
- LIEF: <https://github.com/lief-project/LIEF>
- Zydis: <https://github.com/zyantific/zydis>
- Capstone: <https://github.com/capstone-engine/capstone>
- Rizin: <https://github.com/rizinorg/rizin>
- angr: <https://github.com/angr/angr>
- TLSH: <https://github.com/trendmicro/tlsh>

## B.4 Dynamic, replay, emulation, and VMI

- DynamoRIO: <https://github.com/DynamoRIO/dynamorio>
- QBDI: <https://github.com/QBDI/QBDI>
- Frida Core: <https://github.com/frida/frida-core>
- rr: <https://github.com/rr-debugger/rr>
- QEMU: <https://www.qemu.org/>
- PANDA: <https://github.com/panda-re/panda>
- Unicorn: <https://github.com/unicorn-engine/unicorn>
- Qiling: <https://github.com/qilingframework/qiling>
- LibVMI: <https://github.com/libvmi/libvmi>
- DRAKVUF: <https://github.com/tklengyel/drakvuf>

## B.5 Symbolic, taint, and malware analysis

- Z3: <https://github.com/Z3Prover/z3>
- Bitwuzla: <https://github.com/bitwuzla/bitwuzla>
- Triton: <https://github.com/JonathanSalwan/Triton>
- YARA-X: <https://github.com/VirusTotal/yara-x>
- capa: <https://github.com/mandiant/capa>
- FLOSS: <https://github.com/mandiant/flare-floss>
- PE-sieve: <https://github.com/hasherezade/pe-sieve>

## B.6 Network, storage, GUI, and infrastructure

- FakeNet-NG: <https://github.com/mandiant/flare-fakenet-ng>
- Wireshark: <https://www.wireshark.org/>
- Zeek: <https://zeek.org/>
- Kaitai Struct: <https://kaitai.io/>
- Netzob: <https://github.com/netzob/netzob>
- PostgreSQL: <https://www.postgresql.org/>
- pgvector: <https://github.com/pgvector/pgvector>
- Apache Arrow: <https://arrow.apache.org/>
- Apache Parquet: <https://parquet.apache.org/>
- DuckDB: <https://duckdb.org/>
- Qt open-source licensing: <https://www.qt.io/licensing/open-source-lgpl-obligations>
- Dear ImGui: <https://github.com/ocornut/imgui>
- Graphviz license: <https://graphviz.org/license/>
- Model Context Protocol: <https://modelcontextprotocol.io/specification>
- gRPC: <https://grpc.io/>
- NATS: <https://nats.io/>
- libvirt: <https://libvirt.org/>
- Firecracker: <https://firecracker-microvm.github.io/>
- Intel libipt: <https://github.com/intel/libipt>
- LeechCore: <https://github.com/ufrisk/LeechCore>
- MemProcFS: <https://github.com/ufrisk/MemProcFS>
- Volatility 3: <https://github.com/volatilityfoundation/volatility3>

# Appendix C - Final recommended first release scope

The first release should be an **agent-first static-analysis product**, not a miniature version of every later capability.

**In scope:**

- PE/ELF x86/x86-64.
- Artifact ingestion, metadata, strings, imports/exports, disassembly, CFG/call graph, cross-references, basic dataflow, types where available, and Ghidra pseudocode.
- CoreIR/evidence/provenance and stable identity model.
- PostgreSQL/CAS project store.
- CLI, gRPC, JSON, and MCP adapter.
- Questions such as function purpose, callers/callees, API capability, data references, likely parser/crypto/configuration locations, and version comparisons.
- Explicit uncertainty, contradictions, and evidence links.
- Hardened static-worker isolation and license/SBOM pipeline.

**Immediately next:**

- DynamoRIO user-space tracing, process/module topology, selected argument/memory capture, runtime artifacts, and controlled network capture.
- Planner-generated bounded dynamic experiments.

**Not a first-release commitment:**

- Current commercial kernel anti-cheat or EDR support.
- General VM transparency.
- VMI coverage for every modern Windows build.
- Bare-metal/hardware-trace/DMA productization.
- Whole-application symbolic execution or automatic novel devirtualization.

This sequencing validates the differentiated query/evidence loop while keeping later observation backends replaceable.
