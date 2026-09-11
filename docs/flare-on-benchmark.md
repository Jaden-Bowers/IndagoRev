# FLARE-On catalogue and grading contract

## Scope

The frozen active benchmark is `flare-on-2014-2024-active116-v1`: 116 challenge identities across
eleven editions. **2025 is held out** and is rejected by the current freeze command.
The seed is `config/flare-on-2014-2024.seed.json`. Its definition records explicit
exclusions, the per-challenge selectors for the combined 2020 archive, and the
additional site material for 2018 challenge 4. Challenge IDs in 2023/2024 use
stable title slugs where local filenames lack ordinals.

Reference: [official archive index](https://flare-on.com/), checked 2026-09-10.
Only the index/download links were consulted; no solutions were opened. The local
mirror is not authenticated against every official release. The catalogue states
that limitation rather than treating a locally computed hash as upstream proof.
Challenge access/redistribution rights are not granted by this project's license.

Known local omissions: 2019 challenge 12 (`help`), 2021 challenge 5, and 2024
`sshd`. The operator explicitly excluded these three incomplete challenges on
2026-09-10. They are retained in `exclusions`, not the active denominator.
Included challenges cannot later be dropped because solving fails: any membership
change requires a new benchmark version. No 2025 material is needed or imported.

Frozen catalogue identity:
`58e5f957f264e47052fdeb652a76fc9353d010655c51ea0b8da5471ec20bb3a1`.
All 116 entries have locally available containers. A 116/116 result applies to
this selected set, not the complete historical archive. Synthetic diagnostics
remain separate and do not contribute to this score. The current generated
contract fixtures are sufficient for infrastructure checks; future synthetic RE
challenges should target specific analysis gaps and use independent graders.

## Native operator commands

All commands accept JSON through `indago benchmark OP --request FILE`. They are
**not model/harness tools**. The small Node drivers orchestrate development checks;
catalogue, extraction, verification and scoring execute in C++ in `indago`.

### Freeze

```json
{
  "manifest": "config/flare-on-2014-2024.seed.json",
  "corpus_root": "flare-on-chals/Flare-On-Challenges/Challenges",
  "archive_tool": "C:/Program Files/7-Zip/7z.exe",
  "wall_ms": 240000,
  "hash_bytes": 1073741824
}
```

Save stdout as the catalogue JSON. Alternatively use
`node tools/freeze-flare-catalogue.cjs EXE SEVEN_ZIP CORPUS_ROOT`; it retains the
catalogue and summary in a unique `out/flare-catalogue-*` directory.

Freeze only reads declared containers, not arbitrary corpus directories. It
hashes containers, lists bounded archive members, preserves parent relationships,
and reports unavailable/unsupported inputs. It does not execute samples or open
write-ups. A canonical-JSON SHA-256 pins the complete catalogue including missing
entries. Container bytes remain local and are not committed with metadata.

Member hashes are explicitly `pending_materialization` until extraction. Filename
format hints and entry-point candidates are **not** confirmed loader results.
Environment/dependency assessment is initially unknown, not implicitly Windows
or dependency-free. Actual runtime/entry selection belongs to investigation.

### Prepare a clean analysis input directory

```json
{
  "catalogue": "CATALOGUE.json",
  "corpus_root": "CORPUS_ROOT",
  "archive_tool": "C:/Program Files/7-Zip/7z.exe",
  "challenge": "flare-2014-03",
  "destination": "out/new-challenge-inputs",
  "max_bytes": 67108864,
  "wall_ms": 60000
}
```

The destination must be absent, outside the corpus, with an existing parent.
The default free-space floor is 20 GiB plus the expansion reservation. Preparation
preflights expanded sizes (maximum 512 MiB and 2,048 files), validates container
hashes before/after extraction, rejects unsafe paths and link entries, and uses
literal member selection with glob matching disabled. 7-Zip writes only to a
bounded stdout pipe; native code creates the approved destination paths.

`input-manifest.json` pins every produced file, container hash and member name.
Partial failure retains a labelled partial receipt; it cannot pass grading.
There is no overwrite, automatic retry, recursive extraction, or sample execution.
Nested archives remain artifacts to be investigated explicitly. OS-enforced
archiver memory quotas and hostile parser containment remain execution-layer work.
7-Zip is an explicitly selected development archive worker, not silently downloaded
or embedded by this change; runtime analysis engines are unchanged.

## Independent evaluator store

Keep verifier files outside analysis roots and all model-visible workspaces. For
real evaluation, enforce this with separate users/guest mounts; path checks alone
are not an adversarial security boundary. Do not place expected answers or their
digests in the catalogue, prompts, reports supplied to the model, or source code.

The initial verifier supports exact UTF-8 answer digests, with **no whitespace or
case normalization**:

```json
{
  "kind": "exact_utf8_sha256",
  "authority": "independent_operator",
  "challenge": "flare-2014-03",
  "catalogue_sha256": "CATALOGUE_DIGEST",
  "answer_sha256": "OPERATOR_SUPPLIED_EXPECTED_ANSWER_DIGEST"
}
```

The operator must supply authoritative grading truth. `authority` is a declaration,
not cryptographic authentication. No real challenge verifier is fabricated from
the harness's own answer; all real entries initially say `unconfigured`.
Behavioral verifier execution is intentionally not claimed by this fixed-answer
interface and will require a separately controlled runner in the later tasks.

An analysis submission retains a source solver/helper artifact without executing it:

```json
{
  "challenge": "flare-2014-03",
  "catalogue_sha256": "CATALOGUE_DIGEST",
  "attempt": 1,
  "answer": "MODEL_SELECTED_ANSWER",
  "solver_path": "solver.cpp",
  "solver_sha256": "SOLVER_FILE_DIGEST",
  "run": {
    "model": "DECLARED_MODEL",
    "profile_sha256": "PROFILE_DIGEST",
    "budget": {"wall_ms": 60000},
    "usage": {"wall_ms": 12000}
  }
}
```

`outcome` may instead label `timeout`, `unsupported`, `environment_missing`,
`budget_exhausted`, `analysis_failed`, `cancelled`, or `no_answer`. A failed attempt
still retains its work artifact (which may be an empty source file) and run record.

Grade request:

```json
{
  "catalogue": "CATALOGUE.json",
  "evaluator_root": "SEPARATE_EVALUATOR_DIRECTORY",
  "analysis_root": "PREPARED_ANALYSIS_DIRECTORY",
  "submission": "submission.json",
  "verifier": "oracle.json"
}
```

Receipts pin the submission, verifier, solver and catalogue. They explicitly say
`behavior_verified:false` and `solver_executed:false`: a fixed-answer pass is not
proof that the attached solver reproduces it. This evaluator does not alter the
harness's existing reasoning/report gate (task 2).

### Score

`benchmark score` takes `catalogue`, `evaluator_root`, and `attempts`, an array of
grade requests. It **regrades** submissions rather than trusting saved pass labels.
It reports pass-at-1 count, any-attempt passes, per-attempt provenance/failure
categories, and every challenge including unavailable, unsupported and not-run
entries. Duplicate attempt numbers are rejected. Zero attempts yields zero passes,
not an empty-denominator success. Preserve all attempts; the evaluator cannot
detect an operator omitting an earlier run. Model/budget declarations are retained,
not a claim of attested compute accounting.

## Development checks and research boundary

`node tests/benchmark_contract.cjs EXE SEVEN_ZIP` generates random diagnostic
grading data outside its analysis directory and exercises positive/negative
verification, missing inputs, tampering, fresh-directory checks, expansion bounds,
path rejection, duplicate attempts and 2025 exclusion. It does not execute a target,
read challenge answers, or count synthetic fixtures in the FLARE-On denominator.

Remaining corpus research is explicit: optionally acquire the three excluded payloads for a later version, confirm
official byte provenance, assess per-challenge environments, and independently
provision real verifiers. Those unknowns remain visible in catalogue/scoring rather
than being silently converted into support or solved status.

## Earlier development verification — before the active-set exclusion decision

- Earlier 119-entry catalogue: `out/flare-catalogue-hfiOuX/catalogue.json`, SHA-256 identity
  `daf7483a935100f17df9dbb18983696d94557ba664db0827fb199eb5e1343fec`.
  119 entries: 116 available for preparation, three unavailable. Availability
  means container listing succeeded, not that every environment is supported.
- Windows generated contract checks: 20 passed;
  `out/benchmark-contract-99VfYs/summary.json`.
- Real input preparation: 2014 C3 and 2022 C10 passed, including decomposed-Unicode
  archive/member names and the shared native atomic writer;
  `out/benchmark-prepare-5uKSpo/summary.json`. No target execution.
- Windows native rebuild: `out/benchmark-build-final.log`; existing harness,
  controller and HTTP regressions passed 3/3 in 11.56 seconds (60-second caps).
- Linux native build: `out/benchmark-linux-build.log`; native score invocation
  produced denominator 119, zero passes, and `all_solved:false` with no attempts:
  `out/benchmark-linux-score-result.json`. Linux archive extraction was not run;
  it requires an explicitly selected Linux 7-Zip worker.
- No new payload downloads, no solution retrieval, no 2025 imports, and no
  challenge solve claims were made by these checks. Logs/fixtures remain under
  ignored `out/`; the metadata catalogue and implementation are source files.
