#!/usr/bin/env python3
"""Build and exhaustively inspect the finite string sniper fixture corpus."""

from __future__ import annotations

import argparse
import base64
import collections
import json
import math
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from string_sniper_support import (
    Client,
    CaseResult,
    FIXTURE_COUNTS,
    Fixture,
    HarnessError,
    Results,
    Runner,
    StopSuite,
    equal,
    executable_path,
    list_value,
    object_value,
    require,
    row_key,
    semantic_row,
    validate_finding,
)


PAGE_SIZES = (1, 2, 3, 7, 16, 31, 32, 33, 64, 80, 81, 128)
SCAN_LIMITS = (1, 2, 3, 7, 16, 31, 32, 33, 64, 100000)
OUTPUT_BUDGETS = (4096, 8192, 16384, 32768, 65536, 262144)
TERMINAL_STATUSES = {
    "completed", "partial", "cancelled", "failed", "timeout", "unavailable", "interrupted",
}


def build_fixtures(runner: Runner, source: Path, build: Path, config: str) -> None:
    runner.checked(["cmake", "-S", str(source), "-B", str(build)])
    runner.checked(["cmake", "--build", str(build), "--config", config])


def find_binary(build: Path, config: str, name: str) -> Path:
    suffix = ".exe" if sys.platform == "win32" else ""
    filename = "indago_sniper_" + name + suffix
    candidates = [build / config / filename, build / filename]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise HarnessError(f"Missing binary {filename} under {build}")


def binary_format(fixture: Fixture) -> None:
    with fixture.binary.open("rb") as binary:
        magic = binary.read(4)
        if magic[:2] == b"MZ":
            binary.seek(0x3C)
            offset = int.from_bytes(binary.read(4), "little")
            require(64 <= offset < fixture.binary.stat().st_size - 4, "Invalid PE header offset")
            binary.seek(offset)
            equal(binary.read(4), b"PE\x00\x00", "PE signature")
        else:
            equal(magic, b"\x7fELF", "ELF signature")
    require(fixture.binary.stat().st_size > 1024, "Binary unexpectedly small")
    require(len(fixture.sha256) == 64, "Binary digest length")


def binary_contents(fixture: Fixture) -> None:
    data = fixture.binary.read_bytes()
    for identifier, value in fixture.arrays.items():
        marker = value.encode("ascii") + b"\x00"
        require(marker in data, f"Missing binary string: {identifier}")


def binary_output(runner: Runner, fixture: Fixture) -> None:
    command = runner.run([str(fixture.binary)])
    equal(command.returncode, 0, "Fixture exit code")
    equal(command.stderr, "", "Fixture stderr")
    equal(command.stdout.splitlines(), list(fixture.stdout_lines), "Every emitted marker")
    expected = collections.Counter(fixture.stdout_lines)
    actual = collections.Counter(command.stdout.splitlines())
    equal(actual, expected, "Output occurrence counts")


def index_rows(rows: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    return {row_key(row): semantic_row(row) for row in rows}


def encode_cursor(cursor: str, **changes: Any) -> str:
    padding = "=" * (-len(cursor) % 4)
    data = json.loads(base64.urlsafe_b64decode(cursor + padding))
    require(isinstance(data, dict), "Cursor payload must be an object")
    data.update(changes)
    raw = json.dumps(data).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class Suite:
    def __init__(self, client: Client, results: Results):
        self.client = client
        self.results = results
        self.baselines: dict[str, list[dict[str, Any]]] = {}
        self.pages: dict[str, list[dict[str, Any]]] = {}

    def baseline(self, fixture: Fixture) -> None:
        self.client.setup(fixture)
        rows, pages = self.client.collect(fixture)
        require(bool(rows), "No Ghidra findings")
        for row in rows:
            validate_finding(row, 0, check_score=row.get("value") in fixture.values)
        for page in pages:
            require(not page.get("output_truncated", False), "Baseline output truncated")
            require(not page["pagination"].get("scan_may_be_incomplete"), "Baseline scan incomplete")
        values: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
        for row in rows:
            values[row["value"]].append(row)
        missing = fixture.values - set(values)
        require(not missing, f"Ghidra did not define fixture strings: {sorted(missing)}")
        for marker in fixture.values:
            candidates = values[marker]
            require(any(row["xref_count"] >= 1 for row in candidates), f"No native reference: {marker[:80]}")
            for row in candidates:
                equal(row["length"], len(marker) + 1, "ASCII string storage length")
        self.baselines[fixture.name] = rows
        self.pages[fixture.name] = pages

    def threshold(self, fixture: Fixture, minimum: int) -> None:
        baseline = self.baselines[fixture.name]
        expected = [row for row in baseline if row["score"] >= minimum]
        rows, _ = self.client.collect(fixture, minimum=minimum)
        equal(index_rows(rows), index_rows(expected), f"Threshold {minimum} membership")
        for row in rows:
            validate_finding(row, minimum, check_score=row.get("value") in fixture.values)

    def default_threshold(self, fixture: Fixture) -> None:
        _, data = self.client.query(fixture)
        rows = list_value(data.get("findings"), "default findings")
        require(data["pagination"].get("next_cursor") is None, "Default page incomplete")
        expected = [row for row in self.baselines[fixture.name] if row["score"] >= 1]
        equal(index_rows(rows), index_rows(expected), "Default minimum score is one")

    def search(self, fixture: Fixture, search: str, minimum: int = 0) -> None:
        expected = [
            row for row in self.baselines[fixture.name]
            if search.lower() in row["value"].lower() and row["score"] >= minimum
        ]
        rows, _ = self.client.collect(fixture, minimum=minimum, search=search)
        equal(index_rows(rows), index_rows(expected), f"Search {search[:80]!r}")
        for row in rows:
            require(search.lower() in row["value"].lower(), "Search matched metadata instead of text")
            validate_finding(row, minimum, check_score=row.get("value") in fixture.values)

    def pagination(self, fixture: Fixture, page_size: int) -> None:
        rows, pages = self.client.collect(fixture, page_size=page_size)
        baseline = self.baselines[fixture.name]
        equal([semantic_row(row) for row in rows], [semantic_row(row) for row in baseline], "Stable page order")
        expected_pages = max(1, (len(baseline) + page_size - 1) // page_size)
        equal(len(pages), expected_pages, "Page count")
        for index, page in enumerate(pages):
            metadata = page["pagination"]
            equal(metadata["offset"], index * page_size, "Page offset")
            has_next = index < len(pages) - 1
            equal(metadata["next_cursor"] is not None, has_next, "Continuation presence")
            if has_next:
                equal(page["status"], "partial", "Intermediate page status")

    def filtered_pagination(self, fixture: Fixture) -> None:
        search = "fixture" if fixture.name not in ("ranking", "pagination", "references") else fixture.name
        rows, _ = self.client.collect(fixture, minimum=4, search=search, page_size=3)
        expected = [row for row in self.baselines[fixture.name] if row["score"] >= 4 and search in row["value"].lower()]
        equal(index_rows(rows), index_rows(expected), "Combined filters across pages")

    def scan_limit(self, fixture: Fixture, limit: int) -> None:
        rows, pages = self.client.collect(fixture, scan_limit=limit, page_size=3)
        baseline = index_rows(self.baselines[fixture.name])
        equal(len(rows), min(limit, len(baseline)), "Accepted candidate cap")
        for row in rows:
            equal(semantic_row(row), baseline[row_key(row)], "Bounded scan candidate")
        for page in pages:
            metadata = page["pagination"]
            equal(metadata["scan_limit"], limit, "Reported scan limit")
            equal(metadata["scan_may_be_incomplete"], len(rows) >= limit, "Scan completeness flag")

    def reference_details(self, fixture: Fixture) -> None:
        marker = fixture.arrays["shared_marker"]
        rows = [row for row in self.baselines[fixture.name] if row["value"] == marker]
        equal(len(rows), 1, "Shared string identity")
        row = rows[0]
        require(row["xref_count"] >= 40, "Not all forty direct references recovered")
        equal(len(row["xrefs"]), 32, "Reference detail cap")
        equal(row["xrefs_truncated"], True, "Reference truncation flag")
        allowed = {f"reference_{index:02d}" for index in range(40)}
        names: set[str] = set()
        for ref in row["xrefs"]:
            function = object_value(ref.get("function"), "Reference containing function")
            require(function.get("name") in allowed, f"Unexpected referencing function: {function}")
            names.add(function["name"])
        equal(len(names), 32, "Distinct reference functions")

    def ranking_groups(self, fixture: Fixture) -> None:
        values = {row["value"]: row for row in self.baselines[fixture.name]}
        lows = [values[value]["score"] for key, value in fixture.arrays.items() if key.startswith("low_")]
        mediums = [values[value]["score"] for key, value in fixture.arrays.items() if key.startswith("medium_")]
        highs = [values[value]["score"] for key, value in fixture.arrays.items() if key.startswith("high_")]
        equal(len(lows), 24, "Low-score marker coverage")
        equal(len(mediums), 12, "Medium-score marker coverage")
        equal(len(highs), 12, "High-score marker coverage")
        require(max(lows) < min(mediums), "Low and medium score separation")
        require(max(mediums) < min(highs), "Medium and high score separation")
        _, data = self.client.query(fixture, arguments={"minimum_score": 0}, budget={"max_items": 1})
        equal(data["findings"][0]["score"], max(row["score"] for row in values.values()), "Top result ranks across candidates")

    def cli_query(self, fixture: Fixture, minimum: int) -> None:
        command = self.client.invoke(
            "query", "--project", self.client.projects[fixture.name],
            "--target-id", self.client.targets[fixture.name],
            "--backend", "ghidra", "--operation", "string_sniper",
            "--minimum-score", str(minimum), "--max-items", "4096",
            "--max-output-bytes", str(16 * 1024 * 1024),
            "--timeout-ms", str(self.client.wall_ms),
        )
        envelope = command.json()
        equal(envelope.get("status"), "completed", "CLI query status")
        equal(command.returncode, 0, "CLI success exit code")
        data = object_value(envelope.get("data"), "CLI native data")
        expected = [row for row in self.baselines[fixture.name] if row["score"] >= minimum]
        equal(index_rows(data["findings"]), index_rows(expected), "CLI score forwarding")

    def reject(self, fixture: Fixture, arguments: dict[str, Any] | None = None,
               budget: dict[str, Any] | None = None, operation: str = "string_sniper") -> None:
        request = self.client.request(fixture, operation=operation, arguments=arguments or {}, budget=budget or {})
        command = self.client.action(request)
        require(command.returncode in (1, 2), "Invalid request must fail without crashing")
        envelope = command.json()
        require(envelope.get("status") in {"failed", "invalid_request"}, "Invalid request was not rejected")
        native = envelope.get("data", {})
        diagnostic = envelope.get("diagnostic") or native.get("diagnostic")
        require(isinstance(diagnostic, str) and bool(diagnostic.strip()), "Rejection has no diagnostic")

    def first_cursor(self, fixture: Fixture) -> str:
        _, data = self.client.query(fixture, arguments={"minimum_score": 0}, budget={"max_items": 1})
        cursor = data["pagination"].get("next_cursor")
        require(isinstance(cursor, str), "Need at least two findings for cursor checks")
        return cursor

    def cursor_replay(self, fixture: Fixture) -> None:
        cursor = self.first_cursor(fixture)
        arguments = {"minimum_score": 0, "cursor": cursor}
        _, first = self.client.query(fixture, arguments=arguments, budget={"max_items": 3})
        _, second = self.client.query(fixture, arguments=arguments, budget={"max_items": 3})
        equal(index_rows(first["findings"]), index_rows(second["findings"]), "Cursor replay")
        equal(first["pagination"], second["pagination"], "Cursor replay pagination")
        baseline = self.baselines[fixture.name][1:4]
        equal(index_rows(first["findings"]), index_rows(baseline), "Changing page size with same cursor")

    def cursor_binding(self, fixture: Fixture, mutation: str) -> None:
        cursor = self.first_cursor(fixture)
        args: dict[str, Any] = {"minimum_score": 0, "cursor": cursor}
        operation = "string_sniper"
        if mutation == "score":
            args["minimum_score"] = 1
        elif mutation == "search":
            args["search"] = "fixture"
        elif mutation == "collection":
            args["collection"] = "strings"
        elif mutation == "operation":
            operation = "strings"
        elif mutation == "profile":
            args["profile"] = "inventory"
        elif mutation == "revision":
            args["cursor"] = encode_cursor(cursor, revision=2**62)
        elif mutation == "binding":
            args["cursor"] = encode_cursor(cursor, binding="invalid")
        elif mutation == "negative_offset":
            args["cursor"] = encode_cursor(cursor, offset=-1)
        elif mutation == "huge_offset":
            args["cursor"] = encode_cursor(cursor, offset=100000)
        else:
            raise HarnessError(f"Unknown cursor mutation: {mutation}")
        self.reject(fixture, arguments=args, operation=operation)

    def output_budget(self, fixture: Fixture, budget: int) -> None:
        request = self.client.request(fixture, arguments={"minimum_score": 0}, budget={"output_bytes": budget, "max_items": 1})
        command = self.client.action(request)
        envelope = command.json()
        require(envelope.get("status") in {"completed", "partial"}, "Budget query failed")
        equal(command.returncode, 0 if envelope["status"] == "completed" else 3, "Budget query exit code")
        equal(envelope.get("artifact_sha256"), fixture.sha256, "Budget query artifact")
        require(len(command.stdout.encode("utf-8")) <= budget + 1, "CLI output exceeded byte budget")
        if envelope.get("data_omitted"):
            require(bool(envelope.get("evidence_ids")), "Omitted data must be retained in evidence")
            require(bool(envelope.get("diagnostics")), "Omitted data needs a diagnostic")
            return
        data = object_value(envelope.get("data"), "Budget native data")
        if data.get("output_truncated"):
            equal(data.get("status"), "partial", "Output truncation status")
        for row in data.get("findings", []):
            validate_finding(row, 0, full_text=False)
            original = index_rows(self.baselines[fixture.name])[row_key(row)]
            require(original["value"].startswith(row["value"]), "Truncated text is not a prefix")
            equal(row["score"], original["score"], "Score changed with output budget")

    def long_text(self, fixture: Fixture) -> None:
        marker = fixture.arrays["long_marker"]
        _, data = self.client.query(
            fixture,
            arguments={"minimum_score": 0, "search": "long42"},
            budget={"output_bytes": 16384, "max_items": 1},
        )
        rows = list_value(data.get("findings"), "Long-text findings")
        equal(len(rows), 1, "Long string survives bounded output")
        row = rows[0]
        equal(row["text_truncated"], True, "Long-text truncation flag")
        require(0 < len(row["value"]) < len(marker), "Long text shortened")
        require(marker.startswith(row["value"]), "Long text prefix")
        equal(row["length"], len(marker) + 1, "Untruncated native storage length")
        original = next(row for row in self.baselines[fixture.name] if row["value"] == marker)
        equal(row["score"], original["score"], "Long string scored before shortening")
        equal(row["tags"], original["tags"], "Long string tags preserved")

    def cross_artifact_cursor(self, first: Fixture, second: Fixture) -> None:
        cursor = self.first_cursor(first)
        self.reject(second, arguments={"minimum_score": 0, "cursor": cursor})

    def close_reopen(self, fixture: Fixture) -> None:
        command = self.client.action(self.client.request(fixture, operation="close"))
        envelope = command.json()
        equal(envelope.get("status"), "completed", "Session close")
        rows, _ = self.client.collect(fixture)
        equal(index_rows(rows), index_rows(self.baselines[fixture.name]), "Persisted analysis after reopen")

    def cancellation(self, fixture: Fixture) -> None:
        request = self.client.request(fixture, arguments={"minimum_score": 0})
        submitted = self.client.action(request, submit=True)
        equal(submitted.returncode, 0, "Asynchronous submit")
        job = submitted.json()
        identifier = job.get("id")
        require(isinstance(identifier, str), "Submitted job ID")
        project = self.client.projects[fixture.name]
        cancelled = self.client.invoke("job", "cancel", "--project", project, "--id", identifier)
        equal(cancelled.returncode, 0, "Cancellation request")
        deadline = time.monotonic() + self.client.runner.timeout
        while time.monotonic() < deadline:
            shown = self.client.invoke("job", "show", "--project", project, "--id", identifier)
            equal(shown.returncode, 0, "Job status")
            jobs = shown.json().get("jobs")
            require(isinstance(jobs, list) and len(jobs) == 1, "Job lookup")
            status = jobs[0].get("status")
            if status in TERMINAL_STATUSES:
                require(status in {"cancelled", "completed", "partial"}, f"Cancellation job ended {status}")
                if status == "cancelled":
                    return
                require(jobs[0].get("result") is not None, "Completion race has no result")
                return
            time.sleep(0.1)
        raise HarnessError("Cancelled job never reached a terminal state")

    def execute(self, fixtures: list[Fixture], phases: set[str]) -> None:
        ready: list[Fixture] = []
        for fixture in fixtures:
            if self.results.run(f"{fixture.name}/baseline", lambda f=fixture: self.baseline(f)):
                ready.append(fixture)
        for fixture in ready:
            self.fixture_cases(fixture, phases)
        if "cursors" in phases and len(ready) > 1:
            first, second = ready[:2]
            self.results.run("cursors/cross-artifact", lambda: self.cross_artifact_cursor(first, second))

    def fixture_cases(self, fixture: Fixture, phases: set[str]) -> None:
        run = self.results.run
        prefix = fixture.name + "/"
        if "scores" in phases:
            run(prefix + "default-score", lambda: self.default_threshold(fixture))
            for minimum in range(101):
                run(prefix + f"score/{minimum}", lambda m=minimum: self.threshold(fixture, m))
            for minimum in (0, 1, 4, 100):
                run(prefix + f"cli/{minimum}", lambda m=minimum: self.cli_query(fixture, m))
        if "search" in phases:
            searches = {"", "absent-marker-75d913", "url", "referenced", "fixture", "42", "../", "api_key", "https://"}
            for marker in fixture.values:
                searches.update((marker, marker.upper(), marker.lower(), marker[:12]))
            for index, search in enumerate(sorted(searches)):
                run(prefix + f"search/{index}", lambda s=search: self.search(fixture, s))
            for minimum in (1, 4, 8, 20, 100):
                run(prefix + f"search-score/{minimum}", lambda m=minimum: self.search(fixture, "42", m))
        if "pagination" in phases:
            for size in PAGE_SIZES:
                run(prefix + f"page/{size}", lambda s=size: self.pagination(fixture, s))
            run(prefix + "filtered-pages", lambda: self.filtered_pagination(fixture))
            for limit in SCAN_LIMITS:
                run(prefix + f"scan/{limit}", lambda n=limit: self.scan_limit(fixture, n))
        if "cursors" in phases:
            run(prefix + "cursor-replay", lambda: self.cursor_replay(fixture))
            mutations = ("score", "search", "collection", "operation", "profile", "revision", "binding", "negative_offset", "huge_offset")
            for mutation in mutations:
                run(prefix + "cursor/" + mutation, lambda m=mutation: self.cursor_binding(fixture, m))
        if "validation" in phases:
            self.validation_cases(fixture)
        if "budgets" in phases:
            for budget in OUTPUT_BUDGETS:
                run(prefix + f"output/{budget}", lambda b=budget: self.output_budget(fixture, b))
            if fixture.name == "pagination":
                run(prefix + "long-text", lambda: self.long_text(fixture))
        if "lifecycle" in phases:
            run(prefix + "close-reopen", lambda: self.close_reopen(fixture))
            run(prefix + "cancellation", lambda: self.cancellation(fixture))
        if fixture.name == "references":
            run(prefix + "forty-references", lambda: self.reference_details(fixture))
        if fixture.name == "ranking":
            run(prefix + "ranking-groups", lambda: self.ranking_groups(fixture))

    def validation_cases(self, fixture: Fixture) -> None:
        prefix = fixture.name + "/invalid/"
        run = self.results.run
        bad_scores = (-1, 101, True, False, 1.5, "4", None, [], {})
        for index, value in enumerate(bad_scores):
            run(prefix + f"score/{index}", lambda v=value: self.reject(fixture, arguments={"minimum_score": v}))
        for limit in (0, -1, 100001):
            run(prefix + f"scan/{limit}", lambda n=limit: self.reject(fixture, arguments={"scan_limit": n}))
        for cursor in ("not-base64!", "e30", "", "x" * 2049):
            run(prefix + f"cursor/{len(cursor)}", lambda c=cursor: self.reject(fixture, arguments={"cursor": c}))
        for field, values in {
            "max_items": (0, -1, 100001, True, "1"),
            "output_bytes": (0, 4095, 67108865, True, "4096"),
            "wall_ms": (0, -1, 3600001, True, "1"),
            "memory_bytes": (0, 1048575, 2147483649, True, "1"),
        }.items():
            for index, value in enumerate(values):
                run(prefix + f"budget/{field}/{index}", lambda k=field, v=value: self.reject(fixture, budget={k: v}))
        run(prefix + "unknown-argument", lambda: self.reject(fixture, arguments={"unknown_sniper_argument": 1}))
        run(prefix + "unknown-operation", lambda: self.reject(fixture, operation="unknown_sniper_operation"))
        run(prefix + "invalid-profile", lambda: self.reject(fixture, arguments={"profile": "missing"}))
        run(prefix + "invalid-collection", lambda: self.reject(fixture, arguments={"collection": "missing"}))


ALL_PHASES = {"scores", "search", "pagination", "cursors", "validation", "budgets", "lifecycle"}


def parse_arguments() -> argparse.Namespace:
    repo = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("binaries", "full"), default="full")
    parser.add_argument("--indago", help="Indago executable; required for full mode")
    parser.add_argument("--build-dir", type=Path, default=repo / "out/string-sniper-fixtures")
    parser.add_argument("--report-dir", type=Path, default=repo / "out/string-sniper-harness")
    parser.add_argument("--config", default="Debug")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--fixture", action="append", choices=tuple(FIXTURE_COUNTS))
    parser.add_argument("--phase", action="append", choices=tuple(sorted(ALL_PHASES)))
    parser.add_argument("--timeout", type=float, default=300.0, help="Timeout per command, in seconds")
    parser.add_argument("--wall-ms", type=int, default=120000, help="Ghidra request budget")
    parser.add_argument("--fail-fast", action="store_true")
    args = parser.parse_args()
    if args.mode == "full" and not args.indago:
        parser.error("--indago is required for full mode")
    if not 1 <= args.wall_ms <= 3600000:
        parser.error("--wall-ms must be between 1 and 3600000")
    if args.timeout <= args.wall_ms / 1000 and args.mode == "full":
        parser.error("--timeout must exceed --wall-ms in seconds")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be positive")
    return args


def preflight(client: Client) -> None:
    command = client.invoke("capabilities")
    if command.returncode:
        raise HarnessError("Indago capabilities failed")
    backends = command.json().get("backends", [])
    ghidra = next((row for row in backends if row.get("name") == "ghidra"), None)
    if not ghidra or not ghidra.get("available"):
        raise HarnessError("Ghidra is unavailable; configure GHIDRA_HOME or bundle Ghidra")
    if "string_sniper" not in ghidra.get("operations", []):
        raise HarnessError("This Indago executable does not support string_sniper")


def main() -> int:
    args = parse_arguments()
    repo = Path(__file__).resolve().parents[1]
    source = repo / "tests/fixtures/string_sniper"
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:8]
    directory = args.report_dir.expanduser().resolve() / run_id
    runner = Runner(directory / "commands", args.timeout)
    results = Results(args.fail_fast)
    metadata = {"mode": args.mode, "run_id": run_id, "phases": sorted(args.phase or ALL_PHASES)}
    client: Client | None = None
    fixtures: list[Fixture] = []
    try:
        build = args.build_dir.expanduser().resolve()
        if not args.no_build:
            build_fixtures(runner, source, build, args.config)
        for name in dict.fromkeys(args.fixture or FIXTURE_COUNTS):
            binary = find_binary(build, args.config, name)
            fixture = Fixture.load(name, source, binary)
            fixtures.append(fixture)
            results.run(name + "/binary-format", lambda f=fixture: binary_format(f))
            results.run(name + "/binary-contents", lambda f=fixture: binary_contents(f))
            results.run(name + "/binary-output", lambda f=fixture: binary_output(runner, f))
        metadata["artifacts"] = {fixture.name: {"binary": str(fixture.binary), "sha256": fixture.sha256} for fixture in fixtures}
        if args.mode == "full":
            executable = executable_path(args.indago)
            client = Client(executable, directory / "workspace", runner, args.wall_ms)
            preflight(client)
            suite = Suite(client, results)
            suite.execute(fixtures, set(args.phase or ALL_PHASES))
    except StopSuite:
        pass
    except Exception as error:
        results.cases.append(CaseResult("harness", "error", 0.0, str(error)))
        print(f"ERROR harness: {error}", file=sys.stderr)
    finally:
        results.fail_fast = False
        if client is not None:
            for fixture in fixtures:
                if fixture.name not in client.projects:
                    continue
                def close(f: Fixture = fixture) -> None:
                    command = client.action(client.request(f, operation="close"))
                    equal(command.json().get("status"), "completed", "Final session close")
                results.run(fixture.name + "/cleanup-close", close)
        report = directory / "report.json"
        results.write(report, runner, metadata)
        print(f"Report: {report}", flush=True)
    return results.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
