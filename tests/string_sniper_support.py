"""Standard-library support for the standalone string sniper harness."""

from __future__ import annotations

import ast
import collections
import dataclasses
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import traceback
from pathlib import Path
from typing import Any, Callable


FIXTURE_COUNTS = {
    "network": 40,
    "credentials": 42,
    "paths": 40,
    "ranking": 48,
    "references": 1,
    "pagination": 81,
}
TAG_WEIGHTS = {
    "url": 4,
    "ip_address": 4,
    "filesystem_path": 3,
    "credential_keyword": 5,
    "configuration_path": 3,
    "execution_path": 4,
    "mixed_alphanumeric": 1,
}
SUCCESS_STATUSES = {"completed", "partial"}
ARRAY_PATTERN = re.compile(
    r"static\s+const\s+char\s+(\w+)\s*\[\s*\]\s*=\s*"
    r'((?:"(?:\\.|[^"\\])*"\s*)+);',
    re.MULTILINE,
)
LITERAL_PATTERN = re.compile(r'"(?:\\.|[^"\\])*"')


class HarnessError(RuntimeError):
    """An infrastructure error, distinct from a failed assertion."""


class StopSuite(RuntimeError):
    """Stop after recording a failure while still allowing report cleanup."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def equal(actual: Any, expected: Any, message: str) -> None:
    if actual != expected:
        raise AssertionError(f"{message}: expected {expected!r}, got {actual!r}")


def integer(value: Any, label: str, minimum: int = 0) -> int:
    require(type(value) is int, f"{label} must be an integer")
    require(value >= minimum, f"{label} must be >= {minimum}")
    return value


def object_value(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def list_value(value: Any, label: str) -> list[Any]:
    require(isinstance(value, list), f"{label} must be an array")
    return value


def address(value: Any, label: str) -> str:
    require(isinstance(value, str), f"{label} must be a string")
    require(re.fullmatch(r"0x[0-9a-fA-F]+", value) is not None, label)
    require(int(value, 16) < 2**64, f"{label} exceeds 64 bits")
    return value


def location(value: Any, label: str) -> tuple[str, str]:
    row = object_value(value, label)
    addr = address(row.get("address"), f"{label}.address")
    space = row.get("address_space")
    require(isinstance(space, str) and bool(space), f"{label}.address_space")
    return space, addr


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def executable_path(value: str) -> Path:
    found = shutil.which(value)
    candidate = Path(found or value).expanduser().resolve()
    if not candidate.is_file():
        raise HarnessError(f"Executable not found: {value}")
    if os.name != "nt" and not os.access(candidate, os.X_OK):
        raise HarnessError(f"Executable is not executable: {candidate}")
    return candidate


@dataclasses.dataclass(frozen=True)
class Fixture:
    name: str
    source: Path
    binary: Path
    arrays: dict[str, str]
    stdout_lines: tuple[str, ...]

    @property
    def values(self) -> set[str]:
        return set(self.arrays.values())

    @property
    def sha256(self) -> str:
        return digest_file(self.binary)

    @classmethod
    def load(cls, name: str, source_dir: Path, binary: Path) -> Fixture:
        source = source_dir / f"{name}.c"
        text = source.read_text(encoding="utf-8")
        arrays: dict[str, str] = {}
        for match in ARRAY_PATTERN.finditer(text):
            identifier, literals = match.groups()
            require(identifier not in arrays, f"Duplicate array {identifier}")
            pieces = LITERAL_PATTERN.findall(literals)
            decoded = [ast.literal_eval(piece) for piece in pieces]
            require(all(isinstance(piece, str) for piece in decoded), identifier)
            arrays[identifier] = "".join(decoded)
        equal(len(arrays), FIXTURE_COUNTS[name], f"{name} array coverage")
        equal(len(set(arrays.values())), len(arrays), f"{name} unique markers")
        for identifier, value in arrays.items():
            require("\x00" not in value, f"{identifier} contains embedded NUL")
            require("\n" not in value, f"{identifier} contains embedded newline")
            require(value.isascii(), f"{identifier} must remain ASCII")
        references = re.findall(r"puts\s*\(\s*(\w+)\s*\)", text)
        require(bool(references), f"{name} has no direct puts references")
        equal(set(references), set(arrays), f"{name} referenced arrays")
        output = tuple(arrays[identifier] for identifier in references)
        if name == "references":
            equal(len(output), 40, "Reference fixture call coverage")
        return cls(name, source, binary, arrays, output)


def expected_tags(value: str, reference_count: int) -> set[str]:
    """An independent oracle over ASCII marker contents and native counts."""
    lower = value.lower()
    tags: set[str] = set()
    if re.search(r"https?://\S+", lower, re.ASCII):
        tags.add("url")
    if re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lower, re.ASCII):
        tags.add("ip_address")
    if re.search(r"[a-z]:\\|/etc/|/var/|/tmp/|\\\\[^\\]+\\[^\\]+", lower):
        tags.add("filesystem_path")
    if re.search(r"password|passwd|token|secret|credential|api[_-]?key", lower):
        tags.add("credential_keyword")
    if re.search(r"software\\|currentversion\\|\.\./|\.\.\\", lower):
        tags.add("configuration_path")
    if re.search(r"\bcmd\.exe\b|\bpowershell\b|/bin/(?:sh|bash)\b|\bsystem32\b", lower):
        tags.add("execution_path")
    if len(value) >= 8 and re.search(r"[A-Za-z]", value) and re.search(r"[0-9]", value):
        tags.add("mixed_alphanumeric")
    if reference_count:
        tags.add("referenced")
    return tags


def expected_score(tags: set[str], reference_count: int) -> int:
    score = sum(TAG_WEIGHTS.get(tag, 0) for tag in tags)
    return score + min(3, reference_count)


def row_key(row: dict[str, Any]) -> tuple[str, str]:
    return location(row.get("location"), "finding.location")


def semantic_row(row: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "location", "value", "length", "type", "text_truncated", "score",
        "tags", "xrefs", "xref_count", "xrefs_truncated", "triage",
    )
    return {key: row.get(key) for key in keys}


def validate_finding(row: Any, minimum: int, full_text: bool = True,
                     check_score: bool = True) -> None:
    row = object_value(row, "finding")
    row_key(row)
    value = row.get("value")
    require(isinstance(value, str), "finding.value must be a string")
    require(isinstance(row.get("type"), str), "finding.type must be a string")
    integer(row.get("length"), "finding.length", 1)
    score = integer(row.get("score"), "finding.score")
    require(score >= minimum, "Finding below score threshold")
    tags = list_value(row.get("tags"), "finding.tags")
    require(all(isinstance(tag, str) for tag in tags), "Non-string tag")
    equal(len(set(tags)), len(tags), "Duplicate tags")
    allowed = set(TAG_WEIGHTS) | {"referenced"}
    require(set(tags) <= allowed, f"Unknown tags: {set(tags) - allowed}")
    count = integer(row.get("xref_count"), "finding.xref_count")
    refs = list_value(row.get("xrefs"), "finding.xrefs")
    require(len(refs) <= 32, "More than 32 reference details")
    require(count >= len(refs), "Reference count smaller than details")
    equal(row.get("xrefs_truncated"), count > len(refs), "Reference truncation")
    require(type(row.get("text_truncated")) is bool, "Text truncation flag")
    require("heuristic lead" in row.get("triage", ""), "Missing triage caveat")
    if full_text:
        equal(row["text_truncated"], False, "Unexpected truncated text")
        if check_score and value.isascii():
            oracle = expected_tags(value, count)
            equal(set(tags), oracle, f"Tags for {value[:80]!r}")
            equal(score, expected_score(oracle, count), "Additive score")
    for ref in refs:
        ref = object_value(ref, "xref")
        address(ref.get("from"), "xref.from")
        equal(ref.get("to"), row["location"]["address"], "Reference destination")
        location(ref.get("from_location"), "xref.from_location")
        equal(location(ref.get("to_location"), "xref.to_location"), row_key(row), "Reference location")
        equal(ref.get("direction"), "incoming", "Reference direction")
        require(isinstance(ref.get("kind"), str), "Reference kind")
        require(type(ref.get("operand")) is int, "Reference operand")
        require(type(ref.get("call")) is bool, "Reference call flag")
        if "function" in ref:
            function = object_value(ref["function"], "xref.function")
            address(function.get("entry"), "function.entry")
            require(isinstance(function.get("name"), str), "Function name")
            require(isinstance(function.get("signature"), str), "Function signature")
            location(function.get("location"), "function.location")


@dataclasses.dataclass
class Command:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed: float

    def json(self) -> dict[str, Any]:
        try:
            value = json.loads(self.stdout)
        except json.JSONDecodeError as error:
            raise HarnessError(f"Invalid command JSON: {self.argv}: {error}") from error
        return object_value(value, "command JSON")


class Runner:
    def __init__(self, directory: Path, timeout: float):
        self.directory = directory
        self.timeout = timeout
        self.commands: list[dict[str, Any]] = []
        directory.mkdir(parents=True, exist_ok=True)

    def run(self, argv: list[str], cwd: Path | None = None) -> Command:
        index = len(self.commands)
        stem = self.directory / f"command-{index:06d}"
        started = time.monotonic()
        record: dict[str, Any] = {"argv": argv, "cwd": str(cwd) if cwd else None}
        self.commands.append(record)
        try:
            process = subprocess.run(
                argv,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            stdout = (error.stdout or b"").decode("utf-8", errors="replace")
            stderr = (error.stderr or b"").decode("utf-8", errors="replace")
            stem.with_suffix(".stdout").write_text(stdout, encoding="utf-8")
            stem.with_suffix(".stderr").write_text(stderr, encoding="utf-8")
            record.update(error=str(error), elapsed=time.monotonic() - started, log=str(stem))
            raise HarnessError(f"Command timed out: {argv}") from error
        except OSError as error:
            record["error"] = str(error)
            raise HarnessError(f"Command could not finish: {argv}: {error}") from error
        stdout = process.stdout.decode("utf-8", errors="replace")
        stderr = process.stderr.decode("utf-8", errors="replace")
        stem.with_suffix(".stdout").write_text(stdout, encoding="utf-8")
        stem.with_suffix(".stderr").write_text(stderr, encoding="utf-8")
        elapsed = time.monotonic() - started
        record.update(returncode=process.returncode, elapsed=elapsed, log=str(stem))
        return Command(argv, process.returncode, stdout, stderr, elapsed)

    def checked(self, argv: list[str], cwd: Path | None = None) -> Command:
        command = self.run(argv, cwd)
        if command.returncode:
            raise HarnessError(f"Command failed ({command.returncode}): {argv}\n{command.stderr}")
        return command


class Client:
    def __init__(self, executable: Path, workspace: Path, runner: Runner, wall_ms: int):
        self.executable = executable
        self.workspace = workspace
        self.runner = runner
        self.wall_ms = wall_ms
        self.projects: dict[str, str] = {}
        self.targets: dict[str, str] = {}
        self.requests = 0

    def invoke(self, *args: str) -> Command:
        return self.runner.run([str(self.executable), "--workspace", str(self.workspace), *args])

    def setup(self, fixture: Fixture) -> None:
        project = "sniper_" + fixture.name
        created = self.invoke("project", "create", "--name", project)
        equal(created.returncode, 0, "Project creation")
        created.json()
        imported = self.invoke("target", "import", "--project", project, "--file", str(fixture.binary))
        equal(imported.returncode, 0, "Target import")
        data = imported.json()
        equal(data.get("artifact_sha256"), fixture.sha256, "Imported target digest")
        require(isinstance(data.get("id"), str), "Imported target ID")
        self.projects[fixture.name] = project
        self.targets[fixture.name] = data["id"]

    def request(self, fixture: Fixture, operation: str = "string_sniper", **options: Any) -> dict[str, Any]:
        arguments = {"profile": "standard"}
        arguments.update(options.pop("arguments", {}))
        budget = {
            "wall_ms": self.wall_ms,
            "output_bytes": 16 * 1024 * 1024,
            "memory_bytes": 2 * 1024 * 1024 * 1024,
            "max_items": 4096,
        }
        budget.update(options.pop("budget", {}))
        require(not options, f"Unknown request options: {options}")
        return {
            "schema": "indago.action.v1",
            "project": self.projects[fixture.name],
            "target_id": self.targets[fixture.name],
            "backend": "ghidra",
            "operation": operation,
            "budget": budget,
            "arguments": arguments,
        }

    def action(self, request: dict[str, Any], submit: bool = False) -> Command:
        self.requests += 1
        path = self.runner.directory / f"request-{self.requests:06d}.json"
        path.write_text(json.dumps(request, indent=2), encoding="utf-8")
        verb = "submit" if submit else "run"
        return self.invoke("action", verb, "--request", str(path))

    def query(self, fixture: Fixture, **options: Any) -> tuple[Command, dict[str, Any]]:
        command = self.action(self.request(fixture, **options))
        envelope = command.json()
        require(envelope.get("status") in SUCCESS_STATUSES, f"Query failed: {envelope}")
        expected_exit = 0 if envelope["status"] == "completed" else 3
        equal(command.returncode, expected_exit, "Query process exit code")
        equal(envelope.get("backend"), "ghidra", "Envelope backend")
        equal(envelope.get("artifact_sha256"), fixture.sha256, "Envelope digest")
        require(not envelope.get("data_omitted", False), "Native data omitted")
        data = object_value(envelope.get("data"), "native data")
        equal(data.get("schema"), "indago.ghidra-result.v2", "Native schema")
        equal(data.get("status"), envelope["status"], "Native and envelope statuses")
        equal(data.get("operation"), "string_sniper", "Native operation")
        program = object_value(data.get("program"), "native program")
        equal(program.get("executable_sha256"), fixture.sha256, "Program digest")
        require(not data.get("analysis_timed_out"), "Initial analysis timed out")
        return command, data

    def collect(self, fixture: Fixture, minimum: int = 0, search: str | None = None,
                page_size: int = 4096, scan_limit: int = 100000) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        rows: list[dict[str, Any]] = []
        pages: list[dict[str, Any]] = []
        cursors: set[str] = set()
        cursor: str | None = None
        revision: int | None = None
        while True:
            args: dict[str, Any] = {"minimum_score": minimum, "scan_limit": scan_limit}
            if search is not None:
                args["search"] = search
            if cursor is not None:
                args["cursor"] = cursor
            _, data = self.query(fixture, arguments=args, budget={"max_items": page_size})
            page = list_value(data.get("findings"), "findings")
            metadata = object_value(data.get("pagination"), "pagination")
            equal(metadata.get("collection"), "findings", "Pagination collection")
            equal(metadata.get("offset"), len(rows), "Pagination offset")
            equal(metadata.get("returned"), len(page), "Pagination count")
            require(len(page) <= page_size, "Page exceeds max_items")
            current = integer(metadata.get("program_revision"), "program revision")
            if revision is not None:
                equal(current, revision, "Revision changed while paging")
            revision = current
            rows.extend(page)
            pages.append(data)
            cursor = metadata.get("next_cursor")
            if cursor is None:
                break
            require(isinstance(cursor, str) and bool(cursor), "Invalid continuation")
            require(cursor not in cursors, "Repeated cursor")
            require(bool(page), "Continuation without progress")
            require(len(rows) < 100000, "Pagination exceeds scan bound")
            cursors.add(cursor)
        keys = [row_key(row) for row in rows]
        equal(len(keys), len(set(keys)), "Duplicate finding across pages")
        scores = [row["score"] for row in rows]
        equal(scores, sorted(scores, reverse=True), "Descending score order")
        return rows, pages


@dataclasses.dataclass
class CaseResult:
    name: str
    status: str
    elapsed: float
    diagnostic: str = ""


class Results:
    def __init__(self, fail_fast: bool = False):
        self.cases: list[CaseResult] = []
        self.fail_fast = fail_fast

    def run(self, name: str, function: Callable[[], None]) -> bool:
        started = time.monotonic()
        try:
            function()
        except Exception as error:
            status = "failed" if isinstance(error, AssertionError) else "error"
            diagnostic = str(error)
            if status == "error":
                diagnostic += "\n" + traceback.format_exc()
            self.cases.append(CaseResult(name, status, time.monotonic() - started, diagnostic))
            print(f"{status.upper()} {name}: {error}", flush=True)
            if self.fail_fast:
                raise StopSuite(name) from error
            return False
        self.cases.append(CaseResult(name, "passed", time.monotonic() - started))
        print(f"PASS {name}", flush=True)
        return True

    def write(self, path: Path, runner: Runner, metadata: dict[str, Any]) -> None:
        counts = collections.Counter(case.status for case in self.cases)
        payload = {
            "schema": "indago.string-sniper-harness.v1",
            "metadata": metadata,
            "counts": dict(counts),
            "cases": [dataclasses.asdict(case) for case in self.cases],
            "commands": runner.commands,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @property
    def exit_code(self) -> int:
        if any(case.status == "error" for case in self.cases):
            return 2
        if any(case.status == "failed" for case in self.cases):
            return 1
        return 0
