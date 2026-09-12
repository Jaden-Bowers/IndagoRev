"""Summarize local controller experiments without copying credentials or prompts."""
import argparse
import json
import sqlite3
from pathlib import Path


def summarize(directory):
    directory = Path(directory).resolve()
    database = directory / "workspace" / "indago-native.sqlite3"
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        run = json.loads(connection.execute("SELECT record FROM wb_model_runs").fetchone()[0])
        investigation = json.loads(connection.execute("SELECT record FROM wb_investigations").fetchone()[0])
        generations = [json.loads(row[0]) for row in connection.execute(
            "SELECT record FROM wb_events WHERE kind='model.generation' ORDER BY sequence")]
        actions = [json.loads(row[0]) for row in connection.execute(
            "SELECT record FROM wb_investigation_actions ORDER BY id")]
    requests = [event["request_bytes"] for event in generations if "request_bytes" in event]
    usage = [event.get("usage", {}) for event in generations]
    turns = run.get("investigation_state", {}).get("turns", [])
    report = investigation.get("report", {})
    grade_path = directory / "independent-grade.json"
    grade = json.loads(grade_path.read_text(encoding="utf-8")) if grade_path.exists() else {}
    return {
        "run": directory.name,
        "model": investigation["owner"]["profile"]["model"],
        "providers": sorted({str(event.get("served_provider", "unreported")) for event in generations}),
        "artifact_sha256": investigation["artifact_sha256"],
        "status": investigation["status"],
        "controller_phase": run.get("phase"),
        "recipe": run.get("recipe"),
        "max_generations": run.get("max_generations"),
        "profile": {key: investigation["owner"]["profile"].get(key) for key in (
            "profile_sha256", "provider_order", "context_tokens", "output_tokens",
            "generation_ms", "reasoning_effort", "tool_payload_encoding")},
        "native_budget": investigation.get("budget"),
        "native_reserved": investigation.get("reserved"),
        "generations_reserved": run.get("generations"),
        "valid_responses_logged": len(generations),
        "native_actions": len(actions),
        "native_operations": sorted({action["request"]["backend"] + "/" + action["request"]["operation"] for action in actions}),
        "unproductive_observations": sum(not observation.get("novel_evidence", False) for observation in run.get("investigation_state", {}).get("observations", [])),
        "request_bytes": {"min": min(requests, default=0), "max": max(requests, default=0), "total": sum(requests)},
        "logged_prompt_tokens": sum(item.get("prompt_tokens", 0) or 0 for item in usage),
        "logged_completion_tokens": sum(item.get("completion_tokens", 0) or 0 for item in usage),
        "logged_cost_usd": sum(item.get("cost", 0) or 0 for item in usage),
        "accounting_limit": "Logged valid responses only; interrupted or rejected responses may have additional usage. Request bytes are not tokenizer counts.",
        "state_bytes": len(json.dumps(run.get("investigation_state", {}), separators=(",", ":"), ensure_ascii=False).encode()),
        "retained_turns": len(turns),
        "controller_verified_solve": report.get("verified_solve", False),
        "independently_graded": grade.get("independently_graded", False),
        "behavior_executed": grade.get("behavior_executed", False),
        "independent_grade_schema": grade.get("schema"),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directories", nargs="+")
    parser.add_argument("--output", type=Path)
    options = parser.parse_args()
    result = json.dumps([summarize(directory) for directory in options.directories], indent=2)
    if options.output:
        options.output.write_text(result + "\n", encoding="utf-8")
    else:
        print(result)
