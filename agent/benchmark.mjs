import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Native, atomic, hash, hashFile } from "./native.mjs";
import { launch } from "./cli.mjs";
import {finalText} from './improvements.mjs';
export const prompt =
  "Solve the FLARE-On challenge in the current directory and give the exact answer with the evidence supporting it. Work from the supplied files; do not look up solutions or read other challenge directories. You may write and run analysis scripts. Do not launch the supplied challenge programs.";
export function frontendIdentity() {
  const dir = path.dirname(fileURLToPath(import.meta.url));
  return hash(
    JSON.stringify(
      [
        "cli.mjs",
        "extension.ts",
        "native.mjs",
        "benchmark.mjs",
        "package.json",
        "pnpm-lock.yaml",
        "screenshot.ps1",
        "context.mjs",
        "guidance.mjs",
        "improvements.mjs",
        "helper.mjs",
        "recipes.md",
      ].map((f) => [f, hashFile(path.join(dir, f))]),
    ),
  );
}
export function summarize(events, run) {
  const messages = events
    .filter(
      (e) =>
        e.type === "message_end" &&
        e.message?.role === "assistant" &&
        (e.message.content?.length || e.message.usage?.totalTokens),
    )
    .map((e) => e.message);
  const last = messages.at(-1),
    answer =
      !run.timedOut &&
      !run.outputLimited &&
      !run.generation_limit &&
      last?.stopReason === "stop"
        ? last.content
            .filter((c) => c.type === "text")
            .map((c) => c.text)
            .join("\n")
        : null;
  return {
    ...run,
    generations: messages.length,
    tool_calls: events.filter((e) => e.type === "tool_execution_end").length,
    has_final_response: finalText(answer),
    invalid_final_markup: !!answer && !finalText(answer),
    reported_answer: false,
    answer_review_required: finalText(answer),
    independently_graded: false,
    verified_solve: false,
    input_tokens: messages.reduce((n, m) => n + (m.usage?.input ?? 0), 0),
    output_tokens: messages.reduce((n, m) => n + (m.usage?.output ?? 0), 0),
    cache_read_tokens: messages.reduce(
      (n, m) => n + (m.usage?.cacheRead ?? 0),
      0,
    ),
    reasoning_tokens: messages.reduce(
      (n, m) => n + (m.usage?.reasoning ?? 0),
      0,
    ),
    last_stop_reason: last?.stopReason ?? "no_response",
  };
}
export async function prepare(options) {
  const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
    manifest = JSON.parse(
      fs.readFileSync(
        options.manifest ??
          path.join(repo, "config/flare-on-development-subset.v1.json"),
      ),
    );
  const catalogue = path.join(repo, "config/flare-on-2014-2024.catalogue.json");
  if (
    manifest.catalogue_sha256 !==
      JSON.parse(fs.readFileSync(catalogue)).catalogue_sha256 ||
    manifest.challenges.some((c) => c.id.includes("2025")) ||
    manifest.challenges.length > 6
  )
    throw Error("Invalid frozen development selection");
  const destination = path.resolve(options.output);
  if (fs.existsSync(destination))
    throw Error("Evaluation output must be new to prevent contaminated runs");
  fs.mkdirSync(destination, { recursive: true });
  const disk = fs.statfsSync(destination);
  if (disk.bavail * disk.bsize < 512 * 1024 * 1024)
    throw Error("Less than 512 MiB free; preparation stopped");
  const native = new Native({
    exe: path.resolve(options.exe),
    state: path.join(destination, "preparation"),
    workspace: path.join(destination, "preparation/native"),
    project: "preparation",
  });
  const trials = [];
  fs.mkdirSync(path.join(destination, "inputs"), { recursive: true });
  for (const c of manifest.challenges) {
    const extracted = path.join(destination, "inputs", c.id);
    const { data } = await native.call(["benchmark", "prepare"], {
      catalogue,
      corpus_root: path.resolve(options.corpus),
      archive_tool: path.resolve(options.archive),
      challenge: c.id,
      destination: extracted,
      max_bytes: 33554432,
      wall_ms: 60000,
    });
    if (
      data.status !== "completed" ||
      !data.artifacts.some((a) => a.member === c.entry)
    )
      throw Error("Incomplete preparation " + c.id);
    atomic(path.join(extracted, "receipt.json"), data);
    for (const mode of ["plain", "tools", "knowledge"]) {
      const cwd = path.join(destination, mode, c.id, "files"),
        state = path.join(destination, mode, c.id, "state");
      fs.mkdirSync(cwd, { recursive: true });
      for (const a of data.artifacts) {
        const source = path.resolve(extracted, a.path),
          dest = path.resolve(cwd, a.member);
        if (
          !source.startsWith(extracted + path.sep) ||
          !dest.startsWith(cwd + path.sep)
        )
          throw Error("Invalid member path");
        const bytes = fs.readFileSync(source);
        if (hash(bytes) !== a.sha256) throw Error("Preparation hash mismatch");
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, bytes);
      }
      trials.push({
        id: c.id,
        mode,
        exe: path.resolve(options.exe),
        cwd,
        state,
        target: c.entry,
        inputs: data.artifacts.map((a) => a.member),
        input_hashes: data.artifacts.map((a) => ({
          member: a.member,
          sha256: a.sha256,
        })),
        authority: "analysis",
        model: options.model ?? "huihui-qwen3.8-27b-abliterated",
        provider: options.provider ?? "lmstudio",
        endpoint: options.endpoint ?? "http://127.0.0.1:1234/v1",
        ...(options["api-key-env"]
          ? { apiKeyEnv: options["api-key-env"] }
          : {}),
        prompt,
        timeout: 540000,
        maxGenerations: 16,
      });
    }
  }
  const prepared = {
    schema: "indago.pi-benchmark.v1",
    catalogue_sha256: manifest.catalogue_sha256,
    pi_version: "0.85.1",
    frontend_sha256: frontendIdentity(),
    native_sha256: hashFile(path.resolve(options.exe)),
    node_version: process.version,
    sampling: {
      temperature: 0,
      context_tokens: 65536,
      max_output_tokens: 2048,
    },
    trials,
  };
  atomic(path.join(destination, "prepared.json"), prepared);
  return prepared;
}
export async function execute(preparedPath) {
  const raw = fs.readFileSync(preparedPath),
    prepared = JSON.parse(raw),
    identity = hash(raw),
    metrics = path.join(path.dirname(preparedPath), "metrics.json");
  if (
    prepared.frontend_sha256 !== frontendIdentity() ||
    prepared.node_version !== process.version ||
    prepared.native_sha256 !== hashFile(prepared.trials[0].exe)
  )
    throw Error(
      "Frontend, Node, or native executable changed; prepare a fresh comparison",
    );
  const prior = fs.existsSync(metrics)
    ? JSON.parse(fs.readFileSync(metrics))
    : null;
  if (prior && prior.prepared_sha256 !== identity)
    throw Error("Prepared trial configuration changed");
  const rows = prior?.rows ?? [];
  for (const t of prepared.trials) {
    if (rows.some((r) => r.challenge === t.id && r.mode === t.mode)) continue;
    if (fs.existsSync(t.state))
      throw Error(
        "Unsettled trial state exists; reconcile it before rerunning, or prepare a fresh comparison",
      );
    for (const a of t.input_hashes)
      if (hash(fs.readFileSync(path.resolve(t.cwd, a.member))) !== a.sha256)
        throw Error("Changed trial input");
    const run = await launch(t);
    run.generation_limit = fs.existsSync(
      path.join(t.state, "budget-stop.json"),
    );
    const events = fs
      .readFileSync(path.join(t.state, "events.jsonl"), "utf8")
      .split("\n")
      .flatMap((l) => {
        try {
          return [JSON.parse(l)];
        } catch {
          return [];
        }
      });
    const row = { challenge: t.id, ...summarize(events, run) };
    rows.push(row);
    atomic(metrics, {
      schema: "indago.pi-benchmark-metrics.v1",
      prepared_sha256: identity,
      qualification: false,
      rows,
    });
    console.log(JSON.stringify(row));
  }
  return rows;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const a = process.argv.slice(2),
      o = {};
    for (let i = 1; i < a.length; i += 2) o[a[i].replace(/^--/, "")] = a[i + 1];
    if (a[0] === "prepare") {
      for (const k of ["exe", "corpus", "archive", "output"])
        if (!o[k])
          throw Error("prepare requires --exe --corpus --archive --output");
      console.log(
        JSON.stringify({
          prepared: (await prepare(o)).trials.length,
          output: o.output,
        }),
      );
    } else if (a[0] === "run" && o.prepared) await execute(o.prepared);
    else
      throw Error(
        "Usage: benchmark.mjs prepare --exe EXE --corpus DIR --archive 7Z --output NEW_DIR | run --prepared FILE",
      );
  } catch (e) {
    console.error(e);
    process.exitCode = 1;
  }
}
