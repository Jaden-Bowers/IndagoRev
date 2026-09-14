import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Native, readable, runProcess, hash } from "../native.mjs";
import { summarize } from "../benchmark.mjs";
test("partial readable output preserves semantics and exposes truncation", () => {
  const r = readable(
    {
      status: "partial",
      backend: "ghidra",
      evidence_ids: ["ev_one"],
      data: { decompiled_c: "a".repeat(100) },
    },
    60,
  );
  assert(r.truncated);
  assert.match(r.text, /partial/);
  assert.match(r.text, /ghidra/);
});
test("no final prose or timeout can silently become a verified answer", () => {
  const events = [
    {
      type: "message_end",
      message: {
        role: "assistant",
        stopReason: "stop",
        content: [{ type: "text", text: "I could not solve this." }],
      },
    },
  ];
  assert.equal(summarize(events, {}).reported_answer, false);
  assert.equal(summarize(events, {}).verified_solve, false);
  assert.equal(summarize(events, { timedOut: true }).has_final_response, false);
  assert.equal(
    summarize(events, { generation_limit: true }).has_final_response,
    false,
  );
});
test("process runner preserves literal arguments and bounds output", async () => {
  const arg = 'literal $() ; " spaces';
  const r = await runProcess(process.execPath, [
    "-e",
    "console.log(process.argv[1])",
    arg,
  ]);
  assert.equal(r.stdout.trim(), arg);
  const huge = await runProcess(
    process.execPath,
    ["-e", 'process.stdout.write("x".repeat(10000))'],
    { maxBytes: 100 },
  );
  assert.equal(huge.failure, "output_limit");
});
test("timeout and pre-cancel settle without inference", async () => {
  const r = await runProcess(
    process.execPath,
    ["-e", "setInterval(()=>{},1000)"],
    { timeout: 100 },
  );
  assert.equal(r.failure, "timeout");
  const c = new AbortController();
  c.abort();
  await assert.rejects(
    runProcess(process.execPath, ["-e", "process.exit(99)"], {
      signal: c.signal,
    }),
    /Cancelled/,
  );
});
test(
  "native bridge binds primary after companion import and persists knowledge",
  { skip: !process.env.INDAGO_TEST_EXE, timeout: 120000 },
  async () => {
    const state = fs.mkdtempSync(path.join(os.tmpdir(), "indago-pi-test-"));
    const a = path.join(state, "primary.py"),
      b = path.join(state, "companion.txt");
    fs.writeFileSync(a, "print(123)");
    fs.writeFileSync(b, "companion");
    const native = new Native({
      exe: process.env.INDAGO_TEST_EXE,
      state,
      workspace: path.join(state, "native"),
      project: "test",
      cwd: state,
      mode: "knowledge",
    });
    await native.call(["project", "create", "--name", "test"]);
    const primary = await native.import(a);
    await native.call(["target", "import", "--project", "test", "--file", b]);
    assert.equal(native.active.id, primary.id);
    const route = await native.route();
    assert(route.data);
    const saved = await native.remember({
      title: "Source finding",
      text: "Contains a print call",
      assumptions: ["Source not executed"],
    });
    assert(saved.data);
    const list = (
      await native.knowledge("list", { search: "Source finding", limit: 10 })
    ).data;
    assert.equal(list.records.length, 1);
    assert.equal(
      list.records[0].scope.artifact_sha256,
      hash(fs.readFileSync(a)),
    );
    const second = new Native({ ...native.config, active: native.active });
    assert.equal(
      (await second.knowledge("list", { search: "Source finding", limit: 10 }))
        .data.records.length,
      1,
    );
    const assertion = await native.remember({
      title: "Unresolved reference",
      text: "Unverified caller assertion",
      support: ["invented-tool-id"],
    });
    assert.deepEqual(assertion.data.body.unresolved_support, [
      "invented-tool-id",
    ]);
    assert.deepEqual(assertion.data.support, []);
    assert.equal(assertion.data.state, "inferred");
    const updated = await native.remember({
      id: assertion.data.id,
      title: "Unresolved reference",
      text: "Corrected assertion",
    });
    assert.equal(updated.data.revision, assertion.data.revision + 1);
    assert.equal(updated.data.body.text, "Corrected assertion");
  },
);
test(
  "host experiment sends contrasting inputs through existing runtime",
  {
    skip:
      !process.env.INDAGO_TEST_EXE ||
      !fs.existsSync(
        path.join(
          path.dirname(process.env.INDAGO_TEST_EXE ?? ""),
          "indago_io_fixture.exe",
        ),
      ),
    timeout: 40000,
  },
  async () => {
    const state = fs.mkdtempSync(path.join(os.tmpdir(), "indago-pi-io-")),
      native = new Native({
        exe: process.env.INDAGO_TEST_EXE,
        state,
        workspace: path.join(state, "native"),
        project: "io",
        cwd: state,
        authority: "analysis",
      });
    await native.call(["project", "create", "--name", "io"]);
    await native.import(
      path.join(
        path.dirname(process.env.INDAGO_TEST_EXE),
        "indago_io_fixture.exe",
      ),
    );
    await assert.rejects(
      native.experiment([{ label: "positive", stdin: "OPEN" }]),
      /host-authorized/,
    );
    native.config.authority = "host";
    const r = await native.experiment([
      { label: "positive", stdin: "OPEN" },
      { label: "negative", stdin: "NO" },
    ]);
    assert.equal(r.data.cases.length, 2);
    assert.match(JSON.stringify(r.data.cases[0].data), /4f4b/i);
    assert.match(JSON.stringify(r.data.cases[1].data), /4e4f/i);
  },
);
