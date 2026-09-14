import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { fileURLToPath } from "node:url";
import { launch } from "../cli.mjs";
import { Native } from "../native.mjs";
const repo = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
test(
  "Pi extension dispatches real native analysis and persists searchable program knowledge",
  { skip: !process.env.INDAGO_TEST_EXE, timeout: 120000 },
  async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "indago-pi-sdk-")),
      cwd = path.join(dir, "files");
    fs.mkdirSync(cwd);
    fs.writeFileSync(
      path.join(cwd, "source.txt"),
      "Complete source sentinel: " + "x".repeat(5000) + " END_OF_SOURCE",
    );
    const fixture = path.join(
      repo,
      "xair/XAIR/tests/corpus/phase3/control-flow.pe64",
    );
    fs.copyFileSync(fixture, path.join(cwd, "target.exe"));
    const calls = [],
      requests = [];
    let turn = 0;
    const server = http.createServer(async (req, res) => {
      let raw = "";
      for await (const b of req) raw += b;
      const body = JSON.parse(raw);
      requests.push(body);
      const steps = [
        ["read", { path: "source.txt" }],
        ["analyze", { backend: "xair", operation: "inventory" }],
        [
          "remember",
          {
            title: "Synthetic test finding",
            text: "A fixture was inspected; this is not a solve.",
          },
        ],
        ["knowledge_search", { query: "Synthetic test finding" }],
      ];
      const step = steps[turn++];
      if (step) calls.push(step[0]);
      const delta = step
        ? {
            role: "assistant",
            tool_calls: [
              {
                index: 0,
                id: "call_" + turn,
                type: "function",
                function: { name: step[0], arguments: JSON.stringify(step[1]) },
              },
            ],
          }
        : { role: "assistant", content: "Synthetic bridge check complete." };
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      for (const value of [
        { choices: [{ index: 0, delta, finish_reason: null }] },
        {
          choices: [
            {
              index: 0,
              delta: {},
              finish_reason: step ? "tool_calls" : "stop",
            },
          ],
          usage: {
            prompt_tokens: 100,
            completion_tokens: 20,
            total_tokens: 120,
          },
        },
      ])
        res.write(
          "data: " +
            JSON.stringify({
              id: "test",
              object: "chat.completion.chunk",
              created: 1,
              model: body.model,
              ...value,
            }) +
            "\n\n",
        );
      res.end("data: [DONE]\n\n");
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    try {
      const state = path.join(dir, "state");
      const r = await launch({
        exe: process.env.INDAGO_TEST_EXE,
        cwd,
        target: "target.exe",
        state,
        mode: "knowledge",
        model: "test-local",
        endpoint: `http://127.0.0.1:${server.address().port}/v1`,
        prompt: "Run the synthetic integration check.",
        timeout: 90000,
        maxGenerations: 8,
      });
      assert.equal(r.code, 0);
      assert.equal(r.timedOut, false);
      assert.deepEqual(calls, [
        "read",
        "analyze",
        "remember",
        "knowledge_search",
      ]);
      assert.equal(turn, 5);
      assert(JSON.stringify(requests[1].messages).includes("END_OF_SOURCE"));
      assert(requests[0].tools.some((t) => t.function.name === "analyze"));
      assert(
        JSON.stringify(requests.at(-1).messages).includes(
          "Synthetic test finding",
        ),
      );
      const config = JSON.parse(
          fs.readFileSync(path.join(state, "config.json")),
        ),
        native = new Native(config);
      const records = (await native.knowledge("list", { limit: 20 })).data
        .records;
      assert(records.some((r) => r.title === "Synthetic test finding"));
      assert(
        records.some(
          (r) =>
            r.body.type === "native_analysis_receipt" && r.support.length > 0,
        ),
      );
      assert(
        !fs
          .readFileSync(path.join(state, "stderr.txt"), "utf8")
          .includes("Failed to load extension"),
      );
    } finally {
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
    }
  },
);
test(
  "all three modes enforce the same model-turn budget",
  { skip: !process.env.INDAGO_TEST_EXE, timeout: 90000 },
  async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "indago-pi-budget-"));
    fs.writeFileSync(path.join(dir, "input.txt"), "budget fixture");
    let requests = 0,
      tools = [];
    const server = http.createServer(async (req, res) => {
      let raw = "";
      for await (const b of req) raw += b;
      const body = JSON.parse(raw);
      requests++;
      tools = body.tools.map((t) => t.function.name);
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      res.write(
        "data: " +
          JSON.stringify({
            id: "budget",
            object: "chat.completion.chunk",
            model: body.model,
            choices: [
              {
                index: 0,
                delta: {
                  role: "assistant",
                  tool_calls: [
                    {
                      index: 0,
                      id: "call_" + requests,
                      type: "function",
                      function: {
                        name: "read",
                        arguments: '{"path":"input.txt"}',
                      },
                    },
                  ],
                },
                finish_reason: null,
              },
            ],
          }) +
          "\n\n",
      );
      res.end(
        "data: " +
          JSON.stringify({
            id: "budget",
            object: "chat.completion.chunk",
            model: body.model,
            choices: [{ index: 0, delta: {}, finish_reason: "tool_calls" }],
          }) +
          "\n\ndata: [DONE]\n\n",
      );
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    try {
      for (const mode of ["plain", "tools", "knowledge"]) {
        requests = 0;
        const state = path.join(dir, mode);
        await launch({
          exe: process.env.INDAGO_TEST_EXE,
          cwd: dir,
          target: "input.txt",
          state,
          mode,
          model: "mock",
          endpoint: `http://127.0.0.1:${server.address().port}/v1`,
          prompt: "Read input.txt repeatedly.",
          timeout: 20000,
          maxGenerations: 1,
        });
        assert.equal(requests, 1);
        assert.equal(fs.existsSync(path.join(state, "budget-stop.json")), true);
        assert.equal(tools.includes("analyze"), mode !== "plain");
        assert(tools.includes("read"));
      }
    } finally {
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
    }
  },
);
