import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ContextStore, excerpt, rank, requestManifest } from "../context.mjs";
test("retrieval scopes artifacts, excludes unrelated evidence and survives restart", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "indago-context-"));
  const s = new ContextStore(dir);
  s.put({
    artifact: "a",
    kind: "observation",
    title: "decoder",
    text: "stage one decoded successfully",
  });
  s.put({
    artifact: "b",
    kind: "hypothesis",
    title: "decoder",
    text: "wrong artifact decoy",
  });
  s.put({
    artifact: "a",
    kind: "observation",
    title: "maze",
    text: "unrelated pixels",
  });
  s.focus("a", "decoder stage");
  const restored = new ContextStore(dir);
  assert.equal(restored.search("decoder", "a").length, 1);
  assert(!restored.packet("a").text.includes("decoy"));
  assert(!restored.packet("a").text.includes("pixels"));
  assert.equal(
    restored.packet("a", "stage one decoded successfully").selected.length,
    0,
  );
  assert.deepEqual(rank(s.data.records, "unmatched", "a"), []);
});
test("output preview retains error tail and manifest contains hashes not source", () => {
  const text = "header\n" + "x".repeat(10000) + "\nSyntaxError: bad token";
  assert(excerpt(text, 500).endsWith("SyntaxError: bad token"));
  assert(excerpt(text, 500).length <= 500);
  const m = requestManifest({
    messages: [
      { role: "tool", content: "private bytes" },
      { role: "tool", content: "private bytes" },
    ],
    tools: [],
    max_tokens: 2048,
  });
  assert(m.duplicate_chars > 0);
  assert(!JSON.stringify(m).includes("private bytes"));
});
