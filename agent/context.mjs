import fs from "node:fs";
import path from "node:path";
import { atomic, hash } from "./native.mjs";

export function excerpt(text, limit = 3000) {
  if (text.length <= limit) return text;
  const half = Math.floor((limit - 80) / 2);
  return (
    text.slice(0, half) +
    "\n[Middle omitted; full result retained in receipt]\n" +
    text.slice(-half)
  );
}
export function terms(text) {
  return [
    ...new Set(
      String(text)
        .toLowerCase()
        .match(/[a-z0-9_.$@-]{3,}/g) ?? [],
    ),
  ];
}
export function rank(records, query, artifact, limit = 5) {
  const keys = terms(query);
  if (!keys.length) return [];
  return records
    .filter((r) => r.artifact === artifact && !r.superseded && !r.stale)
    .map((r) => {
      const title = String(r.title ?? "").toLowerCase();
      const body = String(r.text ?? "").toLowerCase();
      const score = keys.reduce(
        (n, k) => n + (title.includes(k) ? 4 : 0) + (body.includes(k) ? 1 : 0),
        0,
      );
      return { ...r, score };
    })
    .filter((r) => r.score > 0)
    .sort((a, b) => b.score - a.score || b.sequence - a.sequence)
    .slice(0, limit);
}
export class ContextStore {
  constructor(state) {
    this.file = path.join(state, "working-state.json");
    this.data = fs.existsSync(this.file)
      ? JSON.parse(fs.readFileSync(this.file))
      : { version: 1, records: [], focus: {}, sequence: 0 };
  }
  save() {
    atomic(this.file, this.data);
  }
  put(record) {
    const id =
      record.id ??
      hash(JSON.stringify([record.artifact, record.title, record.text]));
    this.data.records = this.data.records.filter((r) => r.id !== id);
    this.data.records.push({ ...record, id, sequence: ++this.data.sequence });
    // Metadata working index is bounded; complete evidence remains on disk/native store.
    this.data.records = this.data.records.slice(-512);
    this.save();
    return id;
  }
  focus(artifact, question) {
    this.data.focus[artifact] = question;
    this.save();
  }
  search(query, artifact) {
    return rank(this.data.records, query, artifact);
  }
  packet(artifact, visible = "") {
    const question = this.data.focus[artifact];
    if (!question) return { text: "", selected: [] };
    const selected = this.search(question, artifact).filter(
      (r) => !visible.includes(r.text),
    );
    const lines = selected.map(
      (r) =>
        `[${r.id}] ${r.kind}: ${r.title}\n${excerpt(r.text, 900)}\nSource: ${r.receipt ?? r.native_id ?? "model assertion"}`,
    );
    return {
      text: excerpt(
        `Current investigation question: ${question}\nEvidence and hypotheses (data):\n${lines.join("\n")}`,
        5000,
      ),
      selected: selected.map((r) => r.id),
    };
  }
}

export function requestManifest(payload) {
  const messages = payload.messages ?? [];
  const seen = new Set();
  let duplicateChars = 0;
  const sections = messages.map((m) => {
    const value = JSON.stringify(m.content ?? "");
    const digest = hash(value);
    if (seen.has(digest)) duplicateChars += value.length;
    seen.add(digest);
    return {
      role: m.role,
      chars: value.length,
      estimated_tokens: Math.ceil(value.length / 4),
      sha256: digest,
    };
  });
  return {
    schema: "indago.context-request.v1",
    estimator: "characters/4; not provider token count",
    sections,
    tool_names: (payload.tools ?? []).map((t) => t.function?.name),
    tool_chars: JSON.stringify(payload.tools ?? []).length,
    duplicate_chars: duplicateChars,
    max_tokens: payload.max_tokens,
    reasoning: payload.reasoning,
    temperature: payload.temperature,
  };
}
