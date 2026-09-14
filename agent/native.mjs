import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { spawn } from "node:child_process";
export const hash = (data) =>
  crypto.createHash("sha256").update(data).digest("hex");
export function hashFile(file) {
  const digest = crypto.createHash("sha256"),
    fd = fs.openSync(file, "r"),
    buffer = Buffer.alloc(1024 * 1024);
  try {
    let n;
    while ((n = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0)
      digest.update(buffer.subarray(0, n));
    return digest.digest("hex");
  } finally {
    fs.closeSync(fd);
  }
}
export function atomic(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + "." + crypto.randomUUID() + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
  fs.renameSync(tmp, file);
}
export function stopTree(child) {
  if (!child.pid) return;
  if (process.platform === "win32")
    spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], {
      windowsHide: true,
      stdio: "ignore",
    });
  else {
    try {
      process.kill(-child.pid, "SIGTERM");
    } catch {}
    const timer = setTimeout(() => {
      try {
        process.kill(-child.pid, "SIGKILL");
      } catch {}
    }, 1000);
    timer.unref();
  }
}
export function runProcess(
  command,
  args,
  {
    cwd,
    env = process.env,
    signal,
    timeout = 120000,
    maxBytes = 16 * 1024 * 1024,
    onStderr,
  } = {},
) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error("Cancelled before dispatch"));
    const child = spawn(command, args, {
      cwd,
      env,
      windowsHide: true,
      detached: process.platform !== "win32",
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "",
      err = "",
      failure = null;
    const start = Date.now();
    const abort = () => {
      failure = "cancelled";
      stopTree(child);
    };
    signal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(() => {
      failure = "timeout";
      stopTree(child);
    }, timeout);
    child.stdout.on("data", (b) => {
      if (Buffer.byteLength(out) + b.length > maxBytes) {
        failure = "output_limit";
        stopTree(child);
      } else out += b;
    });
    child.stderr.on("data", (b) => {
      err = (err + b).slice(-16384);
      onStderr?.(b.toString());
    });
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    };
    child.on("error", (e) => {
      cleanup();
      reject(e);
    });
    child.on("close", (code) => {
      cleanup();
      resolve({
        code,
        stdout: out,
        stderr: err,
        failure,
        elapsed_ms: Date.now() - start,
      });
    });
  });
}
export class Native {
  constructor(config) {
    this.config = config;
    this.dir = path.join(config.state, "receipts");
    fs.mkdirSync(this.dir, { recursive: true });
    this.active = config.active;
    this.evidence = new Set();
  }
  async call(args, request, { signal, timeout = 120000 } = {}) {
    const id = crypto.randomUUID(),
      file = path.join(this.dir, id + ".request.json");
    let job = null;
    const receiptFile = path.join(this.dir, id + ".json");
    atomic(receiptFile, {
      id,
      args,
      request,
      status: "dispatching",
      created_at: new Date().toISOString(),
      interpretation:
        "If this remains dispatching, reconcile before repeating side effects",
    });
    if (request) atomic(file, request);
    let result;
    try {
      result = await runProcess(
        this.config.exe,
        [
          "--workspace",
          this.config.workspace,
          ...args,
          ...(request ? ["--request", file] : []),
        ],
        {
          signal,
          timeout,
          onStderr: (text) => {
            job = text.match(/job (job_[a-zA-Z0-9]+)/)?.[1] ?? job;
            if (job)
              atomic(receiptFile, {
                id,
                args,
                request,
                job,
                status: "dispatching",
              });
          },
        },
      );
    } finally {
      if (fs.existsSync(file)) fs.unlinkSync(file);
    }
    let data;
    try {
      data = JSON.parse(result.stdout);
    } catch {
      data = {
        status: "transport_error",
        diagnostic: result.failure ?? result.stderr,
      };
    }
    for (const evidence of data.evidence_ids ?? []) this.evidence.add(evidence);
    // A killed CLI may leave a persistent worker. Set its native cancellation flag too.
    if (result.failure && job)
      await runProcess(
        this.config.exe,
        [
          "--workspace",
          this.config.workspace,
          "job",
          "cancel",
          "--project",
          this.config.project,
          "--id",
          job,
        ],
        { timeout: 5000 },
      );
    const receipt = {
      id,
      args,
      request,
      result: { ...result, stdout: undefined },
      data,
      created_at: new Date().toISOString(),
    };
    atomic(receiptFile, receipt);
    if (result.failure)
      throw new Error(
        `${result.failure}; outcome may be incomplete; receipt ${id}${job ? "; job " + job : ""}`,
      );
    if (![0, 3, 130].includes(result.code))
      throw new Error(
        `${data.diagnostic ?? JSON.stringify(data)}; receipt ${id}`,
      );
    return { data, receipt: path.join(this.dir, id + ".json") };
  }
  async import(file, signal) {
    const resolved = path.resolve(this.config.cwd, file);
    const { data } = await this.call(
      [
        "target",
        "import",
        "--project",
        this.config.project,
        "--file",
        resolved,
      ],
      null,
      { signal },
    );
    this.active = { ...data, path: resolved };
    this.lastObservation = null;
    this.config.active = this.active;
    atomic(path.join(this.config.state, "config.json"), this.config);
    return data;
  }
  async route(signal) {
    return this.call(
      [
        "target",
        "route",
        "--project",
        this.config.project,
        "--id",
        this.active.id,
      ],
      null,
      { signal },
    );
  }
  async capabilities(signal) {
    if (!this.catalogue)
      this.catalogue = await this.call(["capabilities"], null, { signal });
    return this.catalogue;
  }
  async analyze(
    { backend, operation, address, arguments: arguments_ = {}, target_id },
    signal,
  ) {
    if (target_id && target_id !== this.active.id)
      throw Error(
        "Use program_open to select another active program before analysis",
      );
    const { data: catalog } = await this.capabilities(signal);
    const backendInfo = catalog.backends.find(
      (b) => b.name === backend && b.available,
    );
    if (!backendInfo?.operations.includes(operation))
      throw new Error(
        "Unavailable backend/operation; use analysis_tools for current capabilities",
      );
    const result = await this.call(
      ["action", "run"],
      {
        schema: "indago.action.v1",
        project: this.config.project,
        target_id: target_id ?? this.active.id,
        backend,
        operation,
        address: address ?? "",
        view: "compact",
        arguments: arguments_,
        budget: {
          wall_ms: 60000,
          output_bytes: 2097152,
          memory_bytes: 2147483648,
          max_items: 2048,
        },
      },
      { signal, timeout: 90000 },
    );
    if (this.config.mode === "knowledge")
      try {
        await this.knowledge(
          "put",
          {
            kind: "product",
            state: "observed",
            title: `${backend} ${operation} ${address ?? ""}`,
            scope: {
              artifact_sha256:
                result.data.artifact_sha256 ?? this.active.artifact_sha256,
            },
            body: {
              type: "native_analysis_receipt",
              status: result.data.status,
              receipt: result.receipt,
              backend,
              operation,
              address,
              preview: readable(result.data, 3000).text,
            },
            support: result.data.evidence_ids ?? [],
            counterevidence: [],
            assumptions: [],
            dependencies: [],
          },
          signal,
        );
      } catch (e) {
        result.data.knowledge_ingestion_error = String(e);
      }
    return result;
  }
  async knowledge(operation, request = {}, signal) {
    return this.call(
      ["knowledge", operation],
      { ...request, project: this.config.project },
      { signal },
    );
  }
  async experiment(cases, signal) {
    if (this.config.authority !== "host")
      throw Error("Start a host-authorized session to run original targets");
    if (!Array.isArray(cases) || !cases.length || cases.length > 8)
      throw Error("Expected 1..8 experiment cases");
    const results = [];
    for (const c of cases) {
      const r = await this.call(
        ["runtime", "io-run"],
        {
          project: this.config.project,
          file: this.active.path,
          artifact: this.active.artifact_sha256,
          trusted_target_ack: true,
          argv: c.argv ?? [],
          input_hex: Buffer.from(c.stdin ?? "").toString("hex"),
          files: c.files ?? {},
          environment: c.environment ?? {},
          timeout_ms: 10000,
          max_output_bytes: 65536,
        },
        { signal, timeout: 20000 },
      );
      results.push({ label: c.label, ...r });
    }
    return {
      data: {
        status: "completed",
        cases: results,
        interpretation:
          "Observed case results; no independent acceptance oracle supplied",
      },
    };
  }
  async remember({ id, title, text, support = [], assumptions = [] }, signal) {
    const resolved = support.filter((id) => this.evidence.has(id)),
      unresolved = support.filter((id) => !this.evidence.has(id));
    let update = {};
    if (id) {
      const current = (await this.knowledge("show", { id }, signal)).data;
      if (current.scope.artifact_sha256 !== this.active.artifact_sha256)
        throw Error("Finding belongs to a different active program");
      update = { id, expected_revision: current.revision };
    }
    const r = await this.knowledge(
      "put",
      {
        ...update,
        kind: "summary",
        state: "inferred",
        title,
        scope: { artifact_sha256: this.active.artifact_sha256 },
        body: { text, unresolved_support: unresolved },
        support: resolved,
        counterevidence: [],
        assumptions,
        // Temporal proximity is not evidential support. Keep it as context only.
        dependencies: [],
      },
      signal,
    );
    if (unresolved.length)
      r.data.support_note =
        "Finding saved as an assertion. Unrecognized references are retained as unresolved, not validated evidence.";
    return r;
  }
}
export function readable(data, maxChars = 18000) {
  const pieces = [];
  function visit(v, key = "") {
    if (
      typeof v === "string" &&
      /decompiled_c|pseudocode|source_text|native_output/.test(key)
    )
      pieces.push(v);
    else if (v && typeof v === "object")
      for (const [k, x] of Object.entries(v)) visit(x, k);
  }
  visit(data);
  const meta = {
    status: data.status,
    backend: data.backend,
    evidence_ids: data.evidence_ids,
  };
  const text = pieces.length
    ? JSON.stringify(meta) + "\n" + pieces.join("\n\n")
    : JSON.stringify(data, null, 2);
  const half = Math.floor((maxChars - 80) / 2);
  return {
    text:
      text.length > maxChars && maxChars > 100
        ? text.slice(0, half) +
          "\n[Middle omitted; full result in receipt]\n" +
          text.slice(-half)
        : text.slice(0, maxChars),
    truncated: text.length > maxChars,
  };
}
