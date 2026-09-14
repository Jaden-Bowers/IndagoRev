import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Native, hash, hashFile, atomic } from "./native.mjs";
import { frontendIdentity } from "./benchmark.mjs";
const args = process.argv.slice(2),
  o = {};
for (let i = 0; i < args.length; i += 2)
  o[args[i].replace(/^--/, "")] = args[i + 1];
try {
  if (!o.prepared)
    throw Error("Usage: node agent/preflight.mjs --prepared PREPARED.json");
  const preparedPath = path.resolve(o.prepared),
    p = JSON.parse(fs.readFileSync(preparedPath)),
    checks = [];
  const check = (name, ok) => {
    checks.push({ name, passed: !!ok });
    if (!ok) throw Error("Preflight failed: " + name);
  };
  const dir = path.dirname(fileURLToPath(import.meta.url));
  check(
    "pinned_pi",
    JSON.parse(
      fs.readFileSync(
        path.join(
          dir,
          "node_modules/@earendil-works/pi-coding-agent/package.json",
        ),
      ),
    ).version === p.pi_version,
  );
  check("frontend_identity", frontendIdentity() === p.frontend_sha256);
  check("node_identity", p.node_version === process.version);
  check("native_identity", hashFile(p.trials[0].exe) === p.native_sha256);
  for (const t of p.trials) {
    check(`${t.id}/${t.mode}/fresh`, !fs.existsSync(t.state));
    for (const a of t.input_hashes)
      check(
        `${t.id}/${t.mode}/${a.member}`,
        hash(fs.readFileSync(path.resolve(t.cwd, a.member))) === a.sha256,
      );
  }
  const native = new Native({
    exe: p.trials[0].exe,
    state: path.join(path.dirname(preparedPath), "preflight"),
    workspace: path.join(path.dirname(preparedPath), "preflight/native"),
  });
  const c = (await native.capabilities()).data;
  for (const name of [
    "airece",
    "xair",
    "sym",
    "ghidra",
    "ilspy",
    "capa",
    "floss",
    "lief",
    "wireshark",
  ])
    check(
      name,
      c.backends.some((b) => b.name === name && b.available),
    );
  const trial = p.trials[0];
  const apiKey = trial.apiKeyEnv ? process.env[trial.apiKeyEnv] : null;
  if (trial.apiKeyEnv && !apiKey)
    throw Error(`Missing API key environment variable: ${trial.apiKeyEnv}`);
  const response = await fetch(`${trial.endpoint.replace(/\/$/, "")}/models`, {
    headers: apiKey ? { Authorization: `Bearer ${apiKey}` } : {},
    signal: AbortSignal.timeout(10000),
  });
  check("model_endpoint", response.ok);
  const models = await response.json();
  check(
    "selected_model",
    models.data.some((m) => m.id === trial.model),
  );
  const result = {
    schema: "indago.pi-readiness.v1",
    ready: true,
    trials: p.trials.length,
    frontend_sha256: p.frontend_sha256,
    native_sha256: p.native_sha256,
    checks,
    scope:
      "Build, inputs, adapters and model availability. No challenge inference or target execution performed by preflight.",
  };
  atomic(path.join(path.dirname(preparedPath), "ready.json"), result);
  console.log(
    JSON.stringify({
      ready: true,
      trials: p.trials.length,
      checks: checks.length,
    }),
  );
} catch (e) {
  console.error(e.message);
  process.exitCode = 1;
}
