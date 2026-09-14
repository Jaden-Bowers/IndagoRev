import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Type } from "@earendil-works/pi-ai";
import { Native, readable, atomic, hash, runProcess } from "./native.mjs";
import { ContextStore, excerpt, requestManifest } from "./context.mjs";
import { guidance } from "./guidance.mjs";
import {enabled, finalText, Investigation, Progress, extractMember} from './improvements.mjs';
import {strings} from './helper.mjs';

export default function (pi: any) {
  const config = JSON.parse(
    fs.readFileSync(process.env.INDAGO_AGENT_CONFIG!, "utf8"),
  );
  let generations = 0;
  const investigation=new Investigation(path.join(config.state,'investigation.json'),config.active.artifact_sha256);
  const progress=new Progress();
  let requestNumber = 0,
    recoveries = 0;
  pi.on("before_provider_request", (event: any) => {
    const payload = { ...event.payload };
    if (config.provider === "openrouter")
      payload.reasoning = { enabled: false };
    if (
      config.mode !== "plain" &&
      config.maxGenerations > 1 &&
      generations >= config.maxGenerations - 1
    ) {
      payload.tool_choice = "none";
      if(enabled(config,'final')) delete payload.tools;
      payload.messages = [
        ...(payload.messages ?? []),
        {
          role: "user",
          content:
            "This is the final generation. Give the supported answer and evidence, or state the precise unresolved blocker. Do not invent an answer.",
        },
      ];
    }
    atomic(
      path.join(config.state, "context-manifests", `${++requestNumber}.json`),
      requestManifest(payload),
    );
    return payload;
  });
  pi.on("turn_end", async (event: any, ctx: any) => {
    generations++;
    const answer=(event.message?.content??[]).filter((x:any)=>x.type==='text').map((x:any)=>x.text).join('\n');
    if(enabled(config,'final') && event.message?.stopReason==='stop' && !finalText(answer)) {
      atomic(path.join(config.state,'unresolved.json'),{reason:'invalid_final_tool_markup',candidate:investigation.data.candidate,obligation:investigation.data.obligation,generations});
      if(generations<(config.maxGenerations??128)) pi.sendUserMessage('Your response was tool markup, not an answer. Submit plain text with the supported candidate and unresolved evidence. Do not emit tool syntax.',{deliverAs:'followUp'});
    }
    if (
      event.message?.stopReason === "length" &&
      recoveries < 2 &&
      generations < (config.maxGenerations ?? 128)
    ) {
      recoveries++;
      pi.sendUserMessage(
        "The response ended at its token limit. Continue with a short concrete tool call or a concise evidence-backed answer. Avoid repeating prior analysis.",
        { deliverAs: "followUp" },
      );
    }
    if (
      config.maxGenerations &&
      generations >= config.maxGenerations
    ) {
      if(event.message?.stopReason !== 'stop') atomic(path.join(config.state, "budget-stop.json"), {
          reason: "generation_limit", generations,
        });
      ctx.abort();
      if(config.prompt) ctx.shutdown();
    }
  });
  if (config.mode === "plain") return;
  const native = new Native(config),
    history = new Map<string, number>();
  const memory = new ContextStore(config.state);
  const starts = new Map<string, number>();
  const failures = new Map<string, number>();
  let revision = 0;
  let recent: string[] = [];
  const result = (data: any, receipt?: string) => {
    const view = readable(data);
    return {
      content: [
        {
          type: "text",
          text:
            view.text +
            (receipt
              ? `\nFull native receipt: ${receipt}. Read it with normal file tools.`
              : "") +
            (view.truncated
              ? "\nPreview truncated; complete content is in the receipt."
              : ""),
        },
      ],
      details: {
        receipt,
        status: data.status,
        evidence_ids: data.evidence_ids,
      },
    };
  };
  const tool = (
    name: string,
    description: string,
    parameters: any,
    execute: any,
  ) =>
    pi.registerTool({
      name,
      label: name,
      description,
      parameters,
      async execute(_id: any, p: any, signal: any) {
        const r = await execute(p, signal);
        return result(r.data ?? r, r.receipt);
      },
    });
  if(enabled(config,'state')) tool('investigation_update','Update the concise working state after a meaningful discovery. Facts must cite a file, offset or receipt. Candidate is not automatically verified.',Type.Object({facts:Type.Optional(Type.Array(Type.String())),candidate:Type.Optional(Type.String()),obligation:Type.Optional(Type.String())}),async(p:any)=>{investigation.update(p);return investigation.data;});
  if(enabled(config,'surface')) tool('artifact_inspect','Direct inspection: strings for binary text; archive_list then archive_extract for installer payloads; bytecode for a JAR/class. Never launches the target.',Type.Object({operation:Type.Union(['strings','archive_list','archive_extract','bytecode'].map(x=>Type.Literal(x))),file:Type.String(),member:Type.Optional(Type.String()),output:Type.Optional(Type.String())}),async(p:any,s:any)=>{
    const file=path.resolve(config.cwd,p.file);
    if(p.operation==='strings'){if(fs.statSync(file).size>33554432)throw Error('32 MiB limit');return {strings:strings(fs.readFileSync(file))};}
    const env=config.environment;
    if(p.operation==='bytecode'){
      if(!env.javap.path)throw Error('javap unavailable; install a JDK before retrying');
      if(file.endsWith('.jar')){
        if(!p.member)throw Error('List the archive and supply its class name as member (for example package.Main)');
        return await runProcess(env.javap.path,['-c','-p','-classpath',file,p.member],{timeout:30000,maxBytes:262144,signal:s});
      }
      return await runProcess(env.javap.path,['-c','-p',file],{timeout:30000,maxBytes:262144,signal:s});
    }
    if(!env.archive.path)throw Error('Archive tool unavailable; install 7-Zip before retrying');
    if(p.operation==='archive_list')return await runProcess(env.archive.path,['l','-slt',file],{timeout:30000,maxBytes:65536,signal:s});
    if(!p.output)throw Error('Specify a new output file in the investigation directory');
    const output=path.resolve(config.cwd,p.output);
    if(!output.startsWith(path.resolve(config.cwd)+path.sep))throw Error('Output must stay in investigation directory');
    const derived=await extractMember(env.archive.path,file,p.member,output,s);
    atomic(path.join(config.state,'derived',derived.sha256+'.json'),derived);
    return derived;
  });
  tool(
    "analysis_tools",
    "Discover available native analysis engines and their exact operations.",
    Type.Object({}),
    async (_p: any, s: any) => {
      pi.setActiveTools([
        ...new Set([
          ...pi.getActiveTools(),
          "decompile",
          "functions",
          "xrefs",
          "runtime",
          "run_experiment",
          "wsl",
          "graph_context",
        ]),
      ]);
      const r = await native.capabilities(s);
      return {
        data: {
          backends: r.data.backends.map((b: any) => ({
            name: b.name,
            available: b.available,
            operations: b.operations,
          })),
          runtime: r.data.runtime?.backend,
        },
        receipt: r.receipt,
      };
    },
  );
  tool(
    "program_open",
    "Import a file and make it the active program. Returns artifact identity and format routing hints; source files can be read directly.",
    Type.Object({ path: Type.String() }),
    async (p: any, s: any) => {
      const target = await native.import(p.path, s);
      if(enabled(config,'state')) investigation.update({artifact:native.active.artifact_sha256});
      return { data: { target, route: (await native.route(s)).data } };
    },
  );
  tool(
    "analyze",
    "Run native analysis. Defaults bind to the active program. Results preserve native status and evidence IDs. Use Ghidra for native decompilation, XAIR for native CFG/semantics; read source files directly.",
    Type.Object({
      backend: Type.String(),
      operation: Type.String(),
      address: Type.Optional(Type.String()),
      arguments: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
      target_id: Type.Optional(Type.String()),
    }),
    (p: any, s: any) => native.analyze(p, s),
  );
  for (const [name, operation, description] of [
    [
      "decompile",
      "decompile",
      "Get Ghidra pseudocode at a hexadecimal function address.",
    ],
    [
      "xrefs",
      "xrefs",
      "Find Ghidra cross-references at a hexadecimal address.",
    ],
    [
      "functions",
      "functions",
      "Discover Ghidra functions in the active program.",
    ],
  ])
    tool(
      name,
      description,
      Type.Object({ address: Type.Optional(Type.String()) }),
      (p: any, s: any) =>
        native.analyze({ backend: "ghidra", operation, address: p.address }, s),
    );
  tool(
    "native_command",
    "Use an existing IndagoRev CLI family directly, including runtime/debugger/captures/reanalysis, graph, transforms and validation. Arguments are an argv array, not shell text; request is optional native JSON. Project and workspace are supplied automatically. Use the shell for CLI help.",
    Type.Object({
      args: Type.Array(Type.String()),
      request: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
    }),
    (p: any, s: any) =>
      native.call(
        [...p.args, "--project", config.project],
        p.request ? { ...p.request, project: config.project } : undefined,
        { signal: s },
      ),
  );
  tool(
    "investigation_focus",
    "Set the current concrete question. Retrieves relevant local evidence and hypotheses; use when the investigation changes direction.",
    Type.Object({ question: Type.String() }),
    async (p: any) => {
      memory.focus(native.active.artifact_sha256, p.question);
      return {
        data: {
          question: p.question,
          records: memory.search(p.question, native.active.artifact_sha256),
        },
      };
    },
  );
  tool(
    "graph_context",
    "Retrieve a bounded native graph neighborhood around an observed entity ID or address. Preserve native relation kinds and uncertainty.",
    Type.Object({
      id: Type.Optional(Type.String()),
      address: Type.Optional(Type.String()),
      direction: Type.Optional(Type.String()),
      kinds: Type.Optional(Type.Array(Type.String())),
    }),
    (p: any, s: any) =>
      native.call(
        ["graph", "neighborhood"],
        {
          ...p,
          project: config.project,
          artifact: native.active.artifact_sha256,
          depth: 2,
          limit: 24,
          output_bytes: 16384,
        },
        { signal: s },
      ),
  );
  tool(
    "knowledge_search",
    "Search durable program findings. Results include evidence dependencies and freshness. Empty query lists records; use offset to page.",
    Type.Object({
      query: Type.Optional(Type.String()),
      offset: Type.Optional(Type.Number()),
    }),
    async (p: any, s: any) => {
      const r = await native.knowledge(
        "list",
        {
          artifact: native.active.artifact_sha256,
          search: p.query ?? "",
          offset: p.offset ?? 0,
          limit: 6,
        },
        s,
      );
      return {
        data: {
          ...r.data,
          local_matches: memory.search(
            p.query ?? "",
            native.active.artifact_sha256,
          ),
        },
        receipt: r.receipt,
      };
    },
  );
  tool(
    "run_experiment",
    "Run 1..8 named stdin/argument cases against the active native target and retain runtime receipts. Requires host mode. Files values are hex bytes. Results do not by themselves prove acceptance.",
    Type.Object({
      cases: Type.Array(
        Type.Object({
          label: Type.String(),
          argv: Type.Optional(Type.Array(Type.String())),
          stdin: Type.Optional(Type.String()),
          files: Type.Optional(Type.Record(Type.String(), Type.String())),
          environment: Type.Optional(Type.Record(Type.String(), Type.String())),
        }),
        { minItems: 1, maxItems: 8 },
      ),
    }),
    (p: any, s: any) => native.experiment(p.cases, s),
  );
  tool(
    "runtime",
    "Use existing native debugger, Frida, DynamoRIO, replay, capture, or reanalysis operations. Pass the native operation and its parameters; project is automatic. Discover operations with operation=capabilities.",
    Type.Object({
      operation: Type.String(),
      request: Type.Optional(Type.Record(Type.String(), Type.Unknown())),
    }),
    (p: any, s: any) =>
      native.call(
        ["runtime", p.operation],
        { ...p.request, project: config.project },
        { signal: s },
      ),
  );
  tool(
    "remember",
    "Save or correct an inferred program finding. Optional id updates a returned finding; revisions are automatic. Optional support accepts returned native evidence IDs; unfamiliar references remain unresolved. Cite receipt paths in the text for shell observations. This does not verify the assertion. Correct saved notes when your reasoning changes.",
    Type.Object({
      id: Type.Optional(Type.String()),
      title: Type.String(),
      text: Type.String(),
      support: Type.Optional(Type.Array(Type.String())),
      assumptions: Type.Optional(Type.Array(Type.String())),
    }),
    async (p: any, s: any) => {
      const r = await native.remember(p, s);
      memory.put({
        id: r.data.id,
        native_id: r.data.id,
        artifact: native.active.artifact_sha256,
        kind: "hypothesis",
        title: p.title,
        text: p.text,
      });
      return r;
    },
  );
  tool(
    "program_search",
    "Search native indexed program entities by name, string or constant. Returns graph navigation references; use normal file search for source.",
    Type.Object({ query: Type.String() }),
    (p: any, s: any) =>
      native.call(
        ["graph", "search"],
        {
          project: config.project,
          search: p.query,
          artifact: native.active.artifact_sha256,
          limit: 20,
        },
        { signal: s },
      ),
  );
  tool(
    "wsl",
    "Run a command in the selected WSL distribution. Use Linux paths for cwd. This is host access with the same authority as the normal shell.",
    Type.Object({
      command: Type.String(),
      cwd: Type.Optional(Type.String()),
      distribution: Type.Optional(Type.String()),
    }),
    async (p: any, s: any) => ({
      data: await runProcess(
        "wsl.exe",
        [
          ...(p.distribution ? ["--distribution", p.distribution] : []),
          ...(p.cwd ? ["--cd", p.cwd] : []),
          "--exec",
          "bash",
          "-lc",
          p.command,
        ],
        { signal: s, timeout: 120000 },
      ),
    }),
  );
  if (process.platform === "win32" && config.authority === "host")
    pi.registerTool({
      name: "screenshot",
      label: "Screenshot",
      description:
        "Capture the Windows virtual desktop. Image understanding requires a vision-enabled session.",
      parameters: Type.Object({}),
      async execute(_id: any, _p: any, signal: any) {
        const file = path.join(config.state, `screen-${Date.now()}.png`);
        const r = await runProcess(
          "powershell.exe",
          [
            "-NoProfile",
            "-File",
            path.join(
              path.dirname(fileURLToPath(import.meta.url)),
              "screenshot.ps1",
            ),
            "-Destination",
            file,
          ],
          { signal, timeout: 15000 },
        );
        if (r.code !== 0) throw Error(r.stderr);
        const bytes = fs.readFileSync(file);
        return {
          content: config.vision
            ? [
                {
                  type: "image",
                  data: bytes.toString("base64"),
                  mimeType: "image/png",
                },
              ]
            : [
                {
                  type: "text",
                  text: `Screenshot saved: ${file}. This session has no declared vision support.`,
                },
              ],
          details: { file, sha256: hash(bytes) },
        };
      },
    });
  pi.on("before_agent_start", async (event: any) => {
    let route = "";
    try {
      route = readable((await native.route()).data, 2000).text;
    } catch (e) {
      route = "Routing unavailable: " + String(e);
    }
    if (!memory.data.focus[native.active.artifact_sha256])
      memory.focus(
        native.active.artifact_sha256,
        event.prompt ?? config.prompt ?? "Inspect the active program",
      );
    return {
      systemPrompt:
        event.systemPrompt +
        `\nYou have native analysis and coding tools. Active program: ${native.active.path}. Discover additional tools with analysis_tools. Keep backend interpretations distinct. Save useful hypotheses with remember; investigation_focus changes the retrieval question.\n${guidance(native.active.path)}\nFormat hints (data): ${route}` + (enabled(config,'recipes') ? '\nRead '+path.join(import.meta.dirname,'recipes.md')+' when extracting a wrapper or decoding escaped/indexed data. It contains tested, general helper examples; do not invent format parsers.' : ''),
    };
  });
  pi.on("tool_call", (event: any) => {
    starts.set(event.toolCallId, Date.now());
    if (["bash", "powershell"].includes(event.toolName))
      event.input.timeout = Math.min(event.input.timeout ?? 30, 120);
    if (config.maxGenerations > 1 && generations >= config.maxGenerations - 1)
      return {
        block: true,
        reason:
          "Final generation reserved: report your supported answer or the exact unresolved blocker.",
      };
    const key = hash(JSON.stringify([event.toolName, event.input, revision]));
    if (
      (failures.get(key) ?? 0) >= 2 &&
      !["runtime", "run_experiment"].includes(event.toolName)
    )
      return {
        block: true,
        reason:
          "This unchanged call already failed twice. Inspect the error or change the helper/input before retrying.",
      };
    if(enabled(config,'progress') && !['runtime','run_experiment'].includes(event.toolName) && progress.blocked(event.toolName,event.input))return {block:true,reason:'Repeated unchanged inspection already ran twice, including successful results. Change the question/input or use artifact_inspect/native analysis. Do not repeat this call.'};
  });
  pi.on("tool_result", async (event: any) => {
    const text = JSON.stringify(event.content ?? []),
      key = hash(JSON.stringify([event.toolName, event.input, text]));
    const count = (history.get(key) ?? 0) + 1;
    history.set(key, count);
    recent.push(`${event.toolName}: ${text.slice(0, 900)}`);
    recent = recent.slice(-5);
    const id = hash(JSON.stringify([Date.now(), event.toolCallId, text]));
    atomic(path.join(config.state, "observations", id + ".json"), {
      tool: event.toolName,
      input: event.input,
      content: event.content,
      details: event.details,
      observed_at: new Date().toISOString(),
      elapsed_ms: Date.now() - (starts.get(event.toolCallId) ?? Date.now()),
      interpretation:
        "Tool receipt; no semantic validation or complete filesystem lineage implied",
    });
    const failed =
      event.isError ||
      /Traceback|SyntaxError|Command exited with code [1-9]|timed out/i.test(
        text,
      );
    if(enabled(config,'progress') && progress.observe(event.toolName,event.input,text))investigation.update({failure:'Repeated output from '+event.toolName+'. Change assumption or tool; previous output did not advance the investigation.'});
    if(enabled(config,'state') && failed)investigation.update({failure:event.toolName+': '+text.slice(-220)});
    const fingerprint = hash(
      JSON.stringify([event.toolName, event.input, revision]),
    );
    if (failed) failures.set(fingerprint, (failures.get(fingerprint) ?? 0) + 1);
    if (["write", "edit", "program_open"].includes(event.toolName) && !failed)
      revision++;
    if (config.mode === "knowledge" && !enabled(config,'state'))
      memory.put({
        artifact: native.active.artifact_sha256,
        kind: failed ? "failed_attempt" : "observation",
        title: `${event.toolName} ${JSON.stringify(event.input ?? {}).slice(0, 200)}`,
        text: excerpt(
          (event.content ?? [])
            .filter((c: any) => c.type === "text")
            .map((c: any) => c.text)
            .join("\n"),
          2400,
        ),
        receipt: path.join(config.state, "observations", id + ".json"),
      });
    if (
      config.mode === "knowledge" && !enabled(config,'state') &&
      ["bash", "powershell", "wsl", "write", "edit"].includes(event.toolName)
    )
      try {
        const saved = await native.knowledge("put", {
          kind: "product",
          state: "observed",
          title: `Tool receipt: ${event.toolName}`,
          scope: { artifact_sha256: native.active.artifact_sha256 },
          body: {
            type: "agent_tool_receipt",
            receipt: path.join(config.state, "observations", id + ".json"),
            content_sha256: hash(text),
            input: event.input,
            preview: text.slice(0, 1500),
            unknowns: [
              "No complete filesystem lineage or semantic correctness inferred",
            ],
          },
          support: [],
          counterevidence: [],
          assumptions: [],
          dependencies: [],
        });
        native.lastObservation = saved.data.id;
      } catch (e) {
        recent.push("Knowledge ingestion failed: " + String(e));
      }
    if (count >= 3)
      return {
        content: [
          ...(event.content ?? []),
          {
            type: "text",
            text: "Progress hint: the same call returned the same result at least three times. Inspect the error or intermediate representation, test a different assumption, or change tools. No automatic retry was performed.",
          },
        ],
      };
  });
  pi.on("context", async (event: any) => {
    if(enabled(config,'state'))return {messages:[...event.messages,{role:'user',content:[{type:'text',text:investigation.packet()}],timestamp:Date.now()}]};
    if (config.mode !== "knowledge") return;
    const messages = event.messages.map((m: any, i: number) =>
      m.role === "toolResult" && i < event.messages.length - 8
        ? {
            ...m,
            content: m.content.map((c: any) =>
              c.type === "text" ? { ...c, text: excerpt(c.text, 2200) } : c,
            ),
          }
        : m,
    );
    const visible = messages
      .map((m: any) =>
        typeof m.content === "string"
          ? m.content
          : (m.content ?? []).map((c: any) => c.text ?? "").join("\n"),
      )
      .join("\n");
    // Refresh only selected native assertions, never treat local text as a freshness authority.
    for (const record of memory.search(
      memory.data.focus[native.active.artifact_sha256] ?? "",
      native.active.artifact_sha256,
    )) {
      if (!record.native_id) continue;
      try {
        const current = (
          await native.knowledge("show", { id: record.native_id })
        ).data;
        record.stale = /stale|invalid|superseded/.test(
          JSON.stringify(current.freshness ?? current.state),
        );
        memory.put({ ...record, text: current.body?.text ?? record.text });
      } catch {
        memory.put({ ...record, stale: true });
      }
    }
    const packet = memory.packet(native.active.artifact_sha256, visible);
    atomic(path.join(config.state, "context-selection.json"), {
      selected: packet.selected,
      reason:
        "artifact-scoped lexical relevance; omit already visible exact text",
      chars: packet.text.length,
    });
    const text =
      packet.text +
      `\nRemaining generations: ${Math.max(0, (config.maxGenerations ?? 128) - generations)}. Keep an opportunity to submit a supported answer or unresolved blocker.`;
    return {
      messages: [
        ...messages,
        {
          role: "user",
          content: [{ type: "text", text }],
          timestamp: Date.now(),
        },
      ],
    };
  });
  pi.on("session_start", () => {
    const hidden = new Set([
      "decompile",
      "functions",
      "xrefs",
      "runtime",
      "run_experiment",
      "wsl",
      "graph_context",
    ]);
    pi.setActiveTools(
      pi.getActiveTools().filter((name: string) => !hidden.has(name) || (enabled(config,'surface') && ['decompile','functions','xrefs'].includes(name) && /\.(exe|dll|elf|bin)$/i.test(config.active.path))),
    );
  });
  pi.on("session_before_compact", () => {
    atomic(path.join(config.state, "compaction-checkpoint.json"), {
      active: native.active,
      recent,
      at: new Date().toISOString(),
    });
  });
}
