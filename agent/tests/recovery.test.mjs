import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { launch } from "../cli.mjs";
test('third unchanged failing helper is blocked and shell calls have a deadline', {skip:!process.env.INDAGO_TEST_EXE,timeout:30000},async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'indago-repeat-'));
  fs.writeFileSync(path.join(dir,'sample.txt'),'repeat fixture');
  const requests=[];
  const server=http.createServer(async(req,res)=>{
    let raw='';for await(const b of req)raw+=b;
    const body=JSON.parse(raw);requests.push(body);
    const n=requests.length;
    const delta=n<=3?{role:'assistant',tool_calls:[{index:0,id:'repeat'+n,type:'function',function:{name:'bash',arguments:JSON.stringify({command:'exit 7'})}}]}:{role:'assistant',content:'Repeated helper failure; unresolved.'};
    res.writeHead(200,{'Content-Type':'text/event-stream'});
    res.end('data: '+JSON.stringify({id:'repeat',model:body.model,choices:[{index:0,delta,finish_reason:n<=3?'tool_calls':'stop'}],usage:{prompt_tokens:30,completion_tokens:10,totalTokens:40}})+'\n\ndata: [DONE]\n\n');
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  try {
    const state=path.join(dir,'state');
    const r=await launch({exe:process.env.INDAGO_TEST_EXE,cwd:dir,target:'sample.txt',state,mode:'knowledge',endpoint:`http://127.0.0.1:${server.address().port}/v1`,model:'mock',prompt:'Check failure recovery.',maxGenerations:6,timeout:20000});
    assert.equal(r.code,0);assert.equal(requests.length,4);
    assert(JSON.stringify(requests[3].messages).includes('already failed twice'));
    const observations=fs.readdirSync(path.join(state,'observations')).map(f=>JSON.parse(fs.readFileSync(path.join(state,'observations',f))));
    assert(observations.filter(r=>r.tool==='bash').every(r=>r.input.timeout===30));
  } finally {server.closeAllConnections();await new Promise(r=>server.close(r));}
});
test(
  "real Pi recovers a length stop and sends explicit OpenRouter reasoning control",
  { skip: !process.env.INDAGO_TEST_EXE, timeout: 30000 },
  async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "indago-recovery-"));
    fs.writeFileSync(
      path.join(dir, "sample.txt"),
      "synthetic recovery fixture",
    );
    const requests = [];
    const server = http.createServer(async (req, res) => {
      let raw = "";
      for await (const b of req) raw += b;
      const body = JSON.parse(raw);
      requests.push(body);
      res.writeHead(200, { "Content-Type": "text/event-stream" });
      const final = requests.length > 1;
      res.end(
        "data: " +
          JSON.stringify({
            id: "recovery",
            model: body.model,
            choices: [
              {
                index: 0,
                delta: {
                  role: "assistant",
                  content: final
                    ? "Recovered with no unsupported answer."
                    : "Partial",
                },
                finish_reason: final ? "stop" : "length",
              },
            ],
            usage: {
              prompt_tokens: 30,
              completion_tokens: 10,
              total_tokens: 40,
            },
          }) +
          "\n\ndata: [DONE]\n\n",
      );
    });
    await new Promise((r) => server.listen(0, "127.0.0.1", r));
    try {
      const result = await launch({
        exe: process.env.INDAGO_TEST_EXE,
        cwd: dir,
        target: "sample.txt",
        state: path.join(dir, "state"),
        mode: "knowledge",
        provider: "openrouter",
        endpoint: `http://127.0.0.1:${server.address().port}/v1`,
        model: "mock",
        prompt: "Synthetic recovery check",
        maxGenerations: 2,
        timeout: 20000,
      });
      assert.equal(result.code, 0);
      assert.equal(requests.length, 2);
      assert.deepEqual(requests[0].reasoning, { enabled: false });
      assert.equal(requests[1].tool_choice, "none");
      assert(!requests[0].tools.some((t) => t.function.name === "runtime"));
      assert(
        requests[0].tools.some((t) => t.function.name === "analysis_tools"),
      );
      assert.equal(
        fs.readdirSync(path.join(dir, "state/context-manifests")).length,
        2,
      );
    } finally {
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
    }
  },
);
