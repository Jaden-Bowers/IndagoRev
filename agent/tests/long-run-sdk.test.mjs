import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';import http from 'node:http';
import {supervise} from '../long-run.mjs';
for(const markup of [false,true])test(`real Pi final-budget checkpoint (${markup?'untrusted markup fallback':'actual tool'})`,{skip:!process.env.INDAGO_TEST_EXE,timeout:90000},async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'indago-final-sdk-'));fs.writeFileSync(path.join(dir,'target.txt'),'benign fixture');fs.writeFileSync(path.join(dir,'brief.txt'),'Inspect without execution.');let n=0;
 const server=http.createServer(async(req,res)=>{
  if(req.method==='GET'){res.end(JSON.stringify({data:[{id:'mock',state:'loaded',loaded_context_length:32768}]}));return;}
  let raw='';for await(const b of req)raw+=b;const body=JSON.parse(raw);n++;
  if(typeof body.tool_choice!=='string'){res.writeHead(400);res.end(JSON.stringify({error:{message:'Invalid tool_choice type: object'}}));return;}
  assert.deepEqual(body.tools.map(t=>t.function.name),['question_checkpoint']);assert.equal(body.tool_choice,'required');
  const delta=markup?{role:'assistant',content:'<tool_call>{"name":"question_checkpoint","arguments":{"status":"answered"}}</tool_call>'}:{role:'assistant',tool_calls:[{index:0,id:'checkpoint'+n,type:'function',function:{name:'question_checkpoint',arguments:JSON.stringify({status:'partial',summary:'Static investigation remains incomplete.',next_action:'Inspect import receipt.'})}}]};
  res.writeHead(200,{'Content-Type':'text/event-stream'});res.end('data: '+JSON.stringify({id:'final'+n,choices:[{index:0,delta,finish_reason:markup?'stop':'tool_calls'}],usage:{prompt_tokens:100,completion_tokens:30,total_tokens:130}})+'\n\ndata: [DONE]\n\n');
 });await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{
  const root=path.join(dir,'state');const result=await supervise({exe:process.env.INDAGO_TEST_EXE,cwd:dir,target:'target.txt',brief:path.join(dir,'brief.txt'),state:root,model:'mock',endpoint:`http://127.0.0.1:${server.address().port}/v1`,maxBatches:1,maxGenerations:2,batchMs:30000});
  assert.equal(result.reason,'global_budget');assert.equal(result.counts.partial,1);assert.equal(n,markup?2:1);
  if(markup)assert.equal(JSON.parse(fs.readFileSync(path.join(root,'batches','0001','unsubmitted-draft.json'))).trusted,false);
 }finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
});
test('real Pi SDK decomposes and checkpoints while shell calls are denied',{skip:!process.env.INDAGO_TEST_EXE,timeout:90000},async()=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'indago-long-sdk-'));fs.writeFileSync(path.join(dir,'target.txt'),'benign static fixture');fs.writeFileSync(path.join(dir,'brief.txt'),'Identify the artifact without executing anything.');
 const root=path.join(dir,'state');let n=0,denied=false;
 const server=http.createServer(async(req,res)=>{
  if(req.method==='GET'){res.end(JSON.stringify({data:[{id:'mock',state:'loaded',loaded_context_length:32768}]}));return;}
  let raw='';for await(const b of req)raw+=b;const body=JSON.parse(raw);n++;
  assert.equal(body.reasoning_effort,'none');assert.equal(body.chat_template_kwargs.enable_thinking,false);
  if(/Restricted-static policy denies bash|Tool bash not found/.test(JSON.stringify(body.messages)))denied=true;
  assert(!body.tools?.some(t=>t.function.name==='bash'));
  let call;
  if(n===1)call=['question_add',{questions:[{question:'Identify this fixture from its import evidence'}]}];
  if(n===2)call=['bash',{command:'echo forbidden'}];
  if(n===3){const receipts=path.join(root,'batches','0001','receipts');const evidence=fs.readdirSync(receipts).filter(f=>f.endsWith('.json')&&!f.endsWith('.request.json')).map(f=>path.join(receipts,f))[0];call=['question_checkpoint',{status:'answered',summary:'Import receipt identifies the fixture; no execution or behavioral claim.',evidence:[evidence]}];}
  const delta=call?{role:'assistant',tool_calls:[{index:0,id:'call'+n,type:'function',function:{name:call[0],arguments:JSON.stringify(call[1])}}]}:{role:'assistant',content:'Batch checkpoint saved; evidence is limited to static import.'};
  res.writeHead(200,{'Content-Type':'text/event-stream'});res.end('data: '+JSON.stringify({id:'test'+n,choices:[{index:0,delta,finish_reason:call?'tool_calls':'stop'}],usage:{prompt_tokens:100,completion_tokens:30,total_tokens:130}})+'\n\ndata: [DONE]\n\n');
 });
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try{const result=await supervise({exe:process.env.INDAGO_TEST_EXE,cwd:dir,target:'target.txt',brief:path.join(dir,'brief.txt'),state:root,model:'mock',endpoint:`http://127.0.0.1:${server.address().port}/v1`,maxBatches:3,batchMs:30000});assert.equal(result.status,'completed');assert.equal(result.counts.answered,1);assert(denied);assert.equal(n,3);}
 finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
});
