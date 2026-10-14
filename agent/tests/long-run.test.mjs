import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {supervise} from '../long-run.mjs';import {QuestionQueue} from '../question-queue.mjs';import {atomic} from '../native.mjs';
import {preservePartial} from '../checkpoint-policy.mjs';
function fixture(){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'indago-long-'));fs.writeFileSync(path.join(dir,'sample'),'benign');fs.writeFileSync(path.join(dir,'brief.txt'),'Map the benign sample');return {exe:process.execPath,cwd:dir,target:'sample',state:path.join(dir,'state'),brief:path.join(dir,'brief.txt'),model:'mock',maxBatches:6};}
const resolveContext=async()=>({contextTokens:32768,outputTokens:2048});
test('reviewed frontend upgrades preserve budgets and retain old identity',async()=>{
 const o=fixture();await supervise(o,{resolveContext:async()=>{throw Error('offline');}});
 const file=path.join(o.state,'supervisor.json'),old=JSON.parse(fs.readFileSync(file));old.identity.frontend_sha256='old-version';atomic(file,old);
 await assert.rejects(supervise(o,{resolveContext}),/identity/);
 await assert.rejects(supervise({...o,acceptFrontendUpdate:true},{resolveContext}),/reviewed paused/);
 await supervise({...o,acceptFrontendUpdate:true,acknowledgeInterruption:true},{resolveContext:async()=>{throw Error('offline');}});
 assert.equal(fs.readdirSync(path.join(o.state,'implementation-updates')).length,1);
 const updated=JSON.parse(fs.readFileSync(file));assert.deepEqual(updated.limits,old.limits);assert.equal(updated.tokens,old.tokens);
});
test('controller partial checkpoint recovers invalid markup but not timeouts',async()=>{
 for(const timedOut of [false,true]){
  const o=fixture();o.maxBatches=1;
  const result=await supervise(o,{resolveContext,launchBatch:async c=>{
   atomic(path.join(c.state,'unresolved.json'),{reason:'invalid_final_tool_markup'});
   preservePartial(new QuestionQueue(c.queueDirectory),c,'limit','<tool>untrusted</tool>');return {code:0,timedOut};
  }});
  assert.equal(result.counts.partial,1);
  assert.equal(result.reason,timedOut?'batch_interrupted_review_receipts_before_resume':'global_budget');
 }
});
test('supervisor decomposes, carries native identity, checkpoints and resumes without extra work',async()=>{
 const o=fixture();let calls=0;
 const launchBatch=async c=>{calls++;assert(c.restrictedStatic);assert.equal(c.authority,'analysis');const q=new QuestionQueue(c.queueDirectory);
  atomic(path.join(c.state,'config.json'),{active:{id:'target',artifact_sha256:'fixture'}});
  if(c.questionId==='q1')q.add([{question:'Find architecture'}],'q1');else{assert.equal(c.active.id,'target');atomic(path.join(c.state,'receipts','proof.json'),{architecture:'test'});q.checkpoint(c.questionId,{status:'answered',summary:'Fixture architecture',evidence:[path.join(c.state,'receipts','proof.json')]});}
  c.onEvent({type:'message_end',message:{role:'assistant',usage:{input:100,output:20}}});return {code:0};};
 const result=await supervise(o,{launchBatch,resolveContext});assert.equal(result.status,'completed');assert.equal(result.tokens,240);assert.equal(result.counts.answered,1);assert.equal(result.independently_verified,false);
 await supervise(o,{launchBatch,resolveContext});assert.equal(calls,2);
});
test('no checkpoint progress pauses and interrupted runs do not auto retry',async()=>{
 const o=fixture();let calls=0;const r=await supervise(o,{resolveContext,launchBatch:async()=>{calls++;return {code:0};}});assert.equal(r.reason,'no_checkpoint_progress');assert.equal(calls,2);
 const other=fixture();const failed=await supervise(other,{resolveContext,launchBatch:async()=>({code:1,timedOut:true})});assert.equal(failed.batches,1);assert.equal(failed.reason,'batch_interrupted_review_receipts_before_resume');
});
test('exclusive lock, missing provider and changed targets fail closed',async()=>{
 const o=fixture();fs.mkdirSync(o.state);fs.writeFileSync(path.join(o.state,'supervisor.lock'),'old');await assert.rejects(supervise(o,{resolveContext}),/lock/);fs.unlinkSync(path.join(o.state,'supervisor.lock'));
 const r=await supervise(o,{resolveContext:async()=>{throw Error('offline');},launchBatch:async()=>assert.fail()});assert.match(r.reason,/provider_preflight/);
 fs.writeFileSync(path.join(o.cwd,'sample'),'changed');await assert.rejects(supervise(o,{resolveContext}),/identity/);
});
test('global token and batch budgets, stop file and interrupted acknowledgement',async()=>{
 const o=fixture();o.maxBatches=1;let calls=0;
 let r=await supervise(o,{resolveContext,launchBatch:async()=>{calls++;return {code:0};}});assert.equal(r.reason,'global_budget');assert.equal(calls,1);
 const tokenCase=fixture();tokenCase.maxTokens=10;
 r=await supervise(tokenCase,{resolveContext,launchBatch:async c=>{c.onEvent({type:'message_end',message:{role:'assistant',usage:{input:20,output:5}}});return {code:0};}});assert.equal(r.tokens,25);assert.equal(r.batches,1);
 await assert.rejects(supervise(tokenCase,{resolveContext}),/needs review/);
 const stopped=fixture();fs.mkdirSync(stopped.state);fs.writeFileSync(path.join(stopped.state,'STOP'),'');
 r=await supervise(stopped,{resolveContext,launchBatch:async()=>assert.fail()});assert.equal(r.reason,'operator_stop_file');
});
