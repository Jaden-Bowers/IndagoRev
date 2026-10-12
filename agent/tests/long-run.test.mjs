import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {supervise} from '../long-run.mjs';import {QuestionQueue} from '../question-queue.mjs';import {atomic} from '../native.mjs';
function fixture(){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'indago-long-'));fs.writeFileSync(path.join(dir,'sample'),'benign');fs.writeFileSync(path.join(dir,'brief.txt'),'Map the benign sample');return {exe:process.execPath,cwd:dir,target:'sample',state:path.join(dir,'state'),brief:path.join(dir,'brief.txt'),model:'mock',maxBatches:6};}
const resolveContext=async()=>({contextTokens:32768,outputTokens:2048});
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
