import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {QuestionQueue} from '../question-queue.mjs';import {atomic} from '../native.mjs';
test('durable decomposition, dependencies, evidence and interrupted attempts',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'indago-queue-'));const q=new QuestionQueue(root);
 q.initialize('Map the program','abc');q.next();q.add([{question:'Find entry'},{question:'Explain entry',dependencies:['q2']}],'q1');
 assert.equal(q.next().id,'q2');assert.throws(()=>q.checkpoint('q2',{status:'answered',summary:'yes'}));
 atomic(path.join(root,'batch','receipts','1.json'),{observed:'entry'});
 q.checkpoint('q2',{status:'answered',summary:'entry observed',evidence:['batch/receipts/1.json']});
 assert.equal(q.next().id,'q3');assert.equal(new QuestionQueue(root).next().attempts,2);assert.equal(q.next().attempts,3);assert.equal(q.next(),undefined);
 assert.equal(q.read().questions[2].status,'blocked');assert.throws(()=>q.initialize('changed','abc'));
});
test('queue rejects duplicate questions and self dependencies',()=>{
 const q=new QuestionQueue(fs.mkdtempSync(path.join(os.tmpdir(),'indago-queue-')));q.initialize('brief','a');
 assert.throws(()=>q.add([{question:'brief'}],'q1'));assert.throws(()=>q.add([{question:'child',dependencies:['q1']}],'q1'));
});
test('changed evidence invalidates an answered question',()=>{
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'indago-queue-'));const q=new QuestionQueue(root);q.initialize('brief','a');q.next();const receipt=path.join(root,'receipts','proof.json');atomic(receipt,{data:'original'});
 q.checkpoint('q1',{status:'answered',summary:'supported',evidence:[receipt]});atomic(receipt,{data:'changed'});assert.equal(q.next(),undefined);assert.equal(q.read().questions[0].status,'blocked');
});
