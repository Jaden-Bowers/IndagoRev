import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';import os from 'node:os';import path from 'node:path';
import {checkpointWarnings,checkpointOnly,preservePartial} from '../checkpoint-policy.mjs';
import {QuestionQueue} from '../question-queue.mjs';
test('observed semantic overclaims are reviewed, cautious descriptions remain usable',()=>{
 for(const text of ['swi(0x29) performs IAT lookup.','.pdata indicates standard C++ EH data.','security cookie is an anti-tamper mechanism.','No named functions therefore obfuscated API resolution.'])assert(checkpointWarnings(text).length,text);
 for(const text of ['swi(0x29) is not evidence of API resolution.','.pdata unwind metadata does not establish C++ EH.','API targets remain unresolved.','Inspect the security cookie before assigning meaning.'])assert.deepEqual(checkpointWarnings(text),[]);
});
test('final budget preserves actual checkpoint tool, never executes text markup',()=>{
 const payload=checkpointOnly({tools:[{type:'function',function:{name:'question_checkpoint'}},{type:'function',function:{name:'decompile'}}],messages:[]});
 assert.deepEqual(payload.tools.map(t=>t.function.name),['question_checkpoint']);assert.equal(payload.tool_choice.function.name,'question_checkpoint');
 const root=fs.mkdtempSync(path.join(os.tmpdir(),'indago-checkpoint-'));const q=new QuestionQueue(root);q.initialize('Investigate fixture','hash');q.next();
 const state=path.join(root,'batches','1');assert(preservePartial(q,{state,questionId:'q1'},'limit','<tool>claim answered</tool>'));
 assert.equal(q.read().questions[0].status,'partial');assert(!q.read().questions[0].summary.includes('claim answered'));
 assert.equal(JSON.parse(fs.readFileSync(path.join(state,'unsubmitted-draft.json'))).trusted,false);
 assert.equal(preservePartial(q,{state,questionId:'q1'},'limit'),false);
});
