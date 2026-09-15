import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {Desktop,selection} from '../desktop.mjs';
import {collect,initialFunction,providerInfo} from '../desktop-analysis.mjs';

test('context uses loaded provider limit, not model maximum or GUI override',async()=>{
 const fetcher=async()=>({ok:true,json:async()=>({models:[{key:'qwen',max_context_length:262144,loaded_instances:[{id:'qwen',config:{context_length:23552}}]}]})});
 assert.equal((await providerInfo({model:'qwen',contextTokens:65536},undefined,fetcher)).contextTokens,23552);
 assert.equal((await providerInfo({model:'unloaded'},undefined,fetcher)).contextTokens,null);
 await assert.rejects(providerInfo({endpoint:'http://remote.invalid/v1'}),/HTTPS/);
});
test('pagination retains all addresses and rejects repeated or stale continuations',async()=>{
 const native={analyze:async q=>({data:{status:'partial',data:{program_revision:1,instructions:[{address:q.arguments.cursor?'0x20':'0x10'}],pagination:{next_cursor:q.arguments.cursor?null:'next'}}}})};
 assert.equal((await collect(native,'assembly','')).items.length,2);
 native.analyze=async()=>({data:{data:{program_revision:1,instructions:[],pagination:{next_cursor:'same'}}}});
 await assert.rejects(collect(native,'assembly',''),/converge/);
 assert.equal(initialFunction([{name:'entry',entry:'0x10'},{name:'main',entry:'0x20'}],'0x10'),'0x20');
});
test('large listing IPC chunks preserve Unicode and original reference offsets',async()=>{
 const emitted=[],app=new Desktop(e=>emitted.push(e.listing));app.file='sample';
 const text=('é😀 return;\n').repeat(2000),tokens=[{rendered_offset:18000,rendered_end:18006,min_address:'0x42',max_address:'0x42'}];
 await app.publishView({text,tokens,hash:'abc',kind:'tokens'});
 assert.ok(emitted.length>1);assert.equal(emitted.map(c=>c.text).join(''),text);
 for(const c of emitted){assert.ok(c.text.length<=8192);assert.equal(Buffer.from(text).subarray(c.byte_base,c.byte_base+Buffer.byteLength(c.text)).toString(),c.text);}
 const part=emitted.find(c=>c.tokens.length);assert.ok(part.tokens[0].rendered_offset<part.text.length);
 assert.equal(new Set(emitted.map(c=>c.id)).size,1);
});
test('binary click is read-only; full listings persist, reopen reuses, revisions invalidate',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'indago-listing-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 fs.writeFileSync(path.join(dir,'sample.exe'),'MZtest');let calls=[],revision=1;const events=[];
 const app=new Desktop(e=>events.push(e));app.config={cwd:fs.realpathSync(dir),state:path.join(dir,'state')};
 app.native={import:async()=>calls.push('import'),analyze:async q=>{
  calls.push(q.operation);
  let data={program_revision:revision};
  if(q.operation==='functions')data.functions=[{name:'entry',entry:'0x10'},{name:'main',entry:'0x20'}];
  if(q.operation==='tokens')data.decompilation={native_verdict:'completed',rendered_c:'return 1;\n',tokens:[{rendered_offset:0,rendered_end:9,min_address:q.address,max_address:q.address}]};
  if(q.operation==='assembly')data.instructions=[{address:'0x10',text:'RET'},{address:'0x20',text:'RET'},{address:'0x30',text:'NOP'}];
  if(q.operation==='inventory')data.program={entry:'0x10'};
  return {data:{status:'completed',data,evidence_ids:['ev1']}};
 }};
 const opened=await app.request({op:'open',path:'sample.exe'});assert.equal(opened.needs_analysis,true);assert.deepEqual(calls,[]);
 await assert.rejects(app.request({op:'program',path:'sample.exe'}),/confirmation/);assert.deepEqual(calls,[]);
 const first=await app.request({op:'program',path:'sample.exe',confirm:true});assert.equal(first.functions,2);assert.equal(first.initial,'0x20');
 assert.equal(events.filter(e=>e.listing).length,3);assert.match(events.find(e=>e.listing?.kind==='assembly').listing.text,/0x30/);
 calls=[];events.length=0;
 assert.equal((await app.request({op:'open',path:'sample.exe'})).previous_analysis,true);
 await app.request({op:'program',path:'sample.exe'});assert.deepEqual(calls,['import','session']);
 const v=events.find(e=>e.listing?.kind==='tokens').listing;
 app.views.clear();assert.equal((await app.request({op:'reference',view:v.id,start:0,end:9})).locations[0].min_address,'0x10');
 revision=2;calls=[];await app.request({op:'program',path:'sample.exe'});assert.ok(calls.includes('tokens'));
 fs.appendFileSync(path.join(dir,'sample.exe'),'changed');assert.equal((await app.request({op:'open',path:'sample.exe'})).needs_analysis,true);
});
test('cancelled whole-program pass resumes completed functions',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'indago-resume-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));fs.writeFileSync(path.join(dir,'a.exe'),'MZ');
 const app=new Desktop();app.config={cwd:dir,state:path.join(dir,'state')};let cancel=true,tokens=0;
 app.native={import:async()=>{},analyze:async q=>{
  if(q.operation==='tokens'&&q.address==='0x20'&&cancel){app.abort.abort();app.abort.signal.throwIfAborted();}
  const d={program_revision:1};if(q.operation==='functions')d.functions=[{name:'main',entry:'0x10'},{name:'other',entry:'0x20'}];
  if(q.operation==='tokens'){tokens++;d.decompilation={native_verdict:'completed',rendered_c:'x;',tokens:[]};}
  if(q.operation==='assembly')d.instructions=[];
  return {data:{status:'completed',data:d}};
 }};
 await assert.rejects(app.request({op:'program',path:'a.exe',confirm:true}));assert.equal(tokens,1);
 cancel=false;await app.request({op:'program',path:'a.exe'});assert.equal(tokens,2);
});
