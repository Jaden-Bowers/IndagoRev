import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {Desktop,selection,displayMessage} from '../desktop.mjs';
test('Restored chat displays the human message without replaying raw reference JSON',()=>{
 assert.equal(displayMessage({role:'user',content:'Human request:\nExplain x\n\nActive file: example\nQuoted evidence: ...'}),'\nYou:\nExplain x\n');
 assert.equal(displayMessage({role:'assistant',content:[],stopReason:'error',errorMessage:'offline'}),'\nAgent:\nProvider error: offline\n');
});
test('GUI selection maps UTF-8 bytes to Ghidra UTF-16 tokens and preserves identity',()=>{
 const v={file:'sample',hash:'abc',kind:'tokens',backend:'ghidra',revision:7,address:'0x10',text:'x\né😀 test',tokens:[{rendered_offset:2,rendered_end:5,min_address:'0x12',max_address:'0x13',symbol_id:'5'}]};
 const r=selection(v,2,8);assert.equal(r.text,'é😀');assert.equal(r.line_start,2);assert.equal(r.program_revision,7);assert.equal(r.locations[0].symbol_id,'5');assert.throws(()=>selection(v,3,8));assert.throws(()=>selection(v,0,0));assert.throws(()=>selection(v,0,999));
 assert.throws(()=>selection(v,4,7),/UTF-8/);
});
test('GUI source saves reject concurrent edits, traversal and stale references',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'indago-ui-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));fs.writeFileSync(path.join(dir,'sample.cpp'),'int value = 7;\n');
 const app=new Desktop();app.config={cwd:fs.realpathSync(dir)};app.native={};
 const {view}=await app.request({op:'open',path:'sample.cpp'});const ref=await app.request({op:'reference',view:view.id,start:4,end:9});assert.equal(ref.text,'value');
 fs.writeFileSync(path.join(dir,'sample.cpp'),'external edit');await assert.rejects(app.request({op:'save',view:view.id,text:'overwrite'}),/changed/);assert.equal(fs.readFileSync(path.join(dir,'sample.cpp'),'utf8'),'external edit');
 await assert.rejects(app.request({op:'reference',view:view.id,start:0,end:3}),/Stale/);await assert.rejects(app.request({op:'tree',path:'..'}),/outside/);
 const opened=await app.request({op:'open',path:'sample.cpp'});const saved=await app.request({op:'save',view:opened.view.id,text:'saved'});assert.equal(saved.text,'saved');assert.equal(app.refs.size,0);
});
test('GUI annotation forwards revision and does not relabel backend semantics',async()=>{
 const app=new Desktop();let sent;app.native={analyze:async q=>{sent=q;return {data:{status:'completed'}}}};app.config={};
 await app.request({op:'annotate',revision:3,address:'0x20',annotation:{kind:'rename',name:'decode'}});assert.equal(sent.arguments.expected_revision,3);assert.equal(sent.backend,'ghidra');
 await assert.rejects(app.request({op:'annotate',address:'0x20',annotation:{kind:'rename',name:'x'}}),/revision/);
});
test('GUI cancel is accepted while work is pending',async()=>{
 const app=new Desktop();app.abort=new AbortController();const signal=app.abort.signal;assert.equal((await app.request({op:'cancel'})).cancel_requested,true);assert.equal(signal.aborted,true);
});
test('Provider errors cannot be reported as a successful chat; settings propagate without secrets',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'indago-ui-provider-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const file=path.join(dir,'sample.c');fs.writeFileSync(file,'int n;');let options;
 const app=new Desktop(()=>{},async o=>{options=o;o.onEvent({type:'message_end',message:{role:'assistant',stopReason:'error',errorMessage:'mock unavailable'}});return {code:0};});
 app.config={cwd:dir,state:path.join(dir,'state')};app.file=file;app.native={import:async()=>{}};
 app.providerInfo=async r=>{if(r.endpoint==='http://example.invalid/v1')throw Error('Remote providers require HTTPS');return {contextTokens:8192,source:'mock provider'};};
 await assert.rejects(app.request({op:'chat',text:'Explain n',provider:'custom',endpoint:'https://example.invalid/v1',contextTokens:8192,outputTokens:512,apiKeyEnv:'TEST_KEY'}),/Provider error/);
 assert.equal(options.contextTokens,8192);assert.equal(options.apiKeyEnv,'TEST_KEY');assert.equal(JSON.parse(fs.readFileSync(path.join(dir,'state/ui.json'))).outputTokens,512);
 await assert.rejects(app.request({op:'chat',text:'x',endpoint:'http://example.invalid/v1'}),/HTTPS/);
});
