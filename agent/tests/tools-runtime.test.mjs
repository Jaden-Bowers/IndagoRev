import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import contracts from '../native-contracts.mjs';
import {ToolAdapters} from '../tool-adapters.mjs';
import {hashFile} from '../native.mjs';
import {validate} from '../tool-registry.mjs';
function setup(t){const state=fs.mkdtempSync(path.join(os.tmpdir(),'indago-runtime-adapters-'));t.after(()=>fs.rmSync(state,{recursive:true,force:true}));const file=path.join(state,'fixture');fs.writeFileSync(file,'fixture');const calls=[],config={state,project:'test',authority:'analysis',toolCapabilities:{backends:[]}};const native={active:{path:file,id:'t1',artifact_sha256:hashFile(file)},call:async(args,request)=>{calls.push({args,request});return {data:{status:'completed',id:'run_1'}};}};return {app:new ToolAdapters(native,config),native,config,calls,state};}
test('every runtime contract operation has a typed route and native-compatible fields',t=>{
 const {app}=setup(t);for(const op of contracts['runtime-action'].properties.operation.enum){const entry=app.registry.get('runtime_'+op.replaceAll('-','_'));assert.equal(entry.route.operation,op);for(const field of Object.keys(entry.schema.properties))assert.ok(contracts['runtime-action'].properties[field],field);}
});
test('runtime binds the hashed active file; denies ungranted execution and override fields',async t=>{
 const {app,config,calls}=setup(t);await assert.rejects(app.execute('runtime_io_run',{input_hex:''}),/host authority/);assert.equal(calls.length,0);
 config.authority='host';await app.execute('runtime_io_run',{input_hex:'4142',timeout_ms:1000});const p=calls[0].request;assert.equal(p.project,'test');assert.equal(p.trusted_target_ack,true);validate(contracts['runtime-action'],{...p,operation:'io-run'});
 await assert.rejects(app.execute('runtime_continue',{}),/missing session/);await assert.rejects(app.execute('runtime_io_run',{input_hex:'',file:'another'}),/unknown field/);
});
test('uncertain runtime side effects are retained and not blindly repeated',async t=>{
 const {app,config,native,state}=setup(t);config.authority='host';native.call=async()=>{throw Error('transport timeout');};await assert.rejects(app.execute('runtime_continue',{session:'run_1'}),/timeout/);assert.ok(fs.existsSync(path.join(state,'runtime-pending.json')));await assert.rejects(app.execute('runtime_continue',{session:'run_1'}),/uncertain/);
});
