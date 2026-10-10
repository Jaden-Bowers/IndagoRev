import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {ToolAdapters} from '../tool-adapters.mjs';
import {Native,hashFile,redactControlSecrets} from '../native.mjs';
import {workbenchRoutes} from '../tools-workbench.mjs';
function setup(t){const state=fs.mkdtempSync(path.join(os.tmpdir(),'indago-workbench-tools-'));t.after(()=>fs.rmSync(state,{recursive:true,force:true}));const file=path.join(state,'input');fs.writeFileSync(file,'ABCD');const config={state,cwd:state,workspace:path.join(state,'native'),project:'test',authority:'analysis',allowHelpers:true,toolCapabilities:{backends:[],workbench:{families:Object.fromEntries(Object.entries(workbenchRoutes).map(([k,v])=>[k,Object.keys(v)]))}}};const calls=[];const native={active:{path:file,id:'t1',artifact_sha256:hashFile(file)},call:async(args,request)=>{calls.push({args,request});return {data:{status:'completed',id:'inv_1',owner_token:'SECRET',revision:1,investigation_revision:2}};}};return {app:new ToolAdapters(native,config),native,config,calls};}
test('workbench coverage is complete and binds active artifact without transport overrides',async t=>{
 const {app,config,calls}=setup(t);assert.ok(app.registry.coverage(config.toolCapabilities).every(r=>r.status==='direct'));
 await app.execute('transform_run',{offset:0,size:4,spec:{method:'xor',key_hex:'01'}});assert.equal(calls[0].request.artifact,app.native.active.artifact_sha256);
 await assert.rejects(app.execute('transform_run',{spec:{method:'slice'},project:'other'}),/unknown/);
 await assert.rejects(app.execute('retention_quarantine',{plan_digest:'a'.repeat(64)}),/operator/);
});
test('workflow uses native external ownership and never places owner tokens in model-facing arguments',async t=>{
 const {app,calls}=setup(t);await app.execute('helper_run',{language:'python3',source_code:'print(1)',input:{generated_hex:''}});
 assert.deepEqual(calls.map(c=>c.args[1]),['create','show','propose','run']);const proposal=calls[2].request;assert.equal(proposal.owner_token,'SECRET');assert.equal(proposal.request.operation,'helper.run');assert.equal(proposal.request.arguments.input.generated_hex,'');
 const saved=fs.readFileSync(path.join(app.config.state,'workflow-owners',app.native.active.artifact_sha256+'.json'),'utf8');assert.ok(!saved.includes('SECRET'));
 assert.equal(redactControlSecrets({nested:{owner_token:'SECRET'}}).nested.owner_token,'[redacted]');
 await assert.rejects(app.execute('experiment_run',{engine:'io',cases:[{label:'a',input_hex:''}],prediction:'observe'}),/Host authority/);
});
test('real native workbench transforms and external-owner reads',{skip:!process.env.INDAGO_TEST_EXE,timeout:180000},async t=>{
 const {config}=setup(t);config.exe=process.env.INDAGO_TEST_EXE;const native=new Native(config);await native.call(['project','create','--name',config.project]);await native.import(path.join(config.state,'input'));config.active=native.active;
 const app=new ToolAdapters(native,config);
 const transformed=await app.execute('transform_run',{offset:0,size:4,spec:{method:'xor',key_hex:'01'}});assert.equal(transformed.isError,false);
 const read=await app.execute('artifact_read',{offset:0,max_bytes:4});assert.equal(read.isError,false);assert.match(JSON.stringify(read),/41424344/);
 const helper=await app.execute('helper_capabilities',{});assert.equal(helper.isError,false);assert.match(JSON.stringify(helper),/isolation_probe_required/);
 const status=await app.execute('workflow_status',{});assert.equal(status.isError,false);
});
