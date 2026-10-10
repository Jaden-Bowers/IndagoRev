import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {Native} from '../native.mjs';
import {ToolAdapters} from '../tool-adapters.mjs';
test('typed runtime and owned experiment produce real fixture receipts',{skip:!process.env.INDAGO_RUNTIME_FIXTURE||!process.env.INDAGO_TEST_EXE,timeout:120000},async t=>{
 const state=fs.mkdtempSync(path.join(os.tmpdir(),'indago-typed-runtime-'));t.after(()=>fs.rmSync(state,{recursive:true,force:true}));
 const config={exe:process.env.INDAGO_TEST_EXE,cwd:state,state,workspace:path.join(state,'native'),project:'typed_runtime',authority:'host',allowHelpers:false};
 const native=new Native(config);await native.call(['project','create','--name',config.project]);await native.import(process.env.INDAGO_RUNTIME_FIXTURE);config.active=native.active;config.toolCapabilities=(await native.capabilities()).data;
 const app=new ToolAdapters(native,config);
 const io=await app.execute('runtime_io_run',{input_hex:'41420a',timeout_ms:1000,max_output_bytes:4096});assert.equal(io.isError,false);assert.match(JSON.stringify(io),/observation/);
 const exp=await app.execute('experiment_run',{engine:'io',prediction:'Compare two different synthetic fixture inputs; no acceptance claim',cases:[{label:'first',input_hex:'410a'},{label:'control',input_hex:'420a'}]});assert.equal(exp.isError,false);assert.match(JSON.stringify(exp),/indago.experiment|evidence_ids/);
 const status=await app.execute('workflow_status',{});assert.equal(JSON.parse(status.content[0].text).preview.pending,null);
});
