import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {ToolAdapters} from '../tool-adapters.mjs';
import {hashFile} from '../native.mjs';
function setup(t){const state=fs.mkdtempSync(path.join(os.tmpdir(),'indago-adapters-'));t.after(()=>fs.rmSync(state,{recursive:true,force:true}));const calls=[];const config={state,toolCapabilities:{backends:[{name:'ghidra',available:true,operations:['decompile','functions','session','annotate']},{name:'sym',available:true,operations:['path_condition']}]}};const native={active:{id:'t1',artifact_sha256:'abc'},analyze:async p=>{calls.push(p);return {data:{status:'completed',data:{program_revision:1,pagination:{next_cursor:'next'}}}};}};return {app:new ToolAdapters(native,config),config,native,calls,state};}
test('typed static calls preserve paging, bind active target and translate native options',async t=>{
 const {app,calls}=setup(t);await app.execute('functions',{cursor:'cursor',limit:20});assert.equal(calls[0].limit,20);assert.equal(calls[0].arguments.cursor,'cursor');
 await app.execute('sym_path_condition',{source:'funcarg(0)@0x10',sink:'reach@0x20',max_states:64});assert.equal(calls[1].arguments['max-states'],64);
 await assert.rejects(app.execute('functions',{project:'other'}),/unknown field/);
 await assert.rejects(app.execute('ghidra_rename',{address:'0x10',expected_revision:1,name:'renamed'}),/operator/);
});
test('GUI selection resolution rejects stale and ambiguous identities',async t=>{
 const {app,config,native,state,calls}=setup(t);const file=path.join(state,'sample');fs.writeFileSync(file,'bytes');native.active.artifact_sha256=hashFile(file);
 config.selection=[{file,artifact_sha256:hashFile(file),function_address:'0x10',program_revision:1,locations:[{min_address:'0x12'}]}];
 await app.execute('decompile',{address:'current'});assert.equal(calls.at(-1).address,'0x10');
 config.selection[0].locations.push({min_address:'0x13'});await assert.rejects(app.execute('decompile',{address:'selection'}),/multiple/);
 config.selection[0].program_revision=2;await assert.rejects(app.execute('decompile',{address:'current'}),/stale/);
});
test('artifact groups use detected kind, not substring or extension guessing',t=>{
 const {app,config}=setup(t);config.toolRoute={kind:'python',route:'unsupported type'};assert.equal(app.activeGroups().size,0);
 config.toolRoute={kind:'managed_pe'};assert.ok(app.activeGroups().has('ilspy'));
 config.toolRoute={kind:'capture'};assert.deepEqual([...app.activeGroups()],['wireshark']);
});
