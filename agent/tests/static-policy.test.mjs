import test from 'node:test';import assert from 'node:assert/strict';
import {staticToolAllowed,staticPolicy} from '../static-policy.mjs';
test('static unattended tool surface is deny by default including generic bypasses',()=>{
 for(const name of ['bash','powershell','wsl','write','edit','runtime_launch','native_command','analyze','helper_run','program_open','ghidra_rename','future_tool'])assert.throws(()=>staticPolicy({restrictedStatic:true},name));
 for(const name of ['decompile','xair_cfg','sym_solve_branch','question_checkpoint','tools_search','remember'])assert.equal(staticToolAllowed(name),true);
 assert.doesNotThrow(()=>staticPolicy({},'bash'));
});
