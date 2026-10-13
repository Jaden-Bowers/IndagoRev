import test from 'node:test';
import assert from 'node:assert/strict';
import {modelContext} from '../model-context.mjs';
const server=async()=>({ok:true,json:async()=>({data:[{id:'local',state:'loaded',loaded_context_length:131072,max_context_length:262144}]})});
test('loaded context is authoritative and operator may only tighten it',async()=>{
 const c=await modelContext({model:'local',requireLoadedContext:true},server);
 assert.equal(c.contextTokens,131072);assert.equal(c.compaction.reserveTokens,32768);
 assert.equal((await modelContext({model:'local',contextTokens:262144},server)).contextTokens,131072);
 assert.equal((await modelContext({model:'local',contextTokens:32768},server)).contextTokens,32768);
 await assert.rejects(modelContext({model:'missing',requireLoadedContext:true},server));
 await assert.rejects(modelContext({model:'local',outputTokens:100000},server));
 await assert.rejects(modelContext({model:'local',requireLoadedContext:true,requireSingleLoadedModel:true},async()=>({ok:true,json:async()=>({data:[{id:'local',state:'loaded',loaded_context_length:131072},{id:'local:2',state:'loaded',loaded_context_length:131072}]})})),/exactly one/);
});
