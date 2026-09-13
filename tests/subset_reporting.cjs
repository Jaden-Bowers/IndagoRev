const assert=require('node:assert/strict'),{summarize}=require('../tools/summarize-subset.cjs');
const gap={challenge:'fixture',model:'test',state:{status:'budget_exhausted',report:{answer:'Budget exhausted.'}}};
assert.equal(summarize(gap).reported_answer,false);
assert.equal(summarize(gap).attempt,1);
assert.equal(summarize({...gap,state:{status:'answered',report:{answer:'candidate'}}}).reported_answer,true);
assert.equal(summarize({...gap,state:{status:'answered'}}).verified_solve,false);
assert(!JSON.stringify(summarize({...gap,error:'C:/Users/private/secret',owner_token:'lease_secret'})).includes('secret'));
const binding={...gap,state:{status:'partial',target_id:'primary'},controller:{
 investigation_state:{turns:[{generation:1,decision:{kind:'analyze',payload:{request:{target_id:'companion'}}}}]},
 conversation:[{generation:1,assistant:{tool_calls:[{function:{arguments:JSON.stringify({kind:'analyze',payload:{request:{backend:'xair'}}})}}]}}]}};
assert.deepEqual(summarize(binding).primary_binding_mismatch_generations,[1]);
binding.controller.conversation[0].assistant.tool_calls[0].function.arguments=JSON.stringify({kind:'analyze',payload:{request:{target_id:'companion'}}});
assert.deepEqual(summarize(binding).primary_binding_mismatch_generations,[]);
console.log('Subset reporting: gap/candidate/proof/privacy checks passed.');
