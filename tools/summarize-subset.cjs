// Publish metrics only: no candidate answers, host paths, leases or raw evidence.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
function summarize(r){
 const status=r.state?.status??'analysis_failed';
 const turns=r.controller?.investigation_state?.turns??[];
 const token=x=>typeof x==='string'&&/^[a-zA-Z0-9_.-]{1,80}$/.test(x)?x:null;
 const bindingMismatches=[];
 for(const t of turns){
  if(t.decision?.kind!=='analyze')continue;
  const original=r.controller?.conversation?.find(c=>c.generation===t.generation)?.assistant;
  try{const d=JSON.parse(original.tool_calls[0].function.arguments);
   const p=typeof d.payload==='string'?JSON.parse(d.payload):d.payload;
   if(p.request&&!['target_id','artifact_sha256','artifact'].some(k=>k in p.request)&&
      t.decision.payload.request.target_id!==r.state.target_id)bindingMismatches.push(t.generation);
  }catch{} // Unavailable original transport cannot establish a mismatch.
 }
 return {challenge:r.challenge,family:r.family,artifact_sha256:r.artifact_sha256??null,
  attempt:r.attempt??1,budget:r.budget??null,
  status,controller_status:r.controller?.status??null,
  model:r.model,profile_sha256:r.state?.owner?.profile?.profile_sha256??r.profile_sha256,
  generations:r.result?.controller_usage?.generations??0,
  model_elapsed_ms:r.result?.controller_usage?.model_elapsed_ms??0,
  native_actions:r.state?.reserved?.actions??0,elapsed_ms:r.elapsed_ms,
  scope_components:r.scope_components??1,
  reported_answer:status==='answered',independently_graded:false,verified_solve:false,
  failure_category:r.failure_category??(status==='answered'?'ungraded':'controller_or_model_investigation_failure'),
  terminal_reason:r.controller?.status??'setup_or_execution_failure',
  repair_count:r.controller?.repairs??0,
  primary_binding_mismatch_generations:bindingMismatches,
  decisions:turns.map(t=>({generation:t.generation,kind:token(t.decision?.kind),
   backend:token(t.decision?.payload?.request?.backend),
   operation:token(t.decision?.payload?.request?.operation??t.decision?.payload?.operation),
   family:token(t.decision?.payload?.family),status:token(t.feedback?.status),
   invalid_request:typeof t.feedback?.error==='string'})),
  target_execution:false};
}
if(require.main===module){
 const [input,output]=process.argv.slice(2);if(!input||!output)throw Error('Usage: RUN_DIRECTORY PUBLIC_SUMMARY.json');
 const run=JSON.parse(fs.readFileSync(path.join(input,'summary.json'),'utf8'));
 const rows=run.rows.map(summarize);
 const receipts=run.rows.map(r=>JSON.parse(fs.readFileSync(path.join(input,r.challenge,'preparation-receipt.json'),'utf8')));
 const catalogues=[...new Set(receipts.map(r=>r.catalogue_sha256))];
 assert.equal(catalogues.length,1,'one catalogue identity per run');
 const result={schema:'indago.development-subset-summary.v1',catalogue_sha256:catalogues[0],attempted:rows.length,
  reported_answers:rows.filter(r=>r.reported_answer).length,independently_verified_solves:0,
  qualification:false,grading:'No independent answer oracle configured; no solve-rate claim.',rows};
 const text=JSON.stringify(result,null,2)+'\n';
 assert(!/[A-Z]:[\\/]Users[\\/]|\/home\/[^/]+\/|\/Users\/[^/]+\/|lease_|[A-Za-z0-9._%+-]+@flare-on\.(?:com|net)/i.test(text));
 fs.writeFileSync(output,text);console.log(JSON.stringify({attempted:rows.length,reported_answers:result.reported_answers}));
}
module.exports={summarize};
