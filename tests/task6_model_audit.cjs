// Audit original-target receipts, not the model's prose or final status.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const root=path.resolve(process.argv[2]),report=JSON.parse(fs.readFileSync(path.join(root,'summary.json')));
const dir=path.join(root,'state/runtime-experiments');
const journals=fs.readdirSync(dir).filter(n=>n.endsWith('.json')).map(n=>JSON.parse(fs.readFileSync(path.join(dir,n))));
const cases=journals.flatMap(j=>j.cases||[]);
const observed=cases.find(c=>c.input_solutions?.some(s=>s.status==='completed'));
assert(observed,'missing native input solution');
const solution=observed.input_solutions.find(s=>s.status==='completed');
assert.equal(solution.data.caller_binding.status,'completed');
for(const b of solution.data.results[0].branches)assert.equal(b.caller_branch.entailed_by_comparison,true);
const receipts=[0,1].map(branch=>{
 const c=cases.find(c=>c.input?.solver_candidate?.branch===branch);
 assert(c,'missing candidate replay');const ref=c.input.solver_candidate;
 assert.equal(ref.session,observed.session);assert.equal(ref.observation,solution.id);
 assert.match(ref.receipt_sha256,/^[a-f0-9]{64}$/);
 const r=c.state.observation.data;assert.equal(r.complete,true);assert.equal(r.accepted,branch===0);
 assert.equal(r.output_hex,branch?'4641494c':'50415353');
 assert.equal(r.artifact_sha256,report.artifact_sha256);
 return {session:c.session,branch,input_hex:c.input.input_hex,accepted:r.accepted,output_hex:r.output_hex};
});
assert.equal(report.report.verified_solve,false);
assert(report.report.claims.length>=2,'missing cited report');
const proof={passed:true,artifact_sha256:report.artifact_sha256,model:report.owner.profile.model,
 generations:report.controller_usage.generations,native_actions:report.reserved.actions,
 model_elapsed_ms:report.controller_usage.model_elapsed_ms,receipts,verified_solve:false};
fs.writeFileSync(path.join(root,'proof.json'),JSON.stringify(proof,null,2));console.log(JSON.stringify(proof,null,2));
