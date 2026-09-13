// Explicit opt-in development evaluation. No target execution or answer hints.
// Source artifacts and full reports stay in ignored out/. Never commit raw reports.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const [executable,corpus,seven,subsetPath,model]=process.argv.slice(2);
if(!model)throw Error('Usage: EXE CORPUS_ROOT SEVEN_ZIP SUBSET.json EXACT_LOCAL_MODEL');
const root=path.resolve(__dirname,'..'),exe=path.resolve(executable);
const subset=JSON.parse(fs.readFileSync(subsetPath,'utf8'));
if(subset.challenges.length>6||subset.challenges.some(c=>c.id.includes('2025')))throw Error('Development subset bounds');
const catalogue=JSON.parse(fs.readFileSync(path.join(root,'config/flare-on-2014-2024.catalogue.json'),'utf8'));
if(catalogue.catalogue_sha256!==subset.catalogue_sha256)throw Error('Catalogue pin mismatch');
const budget=subset.budget;
if(!Number.isInteger(budget.max_generations)||budget.max_generations<2||budget.max_generations>16||budget.wall_ms>540000||budget.generation_ms>30000||budget.max_actions>32)throw Error('Run budget exceeds bounded development profile');
const report=fs.mkdtempSync(path.join(root,'out','subset-evaluation-'));
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const profile={provider:'local',model,endpoint:'http://127.0.0.1:1234/v1/chat/completions',context_tokens:65536,output_tokens:2048,generation_ms:budget.generation_ms};
const rows=[];let serial=0,caseDeadline=Infinity;
function cli(workspace,args,request,timeout=70000){
 timeout=Math.min(timeout,caseDeadline-Date.now());if(timeout<100)throw Error('Per-challenge deadline exhausted');
 const f=path.join(report,`request-${++serial}.json`);if(request)fs.writeFileSync(f,JSON.stringify(request));
 try{const r=spawnSync(exe,['--workspace',workspace,...args,...(request?['--request',f]:[])],{encoding:'utf8',windowsHide:true,timeout,maxBuffer:16*1024**2});
 if(r.error)throw r.error;const v=JSON.parse(r.stdout);if(![0,3].includes(r.status))throw Error(JSON.stringify(v));return v;
 }finally{if(request)fs.unlinkSync(f);}
}
console.log(JSON.stringify({report,model,challenges:subset.challenges.map(c=>c.id)}));
for(const c of subset.challenges){
 const start=Date.now(),workspace=path.join(report,c.id+'-state'),destination=path.join(report,c.id);
 caseDeadline=start+570000;
 const row={challenge:c.id,family:c.family,model,budget,profile_sha256:sha(JSON.stringify(profile)),attempt:subset.attempt??1,target_execution:false,independently_graded:false,verified_solve:false};
 let inv;
 try{
  const prepared=cli(workspace,['benchmark','prepare'],{catalogue:path.join(root,'config/flare-on-2014-2024.catalogue.json'),corpus_root:path.resolve(corpus),archive_tool:path.resolve(seven),challenge:c.id,destination,max_bytes:33554432,wall_ms:60000});
  fs.writeFileSync(path.join(destination,'preparation-receipt.json'),JSON.stringify(prepared,null,2));
  if(prepared.status!=='completed')throw Error('Incomplete preparation');
  const matches=prepared.artifacts.filter(a=>a.member===c.entry);
  if(matches.length!==1)throw Error('Selected member missing or ambiguous');
  const target=path.resolve(destination,matches[0].path);
  if(!target.startsWith(destination+path.sep)||!fs.statSync(target).isFile())throw Error('Selected entry missing');
  row.artifact_sha256=sha(fs.readFileSync(target));
  if(row.artifact_sha256!==matches[0].sha256)throw Error('Prepared entry hash mismatch');
  cli(workspace,['project','create','--name','evaluation']);
  const imported=cli(workspace,['target','import','--project','evaluation','--file',target]);
  const targetIds=[imported.id];
  for(const artifact of prepared.artifacts){
   if(artifact.path===matches[0].path)continue;
   const file=path.resolve(destination,artifact.path);
   if(!file.startsWith(destination+path.sep)||sha(fs.readFileSync(file))!==artifact.sha256)throw Error('Companion integrity failure');
   const companion=cli(workspace,['target','import','--project','evaluation','--file',file]);
   if(!targetIds.includes(companion.id))targetIds.push(companion.id);
  }
  if(targetIds.length>28)throw Error('Subset component allowance exceeded');
  row.scope_components=targetIds.length;
  inv=cli(workspace,['harness','create'],{project:'evaluation',target_id:imported.id,workbench_mutations:true,
   scope:{target_ids:targetIds},derived_artifacts:{max_artifacts:4,max_bytes:4194304},
   objective:'Determine the challenge answer from the supplied artifact. Independently discover its input, transformations and acceptance/output conditions. Derive the answer from native evidence rather than recalled challenge knowledge. Do not execute the target. Report the exact candidate answer if established, with evidence and remaining uncertainties; do not claim independent grading.',
   required_facts:['challenge answer','input and acceptance or output algorithm'],owner:{mode:'builtin',name:'local development evaluation',profile},
   budget:{max_actions:budget.max_actions,wall_ms:budget.wall_ms,output_bytes:4194304}});
  row.investigation=inv.id;
  row.result=cli(workspace,['harness','explore'],{project:'evaluation',id:inv.id,owner_token:inv.owner_token,expected_revision:inv.revision,allow_inference:true,max_generations:budget.max_generations,recipe:'general'},570000);
  row.state=cli(workspace,['harness','show','--project','evaluation','--id',inv.id]);
  row.audit=cli(workspace,['harness','audit'],{project:'evaluation',id:inv.id});
  row.controller=cli(workspace,['harness','controller'],{project:'evaluation',id:inv.id});
  // A terminal gap/budget message also occupies report.answer. It is not a candidate.
  row.outcome=row.state.status==='answered'?'answer_requires_independent_grade':'no_answer';
  row.profile_sha256=row.state.owner.profile.profile_sha256;
  row.generations=row.result.controller_usage?.generations??row.controller.generations;
  row.failure_category=row.outcome==='no_answer'?'controller_or_model_investigation_failure':'ungraded';
 }catch(e){row.error=e.message;row.outcome='analysis_failed';
  caseDeadline=Date.now()+10000; // Bounded cleanup only; do not resume analysis.
  if(inv)try{row.cancellation=cli(workspace,['harness','cancel'],{project:'evaluation',id:inv.id,owner_token:inv.owner_token},10000);}catch(cleanup){row.cleanup_error=cleanup.message;}
 }
 row.elapsed_ms=Date.now()-start;rows.push(row);
 fs.writeFileSync(path.join(report,c.id+'-result.json'),JSON.stringify(row,null,2));
 fs.writeFileSync(path.join(report,'summary.json'),JSON.stringify({schema:'indago.development-subset-run.v1',rows},null,2));
 console.log(JSON.stringify({challenge:c.id,outcome:row.outcome,elapsed_ms:row.elapsed_ms,error:row.error}));
}
