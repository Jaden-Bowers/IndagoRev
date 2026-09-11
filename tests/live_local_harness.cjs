// Opt-in live loopback inference. Never executed by the ordinary test suite.
// No sample execution: only the harness's bounded static-action envelope.
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const [exe,fixture,model,port='1234',generations='4']=process.argv.slice(2);
const profileFile=process.argv[7];
const mode=process.argv[8]||'inventory';
const profile=profileFile?JSON.parse(fs.readFileSync(profileFile,'utf8')):{provider:'local',endpoint:`http://127.0.0.1:${port}/v1/chat/completions`,model,context_tokens:8192,output_tokens:1024,generation_ms:60000};
if(profile.provider!=='local'||profile.model!==model||profile.endpoint!==`http://127.0.0.1:${port}/v1/chat/completions`)throw Error('Profile must match the explicitly selected local endpoint/model');
if(!exe||!fixture||!model||!/^[0-9]+$/.test(port)||+port<1||+port>65535||!Number.isInteger(+generations)||+generations<1||+generations>12||!['inventory','behavior','assisted','acceptance','solve'].includes(mode))throw Error('exe fixture exact-model [port] [1..12 generations] [profile] [inventory|behavior|assisted|acceptance|solve] required');
if(+generations*profile.generation_ms+100000>580000)throw Error('Live test outer deadline must remain below ten minutes');
const root=path.resolve(__dirname,'..');
const space=fs.statfsSync(root);if(space.bavail*space.bsize<20*1024**3+512*1024**2)throw Error('Live test requires 20 GiB free plus 512 MiB reservation');
const report=fs.mkdtempSync(path.join(root,'out','live-local-harness-')),workspace=path.join(report,'workspace');
const started=Date.now();let serial=0;
function run(args,timeout=20000){
  const r=spawnSync(exe,['--workspace',workspace,...args],{encoding:'utf8',timeout,maxBuffer:2097152});
  fs.writeFileSync(path.join(report,`${++serial}.json`),JSON.stringify({args:args.map((a)=>a===workspace?'WORKSPACE':a),exit_code:r.status,stdout:r.stdout?.replace(/"owner_token":\s*"[^"]*"/g,'"owner_token":"[redacted]"'),stderr:r.stderr,error:r.error?.message},null,2));
  if(r.error)throw r.error;if(![0,1,2,3,130].includes(r.status))throw Error(`Unexpected exit ${r.status}`);
  let value;try{value=JSON.parse(r.stdout);}catch{throw Error(`Invalid CLI JSON: ${r.stderr}`);}
  return value;
}
function action(op,request,timeout){const file=path.join(report,'request.json');fs.writeFileSync(file,JSON.stringify(request));return run(['harness',op,'--request',file],timeout);}
let summary={report,model,scope:'live local model; static-only target analysis; not solve qualification'};
function inventoryLabelCheck(events,shown){
  const values={};
  for(const event of events.records||[])for(const message of event.detail?.input_messages||[]){
    if(message.role!=='tool'&&message.role!=='user')continue;
    let page;try{page=JSON.parse(message.content);}catch{continue;}
    if(message.role==='user')page=page.previous_tool_result||{};
    if(page.schema!=='indago.evidence-page.v1'||!page.source_verified)continue;
    for(const item of page.items||[])if(item.pointer==='/program/format'||item.pointer==='/program/architecture')values[item.pointer]=item.value;
  }
  const claim=shown.report?.claims?.find(c=>c.fact==='format and architecture')?.text||'';
  const format=values['/program/format'],architecture=values['/program/architecture'];
  if(!format||!architecture||!claim)return {status:'not_established',native_values:values,semantic_entailment_checked:false};
  const labels={PE:/\bPE\b|portable executable/i,ELF:/\bELF\b/i,x86:/\bx86\b|\bi386\b/i,x64:/\bx64\b|\bx86[-_]64\b|\bamd64\b/i};
  const match=labels[format]?.test(claim)&&labels[architecture]?.test(claim);
  const incompatible=/Mach-O|\barm64\b|\baarch64\b/i.test(claim)||(format==='PE'&&/\bELF\b/.test(claim))||(architecture==='x86'&&/\bx64\b|\bx86[-_]64\b|\bamd64\b/i.test(claim));
  return {status:match&&!incompatible?'labels_match':'label_check_failed',native_values:values,claim,semantic_entailment_checked:false};
}
try {
  run(['project','create','--name','live-local']);
  const target=run(['target','import','--project','live-local','--file',path.resolve(fixture)]);
  if(!target.id)throw Error('Target import failed');
  const creation={project:'live-local',target_id:target.id,
    objective:mode==='behavior'?'Analyze the exported runtime_probe function of this source-backed fixture using both Ghidra and XAIR/AIRECE. First analyze ghidra/functions with arguments {"search":"runtime_probe"}; retrieve its functions page for the real entry address. Then analyze ghidra/decompile and xair/cfg at that address. Retrieve native decompilation/decompiled_c text and explain the input-dependent result, preserving separate backend views. Use xair/inventory for format metadata, not repeated unfiltered discovery. Never execute the target. Report unresolved behavior honestly.':'Statically establish this executable format and architecture, then explain one concrete aspect of its input or output behavior using native evidence. First obtain native inventory. Do not guess or execute the target. Finish with evidence IDs and explicit unresolved gaps; do not claim a verified solve.',
    required_facts:['format and architecture','one evidence-backed behavior or explicit gap'],
    owner:{mode:'builtin',name:'authorized LM Studio local model',profile},
    budget:{max_actions:mode==='behavior'?10:6,wall_ms:mode==='behavior'?180000:90000,output_bytes:1048576}};
  if(mode==='behavior')creation.objective+=' Reserve 60000 wall_ms for the first Ghidra functions action because cold import can take 40 seconds; use output_bytes=65536, memory_bytes=2147483648, max_items=16. Subsequent Ghidra actions need only 20000 wall_ms; XAIR actions use 10000. Analyze means kind=analyze, not an index lookup. After a returned Ghidra functions evidence ID, read /functions/0 for entry, then query decompile at that entry. Do not finish after Ghidra alone while actions and generations remain: next analyze xair/cfg at the returned entry, then xair/inventory and read /program for exact metadata. Preserve disagreements and finish with citations from both backends; do not assert equivalent IRs.';
  if(mode==='assisted'||mode==='acceptance'||mode==='solve') {
    creation.objective='Statically investigate the native entry function and follow a relevant application-logic callee. Inventory is collected automatically. Use kind=function with the inventory evidence ID and /program/entry pointer to obtain four native views; inspect returned pseudocode. Then select a relevant unvisited function_frontier destination for another function investigation while budget permits. Save exact native observations using record, then finish {saved:true}. Never execute the target or claim a verified solve.';
    creation.budget={max_actions:12,wall_ms:180000,output_bytes:2097152};
    if(mode==='acceptance'||mode==='solve') {
      creation.objective='Use kind=acceptance with the automatically returned inventory evidence ID and /program/entry. This gathers native Ghidra/XAIR views and symbolic branch/taint findings. Follow the relevant application callee from function_frontier using acceptance again. Preserve all native limits and unknowns; never execute the target or claim a solved challenge.';
      creation.budget={max_actions:14,wall_ms:300000,output_bytes:2097152};
      if(mode==='solve') {
        creation.objective='Recover the question-bound static decoder result. Use kind=acceptance on the automatically returned native entry pointer, then follow the relevant application callee with kind=acceptance. When automatic_proof returns, submit reasoning operation solution using its exact proof id, answer, and reasoning revision. Finish with {solved:true} only after the required verified_transformation proof succeeds. Do not describe this as observed output, accepted input, or independent grading.';
        creation.required_facts=['final challenge answer'];
        creation.proof_requirements=['verified_transformation'];
      }
    }
  }
  const inv=action('create',creation);
  if(!inv.id||!inv.owner_token)throw Error(`Investigation creation failed: ${JSON.stringify(inv)}`);
  // Never copy the returned owner lease into provider prompts or the summary.
  const explored=action('explore',{project:'live-local',id:inv.id,owner_token:inv.owner_token,expected_revision:inv.revision,allow_inference:true,max_generations:+generations,recipe:['assisted','acceptance','solve'].includes(mode)?'assisted_static':mode==='behavior'?'static_behavior':'input_validation'},+generations*profile.generation_ms+100000);
  fs.writeFileSync(path.join(report,'request.json'),JSON.stringify({project:'live-local',id:inv.id}));
  const controller=run(['harness','controller','--project','live-local','--id',inv.id]);
  const actions=run(['harness','actions','--project','live-local','--id',inv.id,'--limit','16']);
  const shown=run(['harness','show','--project','live-local','--id',inv.id]);
  const events=run(['harness','events','--project','live-local','--id',inv.id,'--limit','64']);
  const audit=run(['harness','audit','--project','live-local','--id',inv.id,'--limit','16']);
  summary={...summary,investigation:inv.id,elapsed_ms:Date.now()-started,result:explored,controller,actions,events,audit,investigation_state:shown,
    assessment:{native_action_count:actions.records?.length||0,cited_claim_count:shown.report?.claims?.length||0,inventory_label_check:inventoryLabelCheck(events,shown),requirements_verified:false,verified_solve:shown.report?.verified_solve===true}};
  if(mode==='assisted'||mode==='acceptance'||mode==='solve') {
    const claims=shown.report?.claims||[];
    summary.assessment.saved_observation_checks=mode==='solve'?claims.length>=1:claims.length>=2&&claims.every(c=>c.check_result?.status==='passed');
    summary.assessment.four_native_views=['ghidra/decompile','xair/cfg','ghidra/calls','ghidra/xrefs'].every(pair=>(actions.records||[]).some(a=>`${a.request?.backend}/${a.request?.operation}`===pair&&['completed','partial'].includes(a.result?.status)));
    summary.assessment.followed_callee=(controller.visited_functions||[]).length>=2;
    if((mode!=='solve'&&!summary.assessment.saved_observation_checks)||!summary.assessment.four_native_views||!summary.assessment.followed_callee)process.exitCode=1;
    if(mode==='acceptance'||mode==='solve') {
      summary.assessment.symbolic_views=['solve_branch','taint'].every(op=>(actions.records||[]).some(a=>a.request?.backend==='sym'&&a.request?.operation===op&&['completed','partial'].includes(a.result?.status)));
      if(!summary.assessment.symbolic_views)process.exitCode=1;
    }
    if(mode==='solve') {
      summary.assessment.requirements_verified=shown.report?.requirements_verified===true&&shown.reasoning?.requirements_verified===true&&shown.status==='answered'&&shown.report?.proof_kinds?.includes('verified_transformation')&&shown.report?.verified_solve===false&&shown.reasoning?.verified_solve===false&&shown.report?.independently_graded===false&&shown.report?.behavior_verified===false;
      summary.assessment.answer=shown.report?.answer;
      summary.assessment.decoder_stages=shown.reasoning?.recoveries?.at(-1)?.stages?.length||0;
      if(!summary.assessment.requirements_verified||!summary.assessment.answer||summary.assessment.decoder_stages<1)process.exitCode=1;
    }
  } else if(!summary.assessment.native_action_count||!summary.assessment.cited_claim_count||summary.assessment.inventory_label_check.status!=='labels_match')process.exitCode=1;
  if(mode==='behavior') {
    summary.assessment.cross_backend_actions=(actions.records||[]).map(a=>({backend:a.request?.backend,operation:a.request?.operation,status:a.status}));
    if(!summary.assessment.cross_backend_actions.some(a=>a.backend==='ghidra'&&a.operation==='decompile')||
       !summary.assessment.cross_backend_actions.some(a=>(a.backend==='xair'&&['cfg','semantic'].includes(a.operation))||(a.backend==='airece'&&['flow','slice','function'].includes(a.operation))))process.exitCode=1;
  }
}catch(error){summary={...summary,status:'test_failed',error:error.message,elapsed_ms:Date.now()-started};process.exitCode=1;}
fs.writeFileSync(path.join(report,'summary.json'),JSON.stringify(summary,null,2));
console.log(JSON.stringify({report,status:summary.status||summary.result?.status||'inspect_report',elapsed_ms:summary.elapsed_ms,investigation:summary.investigation}));
