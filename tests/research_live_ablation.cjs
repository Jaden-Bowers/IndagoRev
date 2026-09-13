// Bounded live-model experiment selection and helper repair, with one feature
// toggled. Equal results are valid measurements; this does not assert superiority.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const [exe,fixture,model,feature='native_diagnostics']=process.argv.slice(2);if(!model)throw Error('exact local model ID required');
assert(['native_diagnostics','input_suggestions','counterexample_feedback','validated_recipe'].includes(feature));
const root=fs.mkdtempSync(path.resolve('out/research-live-'));let n=0;
const native=p=>p.replace(/^([A-Za-z]):/,(_,d)=>'/mnt/'+d.toLowerCase()).replaceAll('\\','/');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
function call(args,r){const f=path.join(root,`r${++n}.json`);if(r)fs.writeFileSync(f,JSON.stringify(r));const p=spawnSync('wsl.exe',['--exec',exe,'--workspace',native(path.join(root,'state')),...args,...(r?['--request',native(f)]:[])],{encoding:'utf8',timeout:45000,maxBuffer:4194304});assert.ifError(p.error);assert([0,3].includes(p.status),p.stdout+p.stderr);const result=JSON.parse(p.stdout);fs.writeFileSync(path.join(root,`o${n}.json`),JSON.stringify(result,null,2));return result;}
const reference=r=>({id:r.id,revision:r.revision});
(async()=>{
call(['project','create','--name','live']);const t=call(['target','import','--project','live','--file',fixture]);const records=[],runs=[];
for(const feedback of [false,true]){
 const start=Date.now();let actions=0;
 const inv=call(['harness','create'],{project:'live',target_id:t.id,objective:'Repair a transform helper and select a discriminating original-target experiment',required_facts:['exact tested output agreement'],owner:{mode:'external',name:'local-single-model-evaluation'},workbench_mutations:true,analysis_helpers:true,budget:{max_actions:12,wall_ms:240000,output_bytes:1048576},runtime_execution:{trusted_host_execution:true,targets:[{target_id:t.id,file:fixture}],engines:['io']}});
 function run(operation,args){const current=call(['harness','show','--project','live','--id',inv.id]);const a=call(['harness','propose'],{project:'live',id:inv.id,owner_token:inv.owner_token,expected_revision:current.revision,key:`step-${++actions}`,proposal:{gap:'uncertain reconstruction',prediction:'discriminating fixture behavior',expected_evidence:'independent I/O',fallback:'retain failure'},request:{backend:'workbench',operation,arguments:args}});const x=call(['harness','run'],{project:'live',id:inv.id,owner_token:inv.owner_token,expected_revision:a.investigation_revision,action_id:a.id});assert(x.result?.knowledge_ids,JSON.stringify(x));return call(['knowledge','show','--project','live','--id',x.result.knowledge_ids[0]]);}
 const source='import sys\ndata=sys.stdin.buffer.read()\nsys.stdout.buffer.write(data ^ 32)\n';
 const broken=run('helper.run',{language:'python3',source_code:source,input:{generated_hex:'61'},validation:{kind:'none'}});
 let cue={status:broken.body.status,diagnostic:broken.body.untrusted_diagnostic_preview};
 if(feature!=='native_diagnostics'){
   const evidence=run('knowledge.put',{kind:'summary',title:'Source fixture hypothesis',state:'inferred',body:{claim:'XOR32 versus identity'}});
   const cueSource=feature==='validated_recipe'?'import sys\nsys.stdout.buffer.write(bytes(x^32 for x in sys.stdin.buffer.read()))\n':'import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n';
   const candidate=run('research.run',{body:{kind:'algorithm_candidate',domain:'Byte stdin to stdout',assumptions:['Byte-local fixture'],evidence:[reference(evidence)],language:'python3',source_code:cueSource,generator:{seed_hex:'61',count:8}}});
   cue=candidate.body.suggested_inputs;
   if(feature!=='input_suggestions'){
     const helper=run('helper.run',{language:'python3',source_code:cueSource,input:{generated_hex:'61'},validation:{kind:'none'}}),experiment=run('experiment.run',{engine:'io',prediction:'Discriminate identity and XOR32',cases:[{label:'cue',input_hex:'61'}]});
     const comparison=run('research.run',{body:{kind:'algorithm_comparison',candidate:reference(candidate),pairs:[{helper:reference(helper),experiment:reference(experiment),case:0}]}});
     cue=comparison.body.counterexamples;
     if(feature==='validated_recipe')cue=call(['evaluation','recipe'],{evaluation_root:native(path.join(root,'evaluation')),project:'live',scope:comparison.scope,comparison:reference(comparison),applicability:'Independent byte XOR32 candidates',limitations:'Agreement on one fixture input, not universal',technique:'Byte-local transform implementation',answer_free_review:true});
   }
 }
 const request={model,temperature:0,seed:0,max_tokens:1536,messages:[{role:'system',content:'Return only JSON {"source_code":"...","input_hex":"...","prediction":"..."}. Repair a contained Python3 helper for a source-built byte transform fixture. Static evidence suggests each input byte is XORed with 32; identity is a competing hypothesis. Select a short discriminating binary stdin input and predict why it distinguishes these hypotheses. Use only sys, binary stdin/stdout; no packages/network/subprocess. Do not output a flag or claim a solve.'},{role:'user',content:JSON.stringify({source_code:source,...(feedback?{[feature]:cue}:{})})}]};
 const response=await fetch('http://127.0.0.1:1234/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request),signal:AbortSignal.timeout(90000)});assert(response.ok);const generation=await response.json();fs.writeFileSync(path.join(root,`generation-${feedback}.json`),JSON.stringify({request,generation},null,2));
 let outcome='failed',failure='model_limitation',diagnostic='Invalid model response',comparison;
 try {
  const text=generation.choices[0].message.content.replace(/<think>[\s\S]*?<\/think>/g,'').trim().replace(/^```(?:json)?\s*/,'').replace(/\s*```$/,'');const choice=JSON.parse(text);
  assert.equal(typeof choice.source_code,'string');assert(choice.source_code.length<=16384);assert(/^(?:[0-9a-f]{2}){1,32}$/.test(choice.input_hex),'nonempty discriminating input required');
  const evidence=run('knowledge.put',{kind:'summary',title:'Source-backed transform hypothesis',state:'inferred',body:{claim:'Independent development fixture suggests XOR32; identity remains a test alternative'}});
  const candidate=run('research.run',{body:{kind:'algorithm_candidate',domain:'Byte stdin to byte stdout',assumptions:['No environment state'],evidence:[reference(evidence)],language:'python3',source_code:choice.source_code,generator:{seed_hex:choice.input_hex,count:4}}});
  const helper=run('helper.run',{language:'python3',source_code:choice.source_code,input:{generated_hex:choice.input_hex},validation:{kind:'none'}});
  const experiment=run('experiment.run',{engine:'io',prediction:choice.prediction,cases:[{label:'model-selected',input_hex:choice.input_hex}]});
  comparison=run('research.run',{body:{kind:'algorithm_comparison',candidate:reference(candidate),pairs:[{helper:reference(helper),experiment:reference(experiment),case:0}]}});
  outcome=comparison.body.status==='agreement_on_tested_inputs'?'passed':'failed';failure=outcome==='passed'?'none':'model_limitation';diagnostic=comparison.body.status;
 }catch(e){diagnostic=String(e).slice(0,2048);}
 const repro=path.join(root,`repro-${feedback}.json`);fs.writeFileSync(repro,JSON.stringify({source_code:source,feedback,diagnostic}));const sourceFile=path.resolve('tests/fixtures/algorithm_fixture.c');
 const record=call(['evaluation','record'],{evaluation_root:native(path.join(root,'evaluation')),challenge:'development_xor_repair',split:'development',artifact_sha256:t.artifact_sha256,model,settings:{temperature:0,max_tokens:1536},seed:0,budget:{actions:12,generations:1},features:{[feature]:feedback},outcome,failure_category:failure,attempt:feedback?2:1,reproduction:{source_path:native(sourceFile),source_sha256:sha(fs.readFileSync(sourceFile)),request_path:native(repro),request_sha256:sha(fs.readFileSync(repro)),diagnostic},metrics:{wall_ms:Date.now()-start,model_generations:1,native_actions:actions,tokens:generation.usage?.total_tokens||0}});records.push(record);runs.push({feedback,outcome,comparison:comparison?.id});
}
const ablation=call(['evaluation','compare'],{evaluation_root:native(path.join(root,'evaluation')),baseline:records[0].id,variant:records[1].id,feature});
fs.writeFileSync(path.join(root,'summary.json'),JSON.stringify({completed:true,root,model,runs,records,ablation,universal_equivalence:false},null,2));console.log(JSON.stringify({completed:true,root,runs}));
})().catch(e=>{console.error(e);process.exitCode=1;});
