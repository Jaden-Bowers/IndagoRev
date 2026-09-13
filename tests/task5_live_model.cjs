// Explicitly opt-in LM Studio smoke test against the source-backed input fixture.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const [exe,fixture,model]=process.argv.slice(2);if(!model)throw Error('usage: indago input_fixture exact-model-id');
const root=fs.mkdtempSync(path.resolve('out/task5-live-')),workspace=path.join(root,'state');let n=0;
function app(args,r){const f=path.join(root,`request-${++n}.json`);if(r)fs.writeFileSync(f,JSON.stringify(r));
 const p=spawnSync(exe,['--workspace',workspace,...args,...(r?['--request',f]:[])],{encoding:'utf8',timeout:180000,maxBuffer:8*1024**2});
 if(p.error)throw p.error;let out;try{out=JSON.parse(p.stdout)}catch{throw Error(p.stdout+p.stderr)}
 fs.writeFileSync(path.join(root,`response-${n}.json`),JSON.stringify(out,null,2));if(![0,3].includes(p.status))throw Error(JSON.stringify(out));return out;}
app(['project','create','--name','live']);const target=app(['target','import','--project','live','--file',path.resolve(fixture)]);
const artifact=crypto.createHash('sha256').update(fs.readFileSync(fixture)).digest('hex');const oracle=path.join(root,'oracle.json');
fs.writeFileSync(oracle,JSON.stringify({schema:'indago.io-oracle.v1',artifact_sha256:artifact,fact:'The fixture accepts yes',stdout_hex:Buffer.from('accepted:explicit:bound').toString('hex'),exit_code:0,negative_input_hex:'6e6f0a'}));
const id=target.id||target.target?.id;if(!id)throw Error(JSON.stringify(target));
const inv=app(['harness','create'],{project:'live',target_id:id,workbench_mutations:true,
 objective:'Run one bounded IO experiment on this trusted input-delivery fixture. First plan the task. Use workbench experiment.run, engine io, prediction yes changes output, cases positive and negative. Both cases need argv ["--fixture"], files {"payload":"626f756e64"}, environment {"EXPERIMENT_VALUE":"explicit"}. Positive input_hex is 7965730a and negative input_hex is 6e6f0a. Retrieve experiment capabilities if necessary. After receiving the comparison, finish with a partial report of observed output differences; do not claim a challenge solve or call static analysis. These inputs are operator test instructions, not strings extracted from a target.',
 required_facts:['Report the bounded fixture contrast without claiming an independently graded solve'],
 owner:{mode:'builtin',name:'task5-live-qwen',profile:{provider:'local',model,endpoint:'http://127.0.0.1:1234/v1/chat/completions',context_tokens:65536,output_tokens:2048,generation_ms:60000}},
 budget:{max_actions:6,wall_ms:240000,output_bytes:1048576},
 runtime_execution:{trusted_host_execution:true,targets:[{target_id:id,file:path.resolve(fixture),acceptance_oracle:oracle}],engines:['io']}});
const result=app(['harness','explore'],{project:'live',id:inv.id,owner_token:inv.owner_token,expected_revision:inv.revision,allow_inference:true,recipe:'general',max_generations:6});
fs.writeFileSync(path.join(root,'summary.json'),JSON.stringify(result,null,2));console.log(JSON.stringify({root,status:result.status,usage:result.controller_usage},null,2));
