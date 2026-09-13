// One local model repairs a helper using real, bounded harness receipts.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const [exe,model]=process.argv.slice(2);if(!model)throw Error('native Linux executable and exact local model ID required');
const root=fs.mkdtempSync(path.resolve('out/expansion-live-repair-'));let n=0;
const native=p=>p.replace(/^([A-Za-z]):/,(_,d)=>'/mnt/'+d.toLowerCase()).replaceAll('\\','/');
function call(args,r){const f=path.join(root,`request-${++n}.json`);if(r)fs.writeFileSync(f,JSON.stringify(r));const p=spawnSync('wsl.exe',['--exec',exe,'--workspace',native(path.join(root,'state')),...args,...(r?['--request',native(f)]:[])],{encoding:'utf8',timeout:30000,maxBuffer:1048576});assert.ifError(p.error);assert([0,3].includes(p.status),p.stdout+p.stderr);return JSON.parse(p.stdout);}
(async()=>{
call(['project','create','--name','repair']);const fixture=path.join(root,'fixture.bin');fs.writeFileSync(fixture,'abcdABCD');const target=call(['target','import','--project','repair','--file',native(fixture)]);
const inv=call(['harness','create'],{project:'repair',target_id:target.id,objective:'Repair and validate a contained byte transform, not a challenge solve',required_facts:['exact byte equality'],owner:{mode:'external',name:'single-local-model-repair'},workbench_mutations:true,analysis_helpers:true,budget:{max_actions:5,wall_ms:360000,output_bytes:524288}});
let source='import sys\ndata = sys.stdin.buffer.read()\nsys.stdout.buffer.write(data ^ 32)\n';
const receipts=[],generations=[];
for(let attempt=0;attempt<4;attempt++){
 let current=call(['harness','show','--project','repair','--id',inv.id]);
 const action=call(['harness','propose'],{project:'repair',id:inv.id,owner_token:inv.owner_token,expected_revision:current.revision,key:`attempt-${attempt}`,proposal:{gap:'byte transformation',prediction:'uppercase bytes',expected_evidence:'exact reference equality',fallback:'inspect exception and revise'},request:{backend:'workbench',operation:'helper.run',arguments:{language:'python3',source_code:source,input:{offset:0,max_bytes:4},validation:{kind:'artifact_bytes',expected:{offset:4,max_bytes:4}}}}});
 current=call(['harness','show','--project','repair','--id',inv.id]);
 const executed=call(['harness','run'],{project:'repair',id:inv.id,owner_token:inv.owner_token,expected_revision:current.revision,action_id:action.id});
 const receipt=call(['knowledge','show','--project','repair','--id',executed.result.knowledge_ids[0]]);receipts.push(receipt);
 if(receipt.body.validation_passed){assert(attempt>0);assert.equal(receipt.body.verified_solve,false);fs.writeFileSync(path.join(root,'summary.json'),JSON.stringify({passed:true,model,receipts,generations,target_executed:false},null,2));console.log(JSON.stringify({passed:true,root,attempts:receipts.length,generations:generations.length}));return;}
 const error=Buffer.from(receipt.body.runs?.[0]?.stderr_hex||'','hex').toString();
 const request={model,temperature:0,max_tokens:1536,messages:[{role:'system',content:'Repair a small isolated Python 3 helper. Return only a JSON object {"source_code":"..."}. No markdown. No packages, subprocesses or network. Read binary stdin and write only transformed bytes to binary stdout. Input is abcd; apply XOR 32 to each byte. This is a harmless source fixture, not a challenge.'},{role:'user',content:JSON.stringify({source_code:source,status:receipt.body.status,stderr:error})}]};
 const response=await fetch('http://127.0.0.1:1234/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(request),signal:AbortSignal.timeout(90000)});assert(response.ok);const result=await response.json();generations.push({request,result});
 let text=result.choices[0].message.content.replace(/<think>[\s\S]*?<\/think>/g,'').trim().replace(/^```(?:json)?\s*/,'').replace(/\s*```$/,'');source=JSON.parse(text).source_code;assert.equal(typeof source,'string');assert(source.length<=16384);
}
fs.writeFileSync(path.join(root,'summary.json'),JSON.stringify({passed:false,model,receipts,generations},null,2));throw Error('repair budget exhausted');
})().catch(e=>{console.error(e);process.exitCode=1;});
