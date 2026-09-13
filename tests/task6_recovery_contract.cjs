// Trusted source-backed subtract-decoder fixture; no challenge execution.
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const [exe,fixture]=process.argv.slice(2),root=fs.mkdtempSync(path.resolve('out/task6-recovery-')),workspace=path.join(root,'state');let n=0;
function app(args,r){const f=path.join(root,`request-${++n}.json`);if(r)fs.writeFileSync(f,JSON.stringify(r));const p=spawnSync(exe,['--workspace',workspace,...args,...(r?['--request',f]:[])],{encoding:'utf8',timeout:50000,maxBuffer:4*1024**2});if(p.error)throw p.error;const out=JSON.parse(p.stdout);fs.writeFileSync(path.join(root,`response-${n}.json`),JSON.stringify(out,null,2));if(![0,3].includes(p.status))throw Error(JSON.stringify(out));return out;}
app(['project','create','--name','recovery']);const t=app(['target','import','--project','recovery','--file',path.resolve(fixture)]);
const inv=app(['harness','create'],{project:'recovery',target_id:t.id,objective:'Recover non-XOR executable code',required_facts:['observed code lineage'],owner:{mode:'external',name:'fixture'},workbench_mutations:true,budget:{max_actions:1,wall_ms:90000,output_bytes:262144},runtime_execution:{trusted_host_execution:true,targets:[{target_id:t.id,file:path.resolve(fixture)}],engines:['frida']}});
const action=app(['harness','propose'],{project:'recovery',id:inv.id,owner_token:inv.owner_token,expected_revision:inv.revision,key:'recover',proposal:{gap:'runtime code',prediction:'subtract decoder produces return42',expected_evidence:'code epoch and derived analysis image',fallback:'retain partial'},request:{backend:'workbench',operation:'experiment.run',arguments:{engine:'frida',recipe:'code',recover_code:true,prediction:'Non-XOR code reconstructed',cases:[{label:'unpack',argv:['--unpack']}]}}});
const result=app(['harness','run'],{project:'recovery',id:inv.id,owner_token:inv.owner_token,expected_revision:action.investigation_revision,action_id:action.id});
const record=app(['knowledge','show','--project','recovery','--id',result.result.knowledge_ids[0]]);
const recoveries=record.body.cases[0].code_recoveries||[];
const expected=Buffer.alloc(4096);Buffer.from('b82a000000c3','hex').copy(expected);
const expectedHash=require('node:crypto').createHash('sha256').update(expected).digest('hex');
const passed=recoveries.some(r=>r.data?.derivation?.raw_artifact_sha256===expectedHash&&r.data?.analyses?.length>0)&&!record.body.outcome_unknown;
fs.writeFileSync(path.join(root,'summary.json'),JSON.stringify({passed,root,body:record.body},null,2));console.log(JSON.stringify({passed,root,recoveries:recoveries.length,status:record.body.status,diagnostic:record.body.cases[0].diagnostic},null,2));process.exitCode=passed?0:1;
