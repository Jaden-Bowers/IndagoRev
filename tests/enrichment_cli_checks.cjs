const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const [exe,fixture,format='pe',mode]=process.argv.slice(2);
const workspace=fs.mkdtempSync(path.join(os.tmpdir(),'indago-enrichment-cli-'));
const nativePath=value=>mode==='wsl'?path.resolve(value).replace(/^([A-Za-z]):/,(_,drive)=>'/mnt/'+drive.toLowerCase()).replaceAll('\\','/'):path.resolve(value);
function call(args,expected=[0,3]){
  const base=['--workspace',nativePath(workspace),...args];
  const r=mode==='wsl'?spawnSync('wsl.exe',['-d','Ubuntu','--exec',exe,...base],{encoding:'utf8',timeout:40000,maxBuffer:4194304}):spawnSync(exe,base,{encoding:'utf8',timeout:40000,maxBuffer:4194304});
  assert.ifError(r.error);assert.ok(expected.includes(r.status),r.stdout+r.stderr);return JSON.parse(r.stdout);
}
call(['project','create','--name','enrichment']);
const imported=call(['target','import','--project','enrichment','--file',nativePath(fixture)]);
function query(backend,operation,extra=[]){return call(['query','--project','enrichment','--backend',backend,'--operation',operation,'--timeout-ms','30000','--max-output-bytes','2097152','--max-items','16',...extra]);}
const capability=query('capa','capabilities',['--format',format]);
assert.equal(capability.data.native_document_complete,true);
assert.equal(capability.data.native_document.meta.sample.sha256,imported.artifact_sha256);
assert.equal(capability.data.native_document.meta.flavor,'static');
assert.equal(capability.data.target_executed,false);
assert.ok(capability.data.capabilities.every(row=>row.behavior_proven===false));
const strings=query('floss','strings',['--mode','static']);
assert.equal(strings.data.native_document_complete,true);
assert.equal(strings.data.scope,'static');
assert.ok(strings.data.strings.length>0);
assert.ok(strings.data.strings.every(row=>row.location.address_space==='file'&&row.location_role==='file_bytes'));
const indexed=call(['index','entities','--project','enrichment','--backend','floss','--kind','string']);
assert.equal(indexed.records.length,strings.data.strings.length);
assert.ok(indexed.records.every(row=>row.location.address_space==='file'));
const raw=call(['evidence','show','--project','enrichment','--id',strings.evidence_ids[0]]);
assert.deepEqual(raw.evidence[0].native_result.native_document,strings.data.native_document);
const small=call(['query','--project','enrichment','--backend','floss','--operation','strings','--mode','static','--timeout-ms','5000','--max-output-bytes','4096']);
if(Buffer.byteLength(JSON.stringify(strings.data.native_document))>4096)assert.equal(small.status,'partial');
else assert.ok(['completed','partial'].includes(small.status));
assert.ok(Buffer.byteLength(JSON.stringify(small))<=4096);
function request(operation,value){const file=path.join(workspace,'request.json');fs.writeFileSync(file,JSON.stringify(value));return call(['harness',operation,'--request',nativePath(file)]);}
const inv=request('create',{project:'enrichment',target_id:imported.id,objective:'Inspect enrichment leads without executing target',required_facts:['string leads'],owner:{mode:'external',name:'offline enrichment fixture',model_declaration:'no model'},budget:{max_actions:2,wall_ms:30000,output_bytes:2097152}});
function owned(operation,value){const current=call(['harness','show','--project','enrichment','--id',inv.id]);return request(operation,{project:'enrichment',id:inv.id,owner_token:inv.owner_token,expected_revision:current.revision,...value});}
const proposed=owned('propose',{key:'strings',proposal:{gap:'string leads',expected_evidence:'Upstream FLOSS string records',prediction:'Benign source fixture has static strings',fallback:'Retain partial extraction and limits'},request:{backend:'floss',operation:'strings',arguments:{mode:'static'},budget:{wall_ms:10000,output_bytes:1048576,max_items:8,memory_bytes:67108864}}});
const action=owned('run',{action_id:proposed.id});
assert.ok(['completed','partial'].includes(action.result.status));
assert.equal(owned('run',{action_id:proposed.id}).job_id,action.job_id);
owned('release',{});
console.log(JSON.stringify({status:'passed',workspace,format,mode:mode||'native',capabilities:capability.data.finding_count,strings:strings.data.finding_count,target_executed:false}));
