const assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{spawnSync}=require('node:child_process');
const [exe,fixture,format='PE',mode]=process.argv.slice(2);
const workspace=fs.mkdtempSync(path.join(os.tmpdir(),'indago-lief-cli-'));
const nativePath=value=>mode==='wsl'?path.resolve(value).replace(/^([A-Za-z]):/,(_,drive)=>'/mnt/'+drive.toLowerCase()).replaceAll('\\','/'):path.resolve(value);
function call(args,expected=[0,3]){
 const base=['--workspace',nativePath(workspace),...args];
 const r=mode==='wsl'?spawnSync('wsl.exe',['-d','Ubuntu','--exec',exe,...base],{encoding:'utf8',timeout:20000,maxBuffer:1048576}):spawnSync(exe,base,{encoding:'utf8',timeout:20000,maxBuffer:1048576});
 assert.ifError(r.error);assert.ok(expected.includes(r.status),r.stdout+r.stderr);return JSON.parse(r.stdout);
}
call(['project','create','--name','formats']);
const imported=call(['target','import','--project','formats','--file',nativePath(fixture)]);
function query(operation,extra=[]){
 const options=new Map([['--timeout-ms','5000'],['--max-output-bytes','65536'],['--max-items','128']]);
 for(let i=0;i<extra.length;i+=2)options.set(extra[i],extra[i+1]);
 return call(['query','--project','formats','--backend','lief','--operation',operation,...[...options].flat()]);
}
assert.equal(query('inventory').data.format,format);
const preset=call(['analyze','--project','formats','--backend','lief','--timeout-ms','5000','--max-items','128','--max-output-bytes','65536']);
assert.equal(preset.results.length,3);assert.ok(preset.results.every(row=>row.backend==='lief'&&row.status==='completed'));
const operation=format==='PE'?'resources':'notes',kind=format==='PE'?'resource':'format_note';
const result=query(operation);assert.equal(result.status,'completed');assert.ok(result.data[operation].length>0);
const indexed=call(['index','entities','--project','formats','--backend','lief','--kind',kind]);
assert.equal(indexed.records.length,result.data[operation].length);
assert.ok(indexed.records.every(row=>row.producer==='lief'&&row.evidence_id===result.evidence_ids[0]));
if(format==='PE')assert.ok(indexed.records.every(row=>row.location.address_space==='file'));
const raw=call(['evidence','show','--project','formats','--id',result.evidence_ids[0]]);
assert.deepEqual(raw.evidence[0].native_result[operation],result.data[operation]);
const first=query('sections',['--max-items','2','--max-output-bytes','4096']);
assert.equal(first.status,'partial');assert.equal(first.data.page.next_offset,2);
const next=query('sections',['--offset','2','--max-items','2']);assert.equal(next.data.sections[0].native_ordinal,2);
call(['query','--project','formats','--backend','lief','--operation','inventory','--offset','1'],[2]);
function request(verb,value){const file=path.join(workspace,'request.json');fs.writeFileSync(file,JSON.stringify(value));return call(['harness',verb,'--request',nativePath(file)]);}
const inv=request('create',{project:'formats',target_id:imported.id,objective:'Read format metadata without executing target',required_facts:['format metadata'],owner:{mode:'external',name:'offline fixture',model_declaration:'no model'},budget:{max_actions:3,wall_ms:40000,output_bytes:2097152},...(format==='PE'?{workbench_mutations:true,derived_artifacts:{max_artifacts:1,max_bytes:32}}:{})});
function owned(verb,value){const current=call(['harness','show','--project','formats','--id',inv.id]);return request(verb,{project:'formats',id:inv.id,owner_token:inv.owner_token,expected_revision:current.revision,...value});}
const proposal=owned('propose',{key:'metadata',proposal:{gap:'format metadata',expected_evidence:'LIEF format records',prediction:'Source fixture exposes format metadata',fallback:'Preserve parser limitations'},request:{backend:'lief',operation,arguments:{},budget:{wall_ms:5000,output_bytes:65536,max_items:8,memory_bytes:67108864}}});
const action=owned('run',{action_id:proposal.id});assert.equal(action.result.status,'completed');
assert.equal(owned('run',{action_id:proposal.id}).job_id,action.job_id);
if(format==='PE'){
 const resource=result.data.resources.find(r=>r.path.some(k=>k.id===101));assert.ok(resource);
 const derivedProposal=owned('propose',{key:'resource-bytes',proposal:{gap:'format metadata',expected_evidence:'Byte-exact resource artifact',prediction:'Compiled resource contains the independent fixture marker',fallback:'Do not infer execution semantics'},request:{backend:'workbench',operation:'transform.run',arguments:{offset:resource.file_offset,size:resource.size,spec:{method:'slice'},title:'Source fixture resource',assumptions:['LIEF range was compared with the hashed source snapshot']}}});
 const transformed=owned('run',{action_id:derivedProposal.id});assert.equal(transformed.status,'completed');
 const derived=transformed.result.derived_artifact;assert.equal(derived.admitted,true);assert.equal(derived.artifact_sha256,resource.content_sha256);
 const validate=owned('propose',{key:'resource-oracle',proposal:{gap:'format metadata',expected_evidence:'Finite exact-byte fixture comparison',prediction:'Resource bytes equal the source-defined marker',fallback:'Retain a counterexample'},request:{backend:'workbench',operation:'validate.compare',target_id:derived.target_id,arguments:{cases:[{actual_artifact:derived.artifact_sha256,expected_hex:Buffer.from('Indago Resource\0').toString('hex')}]}}});
 const verdict=owned('run',{action_id:validate.id});assert.equal(verdict.status,'completed');
 const validation=call(['knowledge','show','--project','formats','--id',verdict.result.knowledge_ids[0]]);
 assert.equal(validation.body.passed,true);
}
owned('release',{});
console.log(JSON.stringify({status:'passed',workspace,format,mode:mode||'native',records:indexed.records.length,target_executed:false}));
