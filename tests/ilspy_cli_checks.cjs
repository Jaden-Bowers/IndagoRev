const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {spawnSync} = require('node:child_process');
const [executable, fixture, mode] = process.argv.slice(2);
if (!executable || !fixture) throw Error('native executable and source-built fixture required');
const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'indago-ilspy-cli-'));
const nativePath = value => mode === 'wsl' ? path.resolve(value).replace(/^([A-Za-z]):/, (_, drive) => '/mnt/' + drive.toLowerCase()).replaceAll('\\','/') : path.resolve(value);
function call(args, expected = [0,3]) {
  const base = ['--workspace', nativePath(workspace), ...args];
  const result = mode === 'wsl' ? spawnSync('wsl.exe', ['-d','Ubuntu','--exec',executable,...base], {encoding:'utf8',timeout:20000,maxBuffer:2097152}) : spawnSync(executable,base,{encoding:'utf8',timeout:20000,maxBuffer:2097152});
  assert.ifError(result.error);
  assert.ok(expected.includes(result.status), result.stdout + result.stderr);
  return JSON.parse(result.stdout);
}
function request(family, operation, value) {
  const file=path.join(workspace,'request.json');
  fs.writeFileSync(file,JSON.stringify(value));
  return call([family,operation,'--request',nativePath(file)]);
}
call(['project','create','--name','managed']);
const target=call(['target','import','--project','managed','--file',nativePath(fixture)]);
function query(operation, extra=[]) { return call(['query','--project','managed','--target-id',target.id,'--backend','ilspy','--operation',operation,'--timeout-ms','5000','--max-output-bytes','65536',...extra]); }
assert.equal(query('inventory').status,'completed');
const listing=query('methods');
assert.equal(listing.status,'completed');
const method=listing.data.methods.find(row=>row.name==='Select');
assert.ok(method);
const result=query('decompile',['--address',method.token]);
assert.match(result.data.pseudocode,/Select/);
const assembly=query('assembly',['--address',method.token]);
assert.ok(assembly.data.tokens.some(token=>token.location.address_space==='managed_il:'+method.token));
for(const token of assembly.data.tokens) assert.equal(assembly.data.assembly.slice(token.start_utf16,token.end_utf16),token.text);
const evidence=call(['evidence','show','--project','managed','--id',result.evidence_ids[0]]);
assert.equal(evidence.evidence[0].native_result.artifact_sha256,target.artifact_sha256);
assert.equal(evidence.evidence[0].native_result.method.token,method.token);
const entities=call(['index','entities','--project','managed','--backend','ilspy','--kind','managed_method']);
assert.ok(entities.records.some(row=>row.native_id===method.token));
assert.ok(entities.records.every(row=>row.location.address_space==='managed_metadata' && !('rva' in row.location)));
const tokens=call(['index','entities','--project','managed','--backend','ilspy','--kind','token']);
assert.ok(tokens.records.some(row=>row.location.address_space==='managed_il:'+method.token));
assert.equal(call(['functions','--project','managed']).functions.length,0);
const page=query('methods',['--max-items','1','--offset','1']);
assert.equal(page.data.methods.length,1);
assert.equal(page.data.methods[0].token,method.token);
const inv=request('harness','create',{project:'managed',target_id:target.id,objective:'Inspect managed fixture without execution',required_facts:['managed metadata'],owner:{mode:'external',name:'ilspy offline test',model_declaration:'deterministic test; no model'},budget:{max_actions:2,wall_ms:30000,output_bytes:131072}});
const excerpt=request('harness','read',{project:'managed',id:inv.id,family:'evidence',operation:'read',request:{id:result.evidence_ids[0],pointer:'/pseudocode',max_bytes:64}});
assert.equal(excerpt.source_verified,true);
assert.equal(excerpt.raw_sha256,result.raw_sha256);
assert.equal(excerpt.text,Buffer.from(result.data.pseudocode).subarray(0,64).toString('utf8'));
const descriptors=request('harness','read',{project:'managed',id:inv.id,family:'index',operation:'entities',request:{backend:'ilspy',kind:'managed_method',limit:2}});
assert.ok(descriptors.records.length>0);
assert.ok(descriptors.records.every(row=>row.details_omitted && row.evidence_id && row.json_pointer && !row.native));
const descriptor=descriptors.records[0];
const nativeMethod=request('harness','read',{project:'managed',id:inv.id,family:'evidence',operation:'read',request:{id:descriptor.evidence_id,pointer:descriptor.json_pointer+'/token'}});
assert.equal(nativeMethod.type,'string');
assert.equal(nativeMethod.text,descriptor.native_id);
function owned(operation,value) {
  const current=call(['harness','show','--project','managed','--id',inv.id]);
  return request('harness',operation,{project:'managed',id:inv.id,owner_token:inv.owner_token,expected_revision:current.revision,...value});
}
const proposal=owned('propose',{key:'inventory',proposal:{gap:'managed metadata',expected_evidence:'ILSpy inventory',prediction:'Compile-only managed PE',fallback:'Retain partial evidence'},request:{backend:'ilspy',operation:'inventory',target_id:target.id,budget:{wall_ms:5000,output_bytes:65536,max_items:16,memory_bytes:67108864}}});
const action=owned('run',{action_id:proposal.id});
assert.equal(action.result.status,'completed');
assert.equal(owned('run',{action_id:proposal.id}).job_id,action.job_id);
owned('release',{});
console.log(JSON.stringify({status:'passed',mode:mode||'native',workspace,method:method.token,evidence:result.evidence_ids[0],target_executed:false}));
