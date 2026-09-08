// Read-only checks. Only the analysis executable is launched, never the fixture.
const fs=require('node:fs'), cp=require('node:child_process'), crypto=require('node:crypto'), assert=require('node:assert/strict');
const [exe,fixture,format,mode]=process.argv.slice(2);
const data=fs.readFileSync(fixture),sha=crypto.createHash('sha256').update(data).digest('hex');
const linux=mode==='wsl';
const pathForWorker=linux?'/mnt/'+fixture[0].toLowerCase()+fixture.slice(2).replaceAll('\\','/'):fixture;
function query(operation,changes={}){
 const request={path:pathForWorker,sha256:sha,operation,offset:0,limit:128,output_bytes:65536,...changes};
 const args=[JSON.stringify(request)];
 const r=cp.spawnSync(linux?'wsl.exe':exe,linux?['-d','Ubuntu','--',exe,...args]:args,{encoding:'utf8',timeout:20000,maxBuffer:1048576});
 assert.ifError(r.error);assert.ok([0,1].includes(r.status),r.stderr);
 return JSON.parse(r.stdout);
}
const inventory=query('inventory');assert.equal(inventory.status,'completed');assert.equal(inventory.format,format);assert.equal(inventory.artifact_sha256,sha);
let sections=[],offset=0;
for(let i=0;i<512;i++){
 const page=query('sections',{offset,limit:2,output_bytes:4096});assert.notEqual(page.status,'failed');
 sections.push(...page.sections);if(page.page.next_offset===null)break;
 assert.ok(page.page.next_offset>offset);offset=page.page.next_offset;
}
assert.equal(sections.length,inventory.inventory.section_count);assert.equal(new Set(sections.map(s=>s.native_ordinal)).size,sections.length);
assert.equal(query('libraries').status,'completed');
if(format==='PE'){
 const resource=query('resources');assert.equal(resource.status,'completed');assert.ok(resource.resources.length>0);
 for(const row of resource.resources){assert.equal(row.file_range_verified,true);assert.equal(row.location.address_space,'file');assert.equal(crypto.createHash('sha256').update(data.subarray(row.file_offset,row.file_offset+row.size)).digest('hex'),row.content_sha256);}
 assert.ok(resource.resources.some(r=>data.subarray(r.file_offset,r.file_offset+r.size).includes(Buffer.from('Indago Resource'))));
 assert.equal(query('notes').status,'failed');
}else{
 const notes=query('notes');assert.equal(notes.status,'completed');assert.ok(notes.notes.length>0);assert.equal(query('resources').status,'failed');
}
for(const bad of [{sha256:'0'.repeat(64)},{offset:-1},{limit:0},{output_bytes:4095}])assert.equal(query('sections',bad).status,'failed');
console.log(JSON.stringify({status:'passed',format,sections:sections.length,artifact_sha256:sha,target_executed:false}));
