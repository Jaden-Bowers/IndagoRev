const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const [worker,app,dependency]=process.argv.slice(2);
const linux=worker.startsWith('wsl:'),native=p=>linux?path.resolve(p).replace(/^([A-Za-z]):/,(_,d)=>'/mnt/'+d.toLowerCase()).replaceAll('\\','/'):path.resolve(p);
const hash=p=>crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const dep={path:native(dependency),sha256:hash(dependency)};
function run(operation,extra={}) {
 const args=[JSON.stringify({path:native(app),sha256:hash(app),operation,wall_ms:5000,output_bytes:65536,...extra})];
 const r=spawnSync(linux?'wsl.exe':worker,linux?['--exec',worker.slice(4),...args]:args,{encoding:'utf8',timeout:10000});assert.ifError(r.error);return JSON.parse(r.stdout);
}
const absent=run('references');assert.equal(absent.references.find(r=>r.name.startsWith('Indago.Dependency,')).resolution,'unresolved');
const resolved=run('references',{dependencies:[dep]});const ref=resolved.references.find(r=>r.name.startsWith('Indago.Dependency,'));assert.equal(ref.target_artifact_sha256,dep.sha256);assert.equal(ref.resolution,'exact_assembly_identity');
const methods=run('methods'),method=methods.methods.find(m=>m.name==='Select');assert(method);
const members=run('member_refs',{dependencies:[dep]});const add=members.member_refs.find(r=>r.name==='Add');assert.equal(add.target_artifact_sha256,dep.sha256);assert.match(add.target_token,/^0x06/);
const source=run('decompile',{token:method.token,dependencies:[dep]});assert(source.pseudocode.includes('Add'));assert(source.source_il_mappings.length>0,JSON.stringify(source));
const pdb=app.replace(/\.dll$/,'.pdb'),wrongPdb=dependency.replace(/\.dll$/,'.pdb');
const mapped=run('decompile',{token:method.token,dependencies:[dep],pdb:{path:native(pdb),sha256:hash(pdb)}});
assert.equal(mapped.original_source_mapping.debug_identity_matched,true);assert(mapped.original_source_mapping.sequence_points.length>0);assert.equal(mapped.original_source_mapping.source_files_read,false);
assert.equal(run('decompile',{token:method.token,pdb:{path:native(wrongPdb),sha256:hash(wrongPdb)}}).status,'failed');
assert.equal(run('decompile',{token:method.token,pdb:{path:native(pdb),sha256:'0'.repeat(64)}}).status,'failed');
assert(source.resolved_reference_requests>0,'decompiler did not resolve imported dependency');
const lines=source.pseudocode.split('\n');for(const map of source.source_il_mappings){assert(map.start_line>=1&&map.start_line<=lines.length);assert(map.il_end>=map.il_start);}
const resources=run('resources');const resource=resources.resources[0],bytes=fs.readFileSync(app).subarray(resource.file_offset,resource.file_offset+resource.size);assert.equal(crypto.createHash('sha256').update(bytes).digest('hex'),resource.sha256);assert(bytes.toString().includes('indago-task7-resource'));
assert.equal(run('references',{dependencies:[{...dep,sha256:'0'.repeat(64)}]}).status,'failed');
assert.equal(run('references',{dependencies:[dep,dep]}).status,'failed');
assert.equal(source.target_executed,false);console.log(JSON.stringify({passed:true,reference:ref,source_il_mappings:source.source_il_mappings.length,resource,unresolved_framework_requests:source.unresolved_reference_requests},null,2));
