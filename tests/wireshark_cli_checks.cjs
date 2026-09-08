const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const [exe,fixture,mode]=process.argv.slice(2);
const nativePath=value=>mode==='wsl'?path.resolve(value).replace(/^([A-Za-z]):/,(_,drive)=>'/mnt/'+drive.toLowerCase()).replaceAll('\\','/'):path.resolve(value);
const workspace=fs.mkdtempSync(path.join(os.tmpdir(),'indago-packet-cli-'));
const foreign=path.join(workspace,'foreign-profile');fs.mkdirSync(foreign);
fs.writeFileSync(path.join(foreign,'init.lua'),'error("The caller profile must not be loaded by the packet worker")\n');
const env={...process.env,WIRESHARK_CONFIG_DIR:foreign,WIRESHARK_PLUGIN_DIR:foreign,WIRESHARK_DATA_DIR:foreign,WIRESHARK_EXTCAP_DIR:foreign,WIRESHARK_RUN_FROM_BUILD_DIRECTORY:'1'};
function call(args,expected=[0,3]){
 const base=['--workspace',nativePath(workspace),...args];
 const foreignNative=nativePath(foreign);
 const r=mode==='wsl'?spawnSync('wsl.exe',['-d','Ubuntu','--exec','env',...['CONFIG','PLUGIN','DATA','EXTCAP'].map(key=>'WIRESHARK_'+key+'_DIR='+foreignNative),'WIRESHARK_RUN_FROM_BUILD_DIRECTORY=1',exe,...base],{encoding:'utf8',timeout:20000,maxBuffer:1048576}):spawnSync(path.resolve(exe),base,{env,encoding:'utf8',timeout:20000,maxBuffer:1048576});
 assert.ifError(r.error);assert.ok(expected.includes(r.status),r.stdout+r.stderr);return JSON.parse(r.stdout);
}
call(['project','create','--name','packets']);
const imported=call(['target','import','--project','packets','--file',nativePath(fixture)]);
const query=extra=>call(['query','--project','packets','--backend','wireshark','--operation','packets','--timeout-ms','10000',...extra]);
const result=query(['--max-output-bytes','65536','--max-items','8']);
assert.equal(result.status,'completed');assert.equal(result.data.artifact_sha256,imported.artifact_sha256);assert.ok(result.data.native_packets.length>0);
assert.equal(result.data.policy.name_resolution,false);assert.equal(result.data.policy.external_plugins,false);assert.equal(result.data.capture_coverage_proven,false);
assert.equal(result.data.policy.lua_runtime_present,mode!=='wsl');
const preset=call(['analyze','--project','packets','--backend','wireshark','--timeout-ms','10000','--max-output-bytes','65536','--max-items','8']);
assert.equal(preset.results.length,1);assert.equal(preset.results[0].status,'completed');
assert.equal(result.data.packets[0].location.address_space,'capture_frame');assert.equal(result.data.packets[0].packet_number,'1');
assert.ok(result.data.packets[0].record_offset_native);assert.ok(JSON.stringify(result.data.native_packets).includes('fixture.invalid'));
const index=call(['index','entities','--project','packets','--backend','wireshark','--kind','packet']);assert.equal(index.records.length,result.data.packets.length);
assert.ok(index.records.every(row=>row.location.address_space==='capture_frame'&&!row.location.file_offset));
assert.ok(index.records.every(row=>row.source_status==='completed'&&row.source_result_incomplete===false&&row.projection_partial===false));
const streams=call(['index','entities','--project','packets','--backend','wireshark','--kind','packet_stream']);
assert.equal(streams.records.length,1);assert.equal(streams.records[0].location,null);
assert.equal(result.data.streams[0].transport,'udp');assert.equal(result.data.streams[0].complete,false);
assert.equal(result.data.streams[0].packet_ids.length,result.data.packets.length);
assert.equal(result.data.packets[0].stream_refs[0].id,result.data.streams[0].id);
assert.equal(result.data.streams[0].native_ordinal,'0');
const raw=call(['evidence','show','--project','packets','--id',result.evidence_ids[0]]);assert.deepEqual(raw.evidence[0].native_result.native_packets,result.data.native_packets);
if(result.data.packets.length>1){
 const first=query(['--max-output-bytes','65536','--max-items','1']);assert.equal(first.status,'partial');assert.equal(first.data.page.next_offset,1);
 assert.equal(first.index.partial,true);
 const indexedPartial=call(['index','revisions','--project','packets','--revision',first.result_revision]);
 assert.equal(indexedPartial.records[0].source_status,'partial');assert.equal(indexedPartial.records[0].projection_partial,false);
 const next=query(['--max-output-bytes','65536','--max-items','1','--offset','1']);assert.equal(next.status,'completed');assert.equal(next.data.packets[0].packet_number,'2');assert.equal(next.data.page.next_offset,null);
 assert.notEqual(first.data.packets[0].id,next.data.packets[0].id);
 assert.equal(first.data.streams[0].id,next.data.streams[0].id);
 assert.equal(next.data.streams[0].packet_ids.length,1);
}
const small=query(['--max-output-bytes','4096']);assert.equal(small.status,'partial');assert.ok(Buffer.byteLength(JSON.stringify(small))<=4096);
call(['query','--project','packets','--backend','wireshark','--operation','packets','--offset','4097'],[2]);
function request(verb,value){const file=path.join(workspace,'request.json');fs.writeFileSync(file,JSON.stringify(value));return call(['harness',verb,'--request',nativePath(file)]);}
const inv=request('create',{project:'packets',target_id:imported.id,objective:'Inspect fabricated capture without accessing a network',required_facts:['packet evidence'],owner:{mode:'external',name:'offline fixture',model_declaration:'no model'},budget:{max_actions:2,wall_ms:30000,output_bytes:1048576}});
function owned(verb,value){const current=call(['harness','show','--project','packets','--id',inv.id]);return request(verb,{project:'packets',id:inv.id,owner_token:inv.owner_token,expected_revision:current.revision,...value});}
const proposed=owned('propose',{key:'packet-record',proposal:{gap:'packet evidence',expected_evidence:'Native offline packet fields and bytes',prediction:'Source-generated capture has a DNS question',fallback:'Preserve unknown attribution and malformed fields'},request:{backend:'wireshark',operation:'packets',budget:{wall_ms:10000,output_bytes:65536,max_items:8,memory_bytes:67108864}}});
const action=owned('run',{action_id:proposed.id});assert.equal(action.result.status,'completed');assert.equal(owned('run',{action_id:proposed.id}).job_id,action.job_id);owned('release',{});
const damaged=path.join(path.dirname(fixture),'truncated.pcap');
if(fs.existsSync(damaged)){
 call(['target','import','--project','packets','--file',nativePath(damaged)]);
 const partial=query(['--max-output-bytes','65536','--max-items','8']);assert.equal(partial.status,'partial');assert.equal(partial.data.upstream_completed,false);assert.equal(partial.data.packets.length,1);assert.notEqual(partial.data.native_exit_code,0);
}
console.log(JSON.stringify({status:'passed',workspace,packets:result.data.packets.length,traffic_captured:false,network_requests_sent:false}));
