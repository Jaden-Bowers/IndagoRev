// Bounded, fabricated capture analysis only; never sends or captures traffic.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const [exe,fixture,mode]=process.argv.slice(2);
const workspace=fs.mkdtempSync(path.join(os.tmpdir(),'indago-reassembly-cli-'));
const nativePath=value=>mode==='wsl'?path.resolve(value).replace(/^([A-Za-z]):/,(_,drive)=>'/mnt/'+drive.toLowerCase()).replaceAll('\\','/'):path.resolve(value);
function call(args){
 const base=['--workspace',nativePath(workspace),...args];
 const result=mode==='wsl'?spawnSync('wsl.exe',['-d','Ubuntu','--exec',exe,...base],{encoding:'utf8',timeout:20000,maxBuffer:1048576}):spawnSync(path.resolve(exe),base,{encoding:'utf8',timeout:20000,maxBuffer:1048576});
 assert.ifError(result.error);assert.ok([0,3].includes(result.status),result.stdout+result.stderr);return JSON.parse(result.stdout);
}
call(['project','create','--name','tcp']);
const target=call(['target','import','--project','tcp','--file',nativePath(fixture)]);
const query=extra=>call(['query','--project','tcp','--backend','wireshark','--operation','packets','--timeout-ms','10000','--max-output-bytes','262144',...extra]);
const all=query(['--max-items','8']);assert.equal(all.status,'completed');assert.equal(all.data.packets.length,5);
assert.equal(all.data.streams.length,1);assert.equal(all.data.streams[0].transport,'tcp');assert.equal(all.data.streams[0].complete,false);
const last=all.data.packets[4],refs=last.frame_refs.filter(ref=>ref.kind==='native_tcp_segment_source');
assert.deepEqual(refs.map(ref=>ref.native_frame_number),['4','5']);
function pointer(document,value){return value.slice(1).split('/').reduce((node,key)=>node[key.replaceAll('~1','/').replaceAll('~0','~')],document);}
for(const packet of all.data.packets)for(const ref of packet.frame_refs){
 assert.equal(pointer(all.data,ref.native_pointer),ref.native_frame_number);
 assert.equal(ref.target_packet_id,target.artifact_sha256+':'+ref.native_frame_number);
 assert.equal(ref.target_location.address_space,'capture_frame');
}
assert.equal(last.frame_reference_projection_partial,false);
const relations=call(['index','relations','--project','tcp','--backend','wireshark','--kind','native_tcp_segment_source']);
assert.equal(relations.records.length,2);assert.ok(relations.records.every(r=>typeof r.target_entity==='string'&&r.target_location.address_space==='capture_frame'&&!r.target_location.file_offset));
const single=query(['--offset','4','--max-items','1']);assert.equal(single.status,'completed');
assert.equal(single.data.packets.length,1);assert.equal(single.data.streams[0].id,all.data.streams[0].id);
assert.deepEqual(single.data.packets[0].frame_refs.filter(ref=>ref.kind==='native_tcp_segment_source').map(ref=>ref.native_frame_number),['4','5']);
assert.ok(single.data.packets[0].frame_refs.every(ref=>ref.native_pointer.startsWith('/native_packets/0/')));
const native=single.data.native_packets[0]._source.layers;
assert.equal(native.http['http.host'],'fixture.invalid');
assert.equal(native['tcp.segments']['tcp.reassembled.data_raw'][0],Buffer.from('GET /fixture HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n').toString('hex'));
console.log(JSON.stringify({status:'passed',workspace,packets:5,reassembly_sources:refs.length,traffic_captured:false,network_requests_sent:false}));
