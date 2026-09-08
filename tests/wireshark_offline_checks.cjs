// Fabricated capture bytes only. No socket, packet capture, DNS lookup or target
// program is used to produce these fixtures.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const [directory,mode]=process.argv.slice(2);
const nativePath=value=>mode==='wsl'?path.resolve(value).replace(/^([A-Za-z]):/,(_,drive)=>'/mnt/'+drive.toLowerCase()).replaceAll('\\','/'):path.resolve(value);
const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'indago-offline-packets-'));
function checksum(bytes){let n=0;for(let i=0;i<bytes.length;i+=2)n+=(bytes[i]<<8)|(bytes[i+1]||0);while(n>>16)n=(n&65535)+(n>>>16);return (~n)&65535;}
function packet(){
 const qname=Buffer.concat(['fixture','invalid'].map(s=>Buffer.concat([Buffer.from([s.length]),Buffer.from(s)])));
 const dns=Buffer.concat([Buffer.from('123401000001000000000000','hex'),qname,Buffer.from('0000010001','hex')]);
 const udp=Buffer.alloc(8);udp.writeUInt16BE(53000,0);udp.writeUInt16BE(53,2);udp.writeUInt16BE(8+dns.length,4);
 const ip=Buffer.from('450000000001000040110000c0000201c0000202','hex');ip.writeUInt16BE(20+8+dns.length,2);ip.writeUInt16BE(checksum(ip),10);
 return Buffer.concat([Buffer.from('0200000000020200000000010800','hex'),ip,udp,dns]);
}
const frame=packet();
const pcap=Buffer.alloc(24+16+frame.length);pcap.writeUInt32LE(0xa1b2c3d4,0);pcap.writeUInt16LE(2,4);pcap.writeUInt16LE(4,6);pcap.writeUInt32LE(65535,16);pcap.writeUInt32LE(1,20);pcap.writeUInt32LE(1700000000,24);pcap.writeUInt32LE(123456,28);pcap.writeUInt32LE(frame.length,32);pcap.writeUInt32LE(frame.length,36);frame.copy(pcap,40);
function block(type,body){const out=Buffer.alloc(12+body.length);out.writeUInt32LE(type,0);out.writeUInt32LE(out.length,4);body.copy(out,8);out.writeUInt32LE(out.length,out.length-4);return out;}
const section=Buffer.from('4d3c2b1a01000000ffffffffffffffff','hex');
const iface=Buffer.alloc(20);iface.writeUInt16LE(1,0);iface.writeUInt32LE(65535,4);iface.writeUInt16LE(9,8);iface.writeUInt16LE(1,10);iface[12]=9;
const epb=Buffer.alloc(20+Math.ceil(frame.length/4)*4);const ticks=1700000000123456789n;epb.writeUInt32LE(Number(ticks>>32n),4);epb.writeUInt32LE(Number(ticks&0xffffffffn),8);epb.writeUInt32LE(frame.length,12);epb.writeUInt32LE(frame.length,16);frame.copy(epb,20);
const captures={pcap,pcapng:Buffer.concat([block(0x0a0d0d0a,section),block(1,iface),block(6,epb)])};
function tcpPacket(reverse,seq,ack,flags,payload=''){
 const bytes=Buffer.from(payload),tcp=Buffer.alloc(20);
 tcp.writeUInt16BE(reverse?80:54000,0);tcp.writeUInt16BE(reverse?54000:80,2);
 tcp.writeUInt32BE(seq,4);tcp.writeUInt32BE(ack,8);tcp[12]=0x50;tcp[13]=flags;tcp.writeUInt16BE(65535,14);
 const ip=Buffer.from(reverse?'450000000001000040060000c0000202c0000201':'450000000001000040060000c0000201c0000202','hex');
 ip.writeUInt16BE(40+bytes.length,2);ip.writeUInt16BE(checksum(ip),10);
 const pseudo=Buffer.alloc(12);ip.copy(pseudo,0,12,20);pseudo[9]=6;pseudo.writeUInt16BE(20+bytes.length,10);
 tcp.writeUInt16BE(checksum(Buffer.concat([pseudo,tcp,bytes])),16);
 return Buffer.concat([Buffer.from(reverse?'0200000000010200000000020800':'0200000000020200000000010800','hex'),ip,tcp,bytes]);
}
const firstHttp='GET /fixture HTTP/1.1\r\nHost: fixture.';
const tcpFrames=[tcpPacket(false,100,0,2),tcpPacket(true,200,101,0x12),tcpPacket(false,101,201,0x10),tcpPacket(false,101,201,0x18,firstHttp),tcpPacket(false,101+Buffer.byteLength(firstHttp),201,0x18,'invalid\r\n\r\n')];
const tcpRecords=tcpFrames.map((bytes,i)=>{const header=Buffer.alloc(16);header.writeUInt32LE(1700000000,0);header.writeUInt32LE(123456+i*1000,4);header.writeUInt32LE(bytes.length,8);header.writeUInt32LE(bytes.length,12);return Buffer.concat([header,bytes]);});
captures.tcp=Buffer.concat([pcap.subarray(0,24),...tcpRecords]);
fs.writeFileSync(path.join(scratch,'two.pcap'),Buffer.concat([pcap,pcap.subarray(24)]));
fs.writeFileSync(path.join(scratch,'truncated.pcap'),Buffer.concat([pcap,pcap.subarray(24,pcap.length-4)]));
const config=path.join(scratch,'config'),plugins=path.join(scratch,'plugins');fs.mkdirSync(config);fs.mkdirSync(plugins);
const env={...process.env,WIRESHARK_CONFIG_DIR:config,WIRESHARK_PLUGIN_DIR:plugins,WIRESHARK_DATA_DIR:config,WIRESHARK_EXTCAP_DIR:path.join(scratch,'no-extcap')};delete env.WIRESHARK_RUN_FROM_BUILD_DIRECTORY;
for(const [format,bytes] of Object.entries(captures)){
 const file=path.join(scratch,'fixture.'+format);fs.writeFileSync(file,bytes);
 const args=['-n','-r',nativePath(file),'-c','8','-o','frame.show_file_off:true','-T','json','--no-duplicate-keys','-x'];
 const result=mode==='wsl'?spawnSync('wsl.exe',['-d','Ubuntu','--exec','env','-u','WIRESHARK_RUN_FROM_BUILD_DIRECTORY','WIRESHARK_CONFIG_DIR='+nativePath(config),'WIRESHARK_DATA_DIR='+nativePath(config),'WIRESHARK_PLUGIN_DIR='+nativePath(plugins),directory+'/tshark',...args],{encoding:'utf8',timeout:20000,maxBuffer:1048576}):spawnSync(path.resolve(directory,'tshark.exe'),args,{env,cwd:config,encoding:'utf8',timeout:20000,maxBuffer:1048576});
 assert.ifError(result.error);assert.equal(result.status,0,result.stdout+result.stderr);
 const document=JSON.parse(result.stdout);
 if(format==='tcp'){
  assert.equal(document.length,5);assert.ok(document.every(p=>p._source.layers.tcp['tcp.stream']==='0'));
  document.forEach((p,i)=>assert.equal(p._source.layers.frame_raw[0],tcpFrames[i].toString('hex')));
  const last=document.at(-1)._source.layers;assert.equal(last.http['http.host'],'fixture.invalid');
  assert.ok(JSON.stringify(last).includes('/fixture'));
  fs.writeFileSync(path.join(scratch,'tcp.json'),result.stdout);continue;
 }
 assert.equal(document.length,1);const layers=document[0]._source.layers;
 assert.equal(layers.frame_raw[0],frame.toString('hex'));assert.equal(layers.frame['frame.cap_len'],String(frame.length));
 assert.equal(layers.ip['ip.src'],'192.0.2.1');assert.equal(layers.ip['ip.dst'],'192.0.2.2');
 assert.ok(layers.frame['frame.file_off']);
 assert.ok(JSON.stringify(layers.dns).includes('fixture.invalid'));
 // This pinned upstream JSON encoder renders even frame.time_epoch as ISO UTC;
 // retain native text instead of guessing a numeric representation from its name.
 assert.equal(layers.frame['frame.time_epoch'],format==='pcap'?'2023-11-14T22:13:20.123456000Z':'2023-11-14T22:13:20.123456789Z');
 if(format==='pcapng')assert.equal(layers.frame['frame.interface_id'],'0');
 fs.writeFileSync(path.join(scratch,format+'.json'),result.stdout);
}
console.log(JSON.stringify({status:'passed',scratch,formats:Object.keys(captures),traffic_captured:false,network_requests_sent:false,frame_bytes:frame.length}));
