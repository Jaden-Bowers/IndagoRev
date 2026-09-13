const fs=require('node:fs'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const [exe,profile='native',destination]=process.argv.slice(2);
if(!exe||!['native','full'].includes(profile))throw Error('Usage: EXE native|full [MANIFEST]');
const r=spawnSync(exe,['capabilities'],{encoding:'utf8',timeout:180000,maxBuffer:4*1024**2,windowsHide:true});
if(r.error||r.status!==0)throw Error('Capability command failed');
const c=JSON.parse(r.stdout),required=profile==='full'?['airece','xair','sym','ghidra','ilspy','capa','floss','lief','wireshark']:['airece','xair','sym'];
const missing=required.filter(n=>!c.backends.some(b=>b.name===n&&b.available));
if(profile==='full'){
 if(!c.backends.some(b=>b.name==='ghidra'&&b.bundled))missing.push('bundled-ghidra');
 for(const n of ['frida','dynamorio'])if(!c.runtime[n]?.bundled)missing.push(n);
}
function fileHash(file){const h=crypto.createHash('sha256'),fd=fs.openSync(file,'r'),buffer=Buffer.alloc(1048576);
 try{let n;while((n=fs.readSync(fd,buffer,0,buffer.length,null))>0)h.update(buffer.subarray(0,n));return h.digest('hex');}finally{fs.closeSync(fd);}}
const manifest={schema:'indago.build-capabilities.v1',profile,passed:missing.length===0,missing,
 executable_sha256:fileHash(exe),
 backends:c.backends.map(b=>({name:b.name,available:b.available,bundled:b.bundled??null,operations:b.operations})),
 runtime:{backend:c.runtime.backend,frida:c.runtime.frida.bundled,dynamorio:c.runtime.dynamorio.bundled,rr:c.runtime.rr.bundled},
 qualification:false,optional_profiles:['qemu','rr-supported-host'],host_execution_sandboxed:false};
if(destination)fs.writeFileSync(destination,JSON.stringify(manifest,null,2)+'\n');
console.log(JSON.stringify(manifest));if(missing.length)process.exitCode=1;
