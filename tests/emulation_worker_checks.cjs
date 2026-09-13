const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const exe=process.argv[2],root=fs.mkdtempSync(path.resolve('out/emulation-worker-'));let n=0;
function run(code,q){const input=path.join(root,`input${++n}`),request=path.join(root,`request${n}.json`);fs.writeFileSync(input,Buffer.from(code,'hex'));fs.writeFileSync(request,JSON.stringify(q));const p=spawnSync(exe,[request,input],{encoding:'utf8',timeout:5000,maxBuffer:65536});assert.ifError(p.error);const r=JSON.parse(p.stdout);fs.writeFileSync(path.join(root,`result${n}.json`),JSON.stringify(r));return r;}
let r=run('b82a000000',{bits:32,base:4096,entry:4096,stop:4101});assert.equal(r.status,'completed');assert.equal(r.registers.eax,42);
r=run('48c7c02a000000',{bits:64,base:0x140000000,entry:0x140000000,stop:0x140000007});assert.equal(r.status,'completed');assert.equal(r.registers.rax,42);
r=run('ebfe',{bits:32,base:4096,entry:4096,stop:4098,instructions:5});assert.equal(r.status,'partial');assert.equal(r.stop_reason,'instruction_limit');
r=run('e480',{bits:32,base:4096,entry:4096,stop:4098});assert.equal(r.stop_reason,'unmodeled_port_io');
r=run('90',{bits:32,base:4097,entry:4097,stop:4098});assert.equal(r.status,'failed');
console.log(JSON.stringify({passed:true,root,cases:5}));
