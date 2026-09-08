const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),crypto=require('node:crypto'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const [exe,mode]=process.argv.slice(2),scratch=fs.mkdtempSync(path.join(os.tmpdir(),'indago-codec-cli-'));
const nativePath=value=>mode==='wsl'?path.resolve(value).replace(/^([A-Za-z]):/,(_,drive)=>'/mnt/'+drive.toLowerCase()).replaceAll('\\','/'):path.resolve(value);
const source=path.join(scratch,'source.bin'),cache=path.join(scratch,'cache');
const bytes=Buffer.alloc(2097152);for(let i=0;i<bytes.length;i++)bytes[i]=i%251;
fs.writeFileSync(source,bytes);
function run(file=source,success=true){
 const options={encoding:'utf8',timeout:20000,maxBuffer:65536};
 const r=mode==='wsl'?spawnSync('wsl.exe',['-d','Ubuntu','--exec',exe,nativePath(file),nativePath(cache)],options):spawnSync(path.resolve(exe),[file,cache],options);
 assert.ifError(r.error);assert.equal(r.status===0,success,r.stdout+r.stderr);return success?JSON.parse(r.stdout):null;
}
function select(file=source,compressed=true,success=true){
 const result=spawnSync('cmake',['-DRAW_FILE='+file,'-DINDAGO_PACKED_PAYLOAD_DIR='+cache,'-DEXPECT_COMPRESSED='+(compressed?'ON':'OFF'),'-P',path.join(__dirname,'packed_payload.cmake')],{encoding:'utf8',timeout:20000,maxBuffer:65536});
 assert.ifError(result.error);assert.equal(result.status===0,success,result.stdout+result.stderr);
}
const result=run();assert.equal(result.status,'packed');assert.equal(result.manifest.raw_sha256,crypto.createHash('sha256').update(bytes).digest('hex'));assert.equal(result.manifest.roundtrip_verified,true);
const packed=path.join(cache,result.manifest.raw_sha256+'.zst'),metadata=path.join(cache,result.manifest.raw_sha256+'.json');
const initial=fs.statSync(packed).mtimeMs;assert.deepEqual(run(),result);assert.equal(fs.statSync(packed).mtimeMs,initial);
select();
const original=fs.readFileSync(packed),corrupt=Buffer.from(original);corrupt[corrupt.length-1]^=0x80;fs.writeFileSync(packed,corrupt);run(source,false);select(source,true,false);fs.writeFileSync(packed,original);
const invalid={...result.manifest,raw_sha256:'0'.repeat(64)};fs.writeFileSync(metadata,JSON.stringify(invalid));run(source,false);
select(source,true,false);
const small=path.join(scratch,'small.bin');fs.writeFileSync(small,'small raw fixture');assert.equal(run(small).status,'raw');
select(small,false);
run(scratch,false);
assert.ok(fs.readdirSync(cache).every(name=>!name.startsWith('pack_')));
console.log(JSON.stringify({status:'passed',scratch,original_bytes:bytes.length,packed_bytes:result.manifest.stored_bytes,cached_roundtrip_verified:true,corruption_rejected:true,temporary_roundtrips_removed:true}));
