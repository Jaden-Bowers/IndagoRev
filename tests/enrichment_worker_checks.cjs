const fs=require('node:fs');
const path=require('node:path');
const assert=require('node:assert/strict');
const {spawnSync}=require('node:child_process');
const [directory,fixture,reportDirectory]=process.argv.slice(2);
if(!directory||!fixture||!reportDirectory)throw Error('worker directory, benign fixture, report directory required');
fs.mkdirSync(reportDirectory,{recursive:true});
const suffix=process.platform==='win32'?'.exe':'';
for(const [tool,arguments_] of [
  ['capa',['--backend','vivisect','--format','pe','--json','--color','never','--quiet',path.resolve(fixture)]],
  ['floss',['--only','static','--json','--color','never','--quiet','--',path.resolve(fixture)]]
]) {
  const result=spawnSync(path.resolve(directory,tool+suffix),arguments_,{encoding:'utf8',timeout:30000,maxBuffer:2097152});
  fs.writeFileSync(path.join(reportDirectory,tool+'.stderr.log'),result.stderr||'');
  assert.ifError(result.error);
  assert.equal(result.status,0,result.stderr);
  const native=JSON.parse(result.stdout);
  fs.writeFileSync(path.join(reportDirectory,tool+'.json'),JSON.stringify(native));
  assert.ok(native && typeof native==='object');
  console.log(JSON.stringify({tool,status:'passed',bytes:Buffer.byteLength(result.stdout),native_keys:Object.keys(native)}));
}
