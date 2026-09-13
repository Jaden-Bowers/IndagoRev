const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const [exe,fixture]=process.argv.slice(2),root=fs.mkdtempSync(path.resolve('out/task7-runtime-'));let n=0;
const linux=exe.startsWith('wsl:'),native=p=>linux?p.replace(/^([A-Za-z]):/,(_,d)=>'/mnt/'+d.toLowerCase()).replaceAll('\\','/'):p;
function run(args,r){const f=path.join(root,`request-${++n}.json`);if(r){if(r.file)r.file=native(r.file);fs.writeFileSync(f,JSON.stringify(r));}const argv=['--workspace',native(path.join(root,'state')),...args.map(native),...(r?['--request',native(f)]:[])];const p=spawnSync(linux?'wsl.exe':exe,linux?['--exec',exe.slice(4),...argv]:argv,{encoding:'utf8',timeout:30000,maxBuffer:4*1024*1024});assert.ifError(p.error);const result=JSON.parse(p.stdout);fs.writeFileSync(path.join(root,`response-${n}.json`),JSON.stringify(result,null,2));assert([0,3].includes(p.status),p.stdout+p.stderr);return result;}
run(['project','create','--name','trace']);const target=run(['target','import','--project','trace','--file',path.resolve(fixture)]);
const result=run(['runtime','io-run'],{project:'trace',file:path.resolve(fixture),artifact:target.artifact_sha256,input_hex:'',environment:{},timeout_ms:10000,max_output_bytes:65536,trusted_target_ack:true,managed_trace:true});
fs.writeFileSync(path.join(root,'summary.json'),JSON.stringify(result,null,2));
const events=run(['runtime','observations'],{project:'trace',session:result.id,kind:'managed_trace',limit:8});
fs.writeFileSync(path.join(root,'events.json'),JSON.stringify(events,null,2));
const raw=JSON.stringify(events);assert(raw.includes('managed_exception'),raw.slice(0,1800));assert(raw.includes('managed_method'));assert(raw.includes('trace_artifact_sha256'));console.log(JSON.stringify({passed:true,root,session:result.id},null,2));
