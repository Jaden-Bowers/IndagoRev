// Trusted source-backed fixture only. Each engine run is bounded below 10 s.
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const [exe,fixture,...engines]=process.argv.slice(2);if(!fixture)throw Error('usage: indago fixture [debugger frida dynamorio rr]');
const root=fs.mkdtempSync(path.resolve('out/task5-engines-')),workspace=path.join(root,'state');let n=0;
function app(request){const file=path.join(root,'request.json');fs.writeFileSync(file,JSON.stringify(request));
 const args=request.operation==='create'?['project','create','--name','engines']:['runtime',request.operation,'--request',file];
 const r=spawnSync(exe,['--workspace',workspace,...args],{encoding:'utf8',timeout:15000,maxBuffer:2**21});if(r.error)throw r.error;
 let data;try{data=JSON.parse(r.stdout)}catch{throw Error(r.stdout+r.stderr)}fs.writeFileSync(path.join(root,`${++n}.json`),JSON.stringify(data,null,2));
 if(![0,3].includes(r.status))throw Error(JSON.stringify(data));return data;}
app({operation:'create'});const results=[];
for(const engine of engines.length?engines:['debugger','frida','dynamorio','rr']){
 let session;try{
 let s=app({operation:engine==='debugger'?'launch':engine==='rr'?'record':'instrument',project:'engines',file:path.resolve(fixture),argv:['--fixture'],
   input_hex:'7965730a',files:{payload:'626f756e64'},environment:{EXPERIMENT_VALUE:'explicit'},timeout_ms:3000,
   ...(engine==='debugger'?{lifetime_ms:8000,terminate_on_expiry:true}:engine==='rr'?{backend:'rr',trace_bytes:16777216}:{backend:engine,max_events:64,...(engine==='frida'?{recipe:'io'}:{})})});
 session=s.id;const end=Date.now()+7000;
 while(!['completed','failed','exited','terminated','cancelled','detached'].includes(s.state)&&Date.now()<end){
   if(engine==='debugger'&&s.state==='stopped')app({operation:'continue',project:'engines',session,wait:true,timeout_ms:1000});
   s=app({operation:'status',project:'engines',session});
 }
 const dir=s.request?.cwd||path.join(workspace,'runtime-artifacts',session,'inputs');const output=fs.existsSync(path.join(dir,'delivery.txt'))?fs.readFileSync(path.join(dir,'delivery.txt'),'utf8'):null;
 results.push({engine,session,state:s.state,result_status:s.result_status,delivered:output==='accepted:explicit:bound',output,replay_ready:s.replay_ready,diagnostic:s.diagnostic});
 }catch(e){results.push({engine,session,error:e.message,delivered:false});}
 finally{if(session)try{app({operation:engine==='debugger'?'terminate':'cancel',project:'engines',session,timeout_ms:1000});}catch{}}
}
fs.writeFileSync(path.join(root,'summary.json'),JSON.stringify({root,results},null,2));console.log(JSON.stringify({root,results},null,2));
process.exitCode=results.some(r=>!r.delivered)?1:0;
