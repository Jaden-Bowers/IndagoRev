// Operator-only, generated benign fixture; each process is bounded below 5s.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const [exe,fixture]=process.argv.slice(2);if(!exe||!fixture)throw Error('indago and io fixture required');
const root=fs.mkdtempSync(path.resolve('out/runtime-io-contract-')),workspace=path.join(root,'state');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
let count=0;
function app(args,request,fail=false){
 const file=path.join(root,'request.json');if(request)fs.writeFileSync(file,JSON.stringify(request));
 const r=spawnSync(exe,['--workspace',workspace,...args,...(request?['--request',file]:[])],{encoding:'utf8',timeout:10000,maxBuffer:1024**2});
 if(r.error)throw r.error;const result=JSON.parse(r.stdout);fs.writeFileSync(path.join(root,`${++count}.json`),JSON.stringify(result,null,2));
 if(fail?r.status===0:![0,3].includes(r.status))throw Error(JSON.stringify(result));return result;
}
function check(ok,text){if(!ok)throw Error(text);}
app(['project','create','--name','io']);
const artifact=sha(fs.readFileSync(fixture)),oracle=path.join(root,'oracle.json');
fs.writeFileSync(oracle,JSON.stringify({schema:'indago.io-oracle.v1',artifact_sha256:artifact,fact:'accepted input',stdout_hex:'4f4b',exit_code:0,negative_input_hex:'4e4f'}));
const request={operation:'io-run',project:'io',file:path.resolve(fixture),artifact,input_hex:'4f50454e',trusted_target_ack:true,timeout_ms:3000,max_output_bytes:1024,acceptance_oracle:oracle};
const run=(change={},fail=false)=>app(['runtime','io-run'],{...request,...change},fail);
const positive=run();check(positive.observation.data.accepted===true&&positive.observation.data.output==='OK','Exact accepted input receipt');
const denied=run({input_hex:'424144'});check(denied.observation.data.accepted===false&&denied.observation.data.output==='NO','Negative input');
const decoy=run({argv:['ignore']});check(decoy.observation.data.accepted===false,'Input-independent success rejected by contrasting control');
const partial=run({argv:['flood'],max_output_bytes:1});check(partial.observation.data.complete===false&&partial.observation.data.accepted===false,'Truncated output cannot prove acceptance');
const timeout=run({argv:['sleep'],timeout_ms:60});check(timeout.observation.data.complete===false,'Timeout is partial');
const cancel=path.join(root,'cancel');fs.writeFileSync(cancel,'cancel');
check(run({cancel_file:cancel}).observation.data.cancelled===true,'Cancellation receipt');
const raw=run({argv:['binary']});check(raw.observation.data.output_hex==='ff'&&!('output' in raw.observation.data),'Binary stdout preserved without UTF8 fabrication');
const child=run({argv:['child']});check(child.observation.data.complete===false&&child.observation.data.output_eof===false,'Parent exit with inherited open output is not complete');
run({trusted_target_ack:false},true);run({artifact:'0'.repeat(64)},true);
run({input_hex:'4e4f'},true);
const saved=app(['runtime','observations'],{operation:'observations',project:'io',session:positive.id,id:positive.observation.id,limit:1});
check(saved.observations[0].sha256===positive.observation.sha256,'Persisted receipt hash');
console.log(JSON.stringify({status:'passed',checks:12,root}));
