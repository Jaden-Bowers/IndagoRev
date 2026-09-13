const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const [exe,image]=process.argv.slice(2),root=fs.mkdtempSync(path.resolve('out/guest-interruption-'));let n=0;
const native=p=>p.replace(/^([A-Za-z]):/,(_,d)=>'/mnt/'+d.toLowerCase()).replaceAll('\\','/');
function command(op,r,kill=false){const f=path.join(root,`r${++n}.json`);fs.writeFileSync(f,JSON.stringify(r));const args=[exe,'--workspace',native(path.join(root,'state')),'guest',op,'--request',native(f)];const p=spawnSync('wsl.exe',['--exec',...(kill?['timeout','-s','KILL','2']:[]),...args],{encoding:'utf8',timeout:45000,maxBuffer:1048576});assert.ifError(p.error);if(kill){assert.notEqual(p.status,0);return;}assert.equal(p.status,0,p.stdout+p.stderr);return JSON.parse(p.stdout);}
(async()=>{
const sum=spawnSync('wsl.exe',['--exec','sha256sum',image],{encoding:'utf8'}).stdout.split(' ')[0];
const profile=command('create',{image:{path:image,sha256:sum},machine:'pc-i440fx-10.2',accelerator:'kvm',trusted_guest:true});
command('run',{profile:profile.id,actions:Array.from({length:5},()=>({operation:'observe',duration_ms:1000}))},true);
const runs=command('list',{});assert.equal(runs.runs.length,1);const id=runs.runs[0].id;assert.equal(runs.runs[0].stopped_verified,false);
const early=command('reconcile',{id});assert.equal(early.stopped_verified,false);
await new Promise(resolve=>setTimeout(resolve,31000));
const settled=command('reconcile',{id});assert.equal(settled.status,'interrupted',JSON.stringify(settled));assert.equal(settled.stopped_verified,true);assert.equal(settled.outcome_unknown,true);assert.equal(settled.verified_solve,false);
const pruned=command('prune',{id});assert.equal(pruned.private_staging_removed,true);assert.equal(pruned.receipt_retained,true);
fs.writeFileSync(path.join(root,'summary.json'),JSON.stringify({passed:true,root,settled,pruned},null,2));console.log(JSON.stringify({passed:true,root}));
})().catch(e=>{console.error(e);process.exitCode=1;});
