// Opt-in scripted cross-backend check. Never executes the imported target.
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const [exe,fixture]=process.argv.slice(2);if(!exe||!fixture)throw Error('exe and source-backed runtime fixture required');
const root=path.resolve(__dirname,'..'),space=fs.statfsSync(root);
if(space.bavail*space.bsize<20*1024**3+512*1024**2)throw Error('Storage floor');
const report=fs.mkdtempSync(path.join(root,'out','static-behavior-')),workspace=path.join(report,'workspace');
const start=Date.now();let inv,serial=0;
function run(args){
  if(Date.now()-start>480000)throw Error('Aggregate test deadline');
  const r=spawnSync(exe,['--workspace',workspace,...args],{encoding:'utf8',timeout:90000,maxBuffer:2097152});
  fs.writeFileSync(path.join(report,`${++serial}.json`),JSON.stringify({args,status:r.status,stdout:r.stdout?.replace(/"owner_token":\s*"[^"]*"/g,'"owner_token":"[redacted]"'),stderr:r.stderr},null,2));
  if(r.error)throw r.error;if(![0,1,2,3].includes(r.status))throw Error(`CLI failure ${r.status}`);
  return JSON.parse(r.stdout);
}
function owned(op,request){
  const current=run(['harness','show','--project','behavior','--id',inv.id]);
  const file=path.join(report,'request.json');fs.writeFileSync(file,JSON.stringify({project:'behavior',id:inv.id,owner_token:inv.owner_token,expected_revision:current.revision,...request}));
  try{return run(['harness',op,'--request',file]);}finally{fs.writeFileSync(file,'{}');}
}
const analyses=[];
function read(result,pointer){
  const file=path.join(report,'read.json');fs.writeFileSync(file,JSON.stringify({project:'behavior',id:inv.id,family:'evidence',operation:'read',request:{id:result.evidence_ids[0],pointer,limit:16,max_bytes:2048}}));
  const page=run(['harness','read','--request',file]);if(!page.source_verified)throw Error('Unverified evidence page');return page;
}
function analyze(backend,operation,address='',args={}){
  const a=owned('propose',{key:`step_${analyses.length}`,proposal:{gap:'selected fixture function behavior',prediction:'bounded native function view',expected_evidence:`${backend}/${operation}`,fallback:'preserve failure; report the unsupported view'},
    request:{backend,operation,address,arguments:args,budget:{wall_ms:backend==='ghidra'&&operation==='functions'?60000:20000,output_bytes:131072,memory_bytes:2147483648,max_items:256}}});
  const outcome=owned('run',{action_id:a.id});
  const result=outcome.result;analyses.push({backend,operation,status:result?.status,evidence_ids:result?.evidence_ids});
  if(!result?.evidence_ids?.length||!['completed','partial'].includes(result.status))throw Error(`Native ${backend}/${operation} failed: ${JSON.stringify(outcome).slice(0,1000)}`);
  return result;
}
let summary;
try{
  run(['project','create','--name','behavior']);run(['target','import','--project','behavior','--file',path.resolve(fixture)]);
  const file=path.join(report,'create.json');fs.writeFileSync(file,JSON.stringify({project:'behavior',objective:'Cross-backend static views of a source-backed function, not a verified behavioral solve',required_facts:['native function views'],owner:{mode:'external',name:'scripted development check',model_declaration:'no inference'},budget:{max_actions:8,wall_ms:180000,output_bytes:1048576}}));
  inv=run(['harness','create','--request',file]);
  const inventory=analyze('xair','inventory');
  const functions=analyze('ghidra','functions','',{search:'runtime_probe'});
  const function_page=read(functions,'/functions/0');
  const address=function_page.items?.find(f=>f.key==='entry')?.value;
  if(!/^0x[0-9a-f]+$/i.test(address||''))throw Error('Missing returned function address');
  const decompile=analyze('ghidra','decompile',address);
  const cfg=analyze('xair','cfg',address);
  const flow=analyze('xair','semantic',address);
  analyze('ghidra','calls',address);analyze('ghidra','xrefs',address);
  const pseudocode=read(decompile,'/decompilation/decompiled_c'),blocks=read(cfg,'/blocks');
  if(!pseudocode.text||!blocks.total_items)throw Error('Missing pseudocode or native CFG');
  const address_page=read(functions,'/functions/0/entry');
  const answer=owned('finish',{status:'partial',answer:'Separate Ghidra pseudocode and XAIR function views were produced. This scripted test does not assert semantic equivalence or a verified solve.',claims:[{fact:'native function views',text:'The selected function has native decompilation, CFG and SSA evidence.',evidence_ids:[...functions.evidence_ids,...decompile.evidence_ids,...cfg.evidence_ids,...flow.evidence_ids],limitations:['backend meanings remain separate','scripted operations, not autonomous reasoning'],checks:[{operation:'equal',operands:[{evidence_id:functions.evidence_ids[0],pointer:'/functions/0/entry',raw_sha256:address_page.raw_sha256}],expected:address}]}],gaps:['General behavioral entailment not validated']});
  summary={status:'passed',report,analyses,address,claim_checks:answer.report.claims[0].check_result,verified_solve:false,elapsed_ms:Date.now()-start};
}catch(e){process.exitCode=1;summary={status:'failed',report,error:e.message,analyses,elapsed_ms:Date.now()-start};}
fs.writeFileSync(path.join(report,'summary.json'),JSON.stringify(summary,null,2));console.log(JSON.stringify(summary));
