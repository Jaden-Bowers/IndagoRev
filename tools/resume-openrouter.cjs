// Resume a settled saved response/ready checkpoint, never an uncertain request.
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const [binary,directory]=process.argv.slice(2);
if(!binary||!directory)throw Error('Usage: node tools/resume-openrouter.cjs EXE RUN_DIRECTORY');
const exe=path.resolve(binary),report=path.resolve(directory),workspace=path.join(report,'workspace');
const original=JSON.parse(fs.readFileSync(path.join(report,'summary.json'),'utf8'));
const query={project:'development',id:original.investigation};let serial=0;
function request(operation,value,timeout=30000) {
 const file=path.join(report,`resume-request-${++serial}.json`);fs.writeFileSync(file,JSON.stringify(value));
 try {
  const result=spawnSync(exe,['--workspace',workspace,'harness',operation,'--request',file],{encoding:'utf8',timeout,maxBuffer:16*1024*1024,windowsHide:true});
  if(result.error)throw result.error;
  const body=JSON.parse(result.stdout);if(result.status===2)throw Error('Native resume operation failed: '+operation);
  return body;
 } finally {fs.unlinkSync(file);}
}
const state=request('controller',query),inv=request('show',query);
if(!['ready','response_saved'].includes(state.phase))throw Error('Resume requires a ready or response_saved checkpoint; inspect uncertain requests separately');
if(inv.owner.profile.provider!=='openrouter'||inv.owner.profile.model!=='deepseek/deepseek-v4-flash-0731')throw Error('Only the specified OpenRouter model is permitted');
const claimed=request('claim',{...query,expected_revision:inv.revision});
const before=request('actions',query),started=Date.now();
console.log(JSON.stringify({report,phase:state.phase,generations:state.generations,model:inv.owner.profile.model}));
const result=request('explore',{...query,owner_token:claimed.owner_token,expected_revision:claimed.revision,
 allow_inference:true,max_generations:state.max_generations,recipe:state.recipe},state.max_generations*inv.owner.profile.generation_ms+inv.budget.wall_ms+100000);
const after=request('actions',query),controller=request('controller',query),current=request('show',query);
const summary={result,controller,investigation_state:current,elapsed_ms:Date.now()-started,
 resume:{phase:state.phase,previous_generations:state.generations,before_action_ids:before.records.map(a=>a.id),after_action_ids:after.records.map(a=>a.id)},
 assessment:{independently_graded:false,behavior_verified:false}};
const serialized=JSON.stringify(summary,null,2);
fs.writeFileSync(path.join(report,`resume-${Date.now()}.json`),serialized);
fs.writeFileSync(path.join(report,'resume-summary.json'),serialized);
console.log(JSON.stringify({report,status:current.status,controller_status:result.status,retry_after_ms:result.retry_after_ms,elapsed_ms:summary.elapsed_ms}));
