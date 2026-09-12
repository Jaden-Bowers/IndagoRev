// Explicit, operator-invoked live inference. No target execution or answer hints.
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const [executable,target,profilePath='config/openrouter-deepseek.json',generations='48']=process.argv.slice(2);
if(!executable||!target||!Number.isInteger(+generations)||+generations<2||+generations>128)
  throw Error('Usage: node tools/investigate-openrouter.cjs EXE TARGET [PROFILE] [2..128 generations]');
const root=path.resolve(__dirname,'..'),exe=path.resolve(executable),profile=JSON.parse(fs.readFileSync(profilePath,'utf8'));
if(profile.provider!=='openrouter'||profile.model!=='deepseek/deepseek-v4-flash-0731')
  throw Error('This development evaluation permits only deepseek/deepseek-v4-flash-0731 on OpenRouter');
profile.credential_file=path.resolve(profile.credential_file);
const report=fs.mkdtempSync(path.join(root,'out','openrouter-investigation-')),workspace=path.join(report,'workspace');
let serial=0;const started=Date.now();
const nativeWallMs=Math.min(3600000,+generations*60000);
function cli(args,timeout=30000) {
  const result=spawnSync(exe,['--workspace',workspace,...args],{encoding:'utf8',timeout,maxBuffer:16*1024*1024,windowsHide:true});
  if(result.error)throw result.error;
  let value;try{value=JSON.parse(result.stdout);}catch{throw Error('Native command returned no JSON: '+result.stderr.slice(0,500));}
  if(result.status===2)throw Error(JSON.stringify(value));return value;
}
function request(operation,value,timeout) {
  const file=path.join(report,`request-${++serial}.json`);
  fs.writeFileSync(file,JSON.stringify(value));
  try{return cli(['harness',operation,'--request',file],timeout);}finally{fs.unlinkSync(file);}
}
console.log(JSON.stringify({report,model:profile.model,target:path.basename(target)}));
let summary={model:profile.model,target:path.basename(target),target_execution:false,operator_function_hints:false,operator_algorithm_hints:false};
try {
  cli(['project','create','--name','development']);
  const imported=cli(['target','import','--project','development','--file',path.resolve(target)]);
  const investigation=request('create',{project:'development',target_id:imported.id,
    objective:'Determine the challenge answer from the supplied binary. Independently discover the relevant functions and algorithm. Explain how input, transformations, constraints, acceptance and output connect, with native evidence citations and explicit uncertainties. Do not execute the target. Do not assume a remembered challenge answer is correct; derive it from this artifact.',
    required_facts:['challenge answer','input and acceptance algorithm'],
    owner:{mode:'builtin',name:'OpenRouter DeepSeek development investigation',profile},
    budget:{max_actions:64,wall_ms:nativeWallMs,output_bytes:8388608}});
  summary.investigation=investigation.id;
  summary.artifact_sha256=investigation.artifact_sha256;
  fs.writeFileSync(path.join(report,'summary.json'),JSON.stringify(summary,null,2));
  const result=request('explore',{project:'development',id:investigation.id,owner_token:investigation.owner_token,
    expected_revision:investigation.revision,allow_inference:true,max_generations:+generations,recipe:'general'},+generations*profile.generation_ms+nativeWallMs+100000);
  const query={project:'development',id:investigation.id};
  summary={...summary,result,controller:request('controller',query),investigation_state:request('show',query),audit:request('audit',query)};
  summary.assessment={answer:summary.investigation_state.report?.answer,report_status:summary.investigation_state.status,
    independently_graded:false,behavior_verified:false,qualification:'Requires separate operator-side validation; a cited report alone is not a verified solve'};
} catch(error) {summary.error=error.message;process.exitCode=1;}
summary.elapsed_ms=Date.now()-started;
fs.writeFileSync(path.join(report,'summary.json'),JSON.stringify(summary,null,2));
console.log(JSON.stringify({report,elapsed_ms:summary.elapsed_ms,status:summary.investigation_state?.status,controller_status:summary.result?.status,retry_after_ms:summary.result?.retry_after_ms,error:summary.error}));
