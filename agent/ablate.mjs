import fs from 'node:fs';
import path from 'node:path';
import {launch} from './cli.mjs';
import {summarize,frontendIdentity} from './benchmark.mjs';
import {features} from './improvements.mjs';
import {atomic,hashFile} from './native.mjs';

// Fresh, independent single-feature arms; same inputs, budget, prompt and provider.
const [source,output]=process.argv.slice(2);
if(!source||!output)throw Error('Usage: node agent/ablate.mjs PREPARED NEW_OUTPUT');
if(fs.existsSync(output))throw Error('Output must be fresh');
const original=JSON.parse(fs.readFileSync(source));
const base=original.trials.filter(t=>t.mode==='knowledge');
if(base.some(t=>t.provider!=='lmstudio'))throw Error('Qwen/local only');
fs.mkdirSync(output,{recursive:true});
const identity=frontendIdentity();
const plan=[];
for(const arm of ['baseline',...features,'combined'])for(const t of base){
  const cwd=path.resolve(output,arm,t.id,'files');fs.mkdirSync(cwd,{recursive:true});
  for(const a of t.input_hashes){
    const src=path.resolve(t.cwd,a.member),dest=path.resolve(cwd,a.member);
    if(!dest.startsWith(cwd+path.sep)||hashFile(src)!==a.sha256)throw Error('Input mismatch');
    fs.mkdirSync(path.dirname(dest),{recursive:true});fs.copyFileSync(src,dest);
  }
  plan.push({...t,cwd,state:path.resolve(output,arm,t.id,'state'),features:arm==='baseline'?[]:arm==='combined'?features:[arm],arm});
}
atomic(path.join(output,'prepared.json'),{frontend_sha256:identity,trials:plan});
const rows=[];
for(const t of plan){
  if(identity!==frontendIdentity())throw Error('Frontend changed during ablation');
  const run=await launch(t);
  run.generation_limit=fs.existsSync(path.join(t.state,'budget-stop.json'));
  const events=fs.readFileSync(path.join(t.state,'events.jsonl'),'utf8').split('\n').flatMap(l=>{try{return [JSON.parse(l)]}catch{return []}});
  const row={arm:t.arm,challenge:t.id,...summarize(events,run)};
  rows.push(row);atomic(path.join(output,'metrics.json'),{frontend_sha256:identity,rows});console.log(JSON.stringify(row));
}
