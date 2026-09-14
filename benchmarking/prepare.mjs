import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const [exeArg,outputArg]=process.argv.slice(2);
if(!exeArg||!outputArg)throw Error('Usage: node benchmarking/prepare.mjs NATIVE_EXE NEW_OUTPUT_DIRECTORY');
const root=path.dirname(fileURLToPath(import.meta.url));
const m=JSON.parse(fs.readFileSync(path.join(root,'manifest.json')));
const exe=path.resolve(exeArg),output=path.resolve(outputArg);
if(!fs.statSync(exe).isFile()||fs.existsSync(output))throw Error('Native executable required; output must be fresh');
const trials=[];
for(const c of m.challenges){
 const cwd=path.join(root,'challenges',c.id);
 for(const h of c.inputs){
  const file=path.resolve(cwd,h.member);
  if(!file.startsWith(cwd+path.sep)||crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex')!==h.sha256)throw Error('Input hash mismatch');
 }
 trials.push({id:c.id,mode:'knowledge',exe,cwd,target:c.target,inputs:c.inputs.map(h=>h.member),input_hashes:c.inputs.map(({member,sha256})=>({member,sha256})),authority:'analysis',model:m.model,provider:'lmstudio',endpoint:'http://127.0.0.1:1234/v1',prompt:m.prompt,timeout:m.timeout,maxGenerations:m.maxGenerations});
}
fs.mkdirSync(output,{recursive:true});
fs.writeFileSync(path.join(output,'prepared.json'),JSON.stringify({schema:'indago.pi-benchmark.v1',sampling:m.sampling,trials},null,2));
console.log(path.join(output,'prepared.json'));
