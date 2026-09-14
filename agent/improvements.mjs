import fs from 'node:fs';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {runProcess, hashFile, atomic, stopTree} from './native.mjs';

export const features = ['environment','surface','state','progress','final','recipes'];
export function enabled(config, feature) {
  return (config.features ?? (config.mode==='plain'?[]:features)).includes(feature);
}
export function finalText(text) {
  return !!text?.trim() && !/<\/?(?:tool_call|function|parameter)\b|<function=|<parameter=/i.test(text);
}
export async function resolveEnvironment(config) {
  const dirs = (process.env.PATH ?? '').split(path.delimiter);
  const java = process.env.JAVA_HOME;
  if (java) dirs.unshift(path.join(java,'bin'));
  if (process.platform === 'win32') {
    const base = path.join(process.env.ProgramFiles ?? 'C:/Program Files','Java');
    if (fs.existsSync(base)) for(const d of fs.readdirSync(base)) dirs.push(path.join(base,d,'bin'));
    dirs.push(path.join(process.env.ProgramFiles ?? 'C:/Program Files','7-Zip'));
  }
  const result = {};
  for (const [name, names, args] of [
    ['javap',['javap'],['-version']], ['archive',['7z','7zz'],['i']],
    ['python',['python3','python'],['--version']],
  ]) {
    for(const dir of [...new Set(dirs)]) {
      for(const base of names) {
        const file = path.join(dir,base + (process.platform==='win32'?'.exe':''));
        if(!fs.existsSync(file)) continue;
        try {
          const r = await runProcess(file,args,{timeout:5000,maxBytes:32768});
          if(r.code===0 && !r.failure) {result[name]={path:file,version:(r.stdout+' '+r.stderr).trim().slice(0,400),sha256:hashFile(file)};break;}
        } catch {}
      }
      if(result[name]) break;
    }
    result[name] ??= {unavailable:true};
  }
  result.native={path:config.exe,sha256:hashFile(config.exe)};
  result.strings={path:path.join(import.meta.dirname,'helper.mjs'),runtime:process.execPath};
  atomic(path.join(config.state,'environment.json'),result);
  return result;
}
export function environmentPrompt(env) {
  const paths=Object.fromEntries(Object.entries(env).map(([k,v])=>[k,v.unavailable?'unavailable':{path:v.path,...(v.runtime?{runtime:v.runtime}:{})}]));
  return 'Resolved analysis tools (use these exact paths, do not search the host):\n'+JSON.stringify(paths)+'\nStrings: run node helper.mjs strings FILE using the resolved runtime and helper paths. Tools marked unavailable must not be searched for repeatedly.'+
    (process.platform==='win32'?'\nPath contract: these are Windows executables, even when invoked from Git Bash. Write and run generated helpers using case-relative paths, such as helper.py and payload.bin. Do not use /tmp: Git Bash rewrites command-line paths differently from Windows Python/Node string-literal paths. Use an explicit Linux/WSL runtime for Linux paths; do not mix the two path systems.':'');
}
export class Investigation {
  constructor(file,artifact) { this.file=file;this.data=fs.existsSync(file)?JSON.parse(fs.readFileSync(file)):{artifact,facts:[],candidate:null,obligation:'Identify the input/output condition and establish the answer from evidence.',failed:[]}; }
  update(p) {
    if(p.artifact && p.artifact!==this.data.artifact) this.data={artifact:p.artifact,facts:[],candidate:null,obligation:'Analyze the new artifact.',failed:[]};
    if(p.facts) this.data.facts=p.facts.slice(0,5).map(x=>String(x).slice(0,300));
    if(p.candidate!==undefined) this.data.candidate=p.candidate===null?null:String(p.candidate).slice(0,300);
    if(p.obligation) this.data.obligation=String(p.obligation).slice(0,500);
    if(p.failure) this.data.failed=[...new Set([...this.data.failed,String(p.failure).slice(0,240)])].slice(-3);
    atomic(this.file,this.data);
  }
  packet() { return 'Investigation state (model assertions are not independently verified):\n'+JSON.stringify(this.data); }
}
export class Progress {
  constructor(){this.calls=new Map();this.outputs=new Map();this.revision=0;}
  key(name,input){const {timeout,...rest}=input??{};return JSON.stringify([name,rest,this.revision]);}
  blocked(name,input){return (this.calls.get(this.key(name,input))??0)>=2;}
  observe(name,input,text){
    if(['write','edit','program_open'].includes(name)){this.revision++;return false;}
    const k=this.key(name,input);this.calls.set(k,(this.calls.get(k)??0)+1);
    const out=JSON.stringify([name,text,this.revision]);this.outputs.set(out,(this.outputs.get(out)??0)+1);
    return this.outputs.get(out)>=2;
  }
}
export async function extractMember(archive,file,member,output,signal) {
  if(!member || /[\r\n*?]/.test(member))throw Error('An exact member name is required');
  if(fs.existsSync(output))throw Error('Choose a new output file');
  const chunks=[];let size=0;
  await new Promise((resolve,reject)=>{
    const child=spawn(archive,['e','-so','-spd',file,member],{windowsHide:true,detached:process.platform!=='win32',stdio:['ignore','pipe','pipe']});
    let error=null;
    const stop=()=>{error=Error('Extraction cancelled or exceeded 30 seconds');stopTree(child);};
    const timer=setTimeout(stop,30000);signal?.addEventListener('abort',stop,{once:true});
    child.stdout.on('data',b=>{size+=b.length;if(size>32*1024*1024){error=Error('32 MiB extraction limit');stopTree(child);}else chunks.push(b);});
    child.stderr.resume();
    child.on('error',e=>{clearTimeout(timer);signal?.removeEventListener('abort',stop);reject(e);});
    child.on('close',code=>{clearTimeout(timer);signal?.removeEventListener('abort',stop);error||code!==0?reject(error??Error('Archive extraction failed: '+code)):resolve();});
    if(signal?.aborted)stop();
  });
  fs.mkdirSync(path.dirname(output),{recursive:true});fs.writeFileSync(output,Buffer.concat(chunks),{flag:'wx'});
  return {path:output,bytes:size,sha256:hashFile(output),parent_sha256:hashFile(file),member};
}
