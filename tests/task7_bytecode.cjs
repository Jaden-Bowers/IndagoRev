const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{spawnSync}=require('node:child_process');
const [exe,fixture]=process.argv.slice(2),root=fs.mkdtempSync(path.resolve('out/task7-bytecode-'));let n=0;
function call(args,r){const f=path.join(root,`r${++n}.json`);if(r)fs.writeFileSync(f,JSON.stringify(r));const p=spawnSync(exe,['--workspace',path.join(root,'state'),...args,...(r?['--request',f]:[])],{encoding:'utf8',timeout:90000,maxBuffer:1048576});assert.ifError(p.error);const result=JSON.parse(p.stdout);fs.writeFileSync(path.join(root,`o${n}.json`),JSON.stringify(result,null,2));assert([0,3].includes(p.status),p.stdout+p.stderr);return result;}
call(['project','create','--name','bytecode']);const t=call(['target','import','--project','bytecode','--file',path.resolve(fixture)]);
const base={project:'bytecode',target_id:t.id,backend:'ghidra',budget:{wall_ms:60000,output_bytes:131072,max_items:128,memory_bytes:2147483648}};
const functions=call(['action','run'],{...base,operation:'functions',arguments:{search:'compare'}});assert(JSON.stringify(functions).includes('compare'));
const decompiled=call(['action','run'],{...base,operation:'decompile',address:functions.data.functions[0].entry});assert.equal(decompiled.status,'completed');assert.equal(decompiled.data.program.language,functions.data.program.language);assert(decompiled.evidence_ids.length>0);
console.log(JSON.stringify({passed:true,root,fixture}));
