// Opt-in real-corpus extraction check. Does not execute any extracted material.
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const [exe,seven,corpus]=process.argv.slice(2),root=path.resolve(__dirname,'..');
const report=fs.mkdtempSync(path.join(root,'out','benchmark-prepare-'));
const catalogue=path.join(root,'config','flare-on-2014-2024.catalogue.json'),rows=[];
for(const challenge of ['flare-2014-03','flare-2022-10']) {
 const request=path.join(report,'request.json');fs.writeFileSync(request,JSON.stringify({catalogue,corpus_root:path.resolve(corpus),archive_tool:seven,challenge,destination:path.join(report,challenge),wall_ms:60000}));
 const r=spawnSync(exe,['--workspace',path.join(report,'state'),'benchmark','prepare','--request',request],{encoding:'utf8',timeout:70000,maxBuffer:4*1024**2});
 if(r.error)throw r.error;const value=JSON.parse(r.stdout);if(r.status||value.status!=='completed')throw Error(JSON.stringify(value));
 rows.push({challenge,artifacts:value.artifacts,status:value.status});
}
const result={status:'passed',report,rows,target_execution:false};fs.writeFileSync(path.join(report,'summary.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result));
