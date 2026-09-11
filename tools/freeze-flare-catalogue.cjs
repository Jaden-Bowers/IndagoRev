// Development orchestration only. Catalogue/extraction/grading logic is native.
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const [exe,seven,corpus]=process.argv.slice(2);if(!exe||!seven||!corpus)throw Error('exe 7z corpus-root required');
const root=path.resolve(__dirname,'..'),report=fs.mkdtempSync(path.join(root,'out','flare-catalogue-'));
const request=path.join(report,'request.json');
fs.writeFileSync(request,JSON.stringify({manifest:path.join(root,'config','flare-on-2014-2024.seed.json'),corpus_root:path.resolve(corpus),archive_tool:path.resolve(seven),wall_ms:240000}));
const r=spawnSync(exe,['--workspace',path.join(report,'state'),'benchmark','freeze','--request',request],{encoding:'utf8',timeout:270000,maxBuffer:16*1024**2});
if(r.error)throw r.error;if(r.status)throw Error(r.stdout+r.stderr);
const catalog=JSON.parse(r.stdout);fs.writeFileSync(path.join(report,'catalogue.json'),JSON.stringify(catalog,null,2));
const counts={};for(const c of catalog.challenges)counts[c.status]=(counts[c.status]||0)+1;
const summary={report,denominator:catalog.denominator,counts,catalogue_sha256:catalog.catalogue_sha256,unavailable:catalog.challenges.filter(c=>c.status!=='available').map(c=>({id:c.id,artifacts:c.artifacts}))};
fs.writeFileSync(path.join(report,'summary.json'),JSON.stringify(summary,null,2));console.log(JSON.stringify(summary));
