// Select the latest declared attempt for each frozen subset member.
const fs=require('node:fs'),assert=require('node:assert/strict');
const [manifestPath,output,...summaries]=process.argv.slice(2);
if(!manifestPath||!output||!summaries.length)throw Error('Usage: MANIFEST OUTPUT SUMMARY...');
const manifest=JSON.parse(fs.readFileSync(manifestPath,'utf8')),byId=new Map();
for(const file of summaries){const s=JSON.parse(fs.readFileSync(file,'utf8'));
 assert.equal(s.catalogue_sha256,manifest.catalogue_sha256,'catalogue identity');
 for(const r of s.rows){if(!manifest.challenges.some(c=>c.id===r.challenge))throw Error('Row outside declared subset');
  const old=byId.get(r.challenge);if(!old||r.attempt>old.attempt)byId.set(r.challenge,r);}}
const rows=manifest.challenges.map(c=>{const r=byId.get(c.id);if(!r)throw Error('Missing subset row: '+c.id);return r;});
const result={schema:'indago.development-subset-combined.v1',catalogue_sha256:manifest.catalogue_sha256,
 selection:manifest.selection,attempted:rows.length,reported_answers:rows.filter(r=>r.reported_answer).length,
 independently_verified_solves:0,grading:'No independent answer oracle configured; no solve-rate claim.',rows};
const text=JSON.stringify(result,null,2)+'\n';assert(!/[A-Z]:[\\/]Users[\\/]|\/home\/[^/]+\/|\/Users\/[^/]+\/|lease_|[A-Za-z0-9._%+-]+@flare-on\.(?:com|net)/i.test(text));
fs.writeFileSync(output,text);console.log(JSON.stringify({attempted:rows.length,reported_answers:result.reported_answers}));
