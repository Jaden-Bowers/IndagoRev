// Produces a catalogue filename-derived LOWER BOUND, never a solve/coverage claim.
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process'),assert=require('node:assert/strict');
const [exe,destination='out/capability-matrix.json',assessmentFile]=process.argv.slice(2),linux=exe.startsWith('wsl:');
const native=p=>linux?p.replace(/^([A-Za-z]):/,(_,d)=>'/mnt/'+d.toLowerCase()).replaceAll('\\','/'):p;
const root=fs.mkdtempSync(path.resolve('out/matrix-build-'));let n=0;
function call(args,r){const file=path.join(root,`r${++n}.json`);fs.writeFileSync(file,JSON.stringify(r));const result=spawnSync(linux?'wsl.exe':exe,linux?['--exec',exe.slice(4),'--workspace',native(path.join(root,'state')),...args,'--request',native(file)]:['--workspace',path.join(root,'state'),...args,'--request',file],{encoding:'utf8',timeout:30000,maxBuffer:8388608});assert.equal(result.status,0,result.stdout+result.stderr);return JSON.parse(result.stdout);}
const catalogue=native(path.resolve('config/flare-on-2014-2024.catalogue.json'));const coverage=call(['benchmark','coverage'],{catalogue}),requirements={};
for(const row of coverage.artifacts){const kind=row.assessment.kind;requirements[row.challenge]??=new Set();requirements[row.challenge].add(kind);}
const capabilities={};for(const values of Object.values(requirements))for(const kind of values)capabilities[kind]={status:'unknown'};
if(assessmentFile){const assessments=JSON.parse(fs.readFileSync(assessmentFile));for(const [kind,assessment] of Object.entries(assessments)){assert(Object.hasOwn(capabilities,kind),'assessment has no catalogue family: '+kind);capabilities[kind]=assessment;}}
// Do not automatically promote a filename's tool route into a tested capability.
const matrix=call(['evaluation','matrix'],{catalogue,basis:'filename_lower_bound',requirements:Object.fromEntries(Object.entries(requirements).map(([k,v])=>[k,[...v].sort()])),capabilities});
fs.mkdirSync(path.dirname(path.resolve(destination)),{recursive:true});fs.writeFileSync(destination,JSON.stringify(matrix,null,2));console.log(JSON.stringify({destination:path.resolve(destination),denominator:matrix.denominator,rows:matrix.rows.length,requirements_complete:false}));
