// Bounded operator-side diagnostic; generated material only, no challenge solutions.
const fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto'),{spawnSync}=require('node:child_process');
const [exe,seven]=process.argv.slice(2);if(!exe||!seven)throw Error('exe and 7z executable required');
const root=fs.mkdtempSync(path.resolve('out/benchmark-contract-')),corpus=path.join(root,'corpus'),evaluator=path.join(root,'evaluator');
fs.mkdirSync(corpus);fs.mkdirSync(evaluator);
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
function save(name,value){const file=path.join(root,name);fs.writeFileSync(file,JSON.stringify(value));return file;}
let number=0;
function cli(op,request,fail=false){
 const file=save('request.json',request),r=spawnSync(exe,['--workspace',path.join(root,'state'),'benchmark',op,'--request',file],{encoding:'utf8',timeout:60000,maxBuffer:8*1024**2});
 if(r.error)throw r.error;const out=JSON.parse(r.stdout);fs.writeFileSync(path.join(root,`${++number}-${op}.json`),JSON.stringify(out,null,2));
 if(fail){if(r.status===0)throw Error('Expected rejection');}else if(r.status!==0)throw Error(JSON.stringify(out));return out;
}
function app(args,request,fail=false){
 const file=request?save('app-request.json',request):null,argv=['--workspace',path.join(root,'state'),...args];if(file)argv.push('--request',file);
 const r=spawnSync(exe,argv,{encoding:'utf8',timeout:60000,maxBuffer:8*1024**2});if(r.error)throw r.error;
 const out=JSON.parse(r.stdout);fs.writeFileSync(path.join(root,`${++number}-app-${args[0]}-${args[1]}.json`),JSON.stringify(out,null,2));
 if(fail){if(r.status===0)throw Error('Expected rejection');}else if(r.status!==0)throw Error(JSON.stringify(out));return out;
}
function check(ok,message){if(!ok)throw Error(message);}
const material=path.join(root,'fixture.txt');fs.writeFileSync(material,'generated public diagnostic material\n');
const zip=path.join(corpus,'fixture.zip');const packed=spawnSync(seven,['a','-tzip',zip,material],{encoding:'utf8',timeout:10000});if(packed.status)throw Error(packed.stderr);
const seed=save('seed.json',{schema:'indago.benchmark-seed.v1',challenges:[{id:'synthetic-present',year:2014,inputs:[{path:'fixture.zip',password:''}]},{id:'synthetic-missing',year:2014,inputs:[{path:'missing.zip',password:''}]}]});
const catalog=cli('freeze',{manifest:seed,corpus_root:corpus,archive_tool:seven,wall_ms:10000});
check(catalog.denominator===2&&catalog.challenges[1].status==='unavailable','Missing target disappeared');
const catalogue=save('catalogue.json',catalog),analysis=path.join(root,'analysis');
cli('prepare',{catalogue,corpus_root:corpus,archive_tool:seven,challenge:'synthetic-present',destination:analysis,max_bytes:1},true);
const prepared=cli('prepare',{catalogue,corpus_root:corpus,archive_tool:seven,challenge:'synthetic-present',destination:analysis});
check(prepared.status==='completed'&&prepared.artifacts.length===1,'Preparation failed');
cli('prepare',{catalogue,corpus_root:corpus,archive_tool:seven,challenge:'synthetic-present',destination:analysis},true);
const answer=crypto.randomBytes(20).toString('hex');
app(['project','create','--name','proof-gate']);
const target=app(['target','import','--project','proof-gate','--file',path.join(analysis,prepared.artifacts[0].path)]);
const fact='synthetic challenge answer';
fs.writeFileSync(path.join(evaluator,'oracle.json'),JSON.stringify({kind:'exact_utf8_sha256',authority:'independent_operator',challenge:'synthetic-present',catalogue_sha256:catalog.catalogue_sha256,answer_sha256:sha(answer),requirement_kind:'challenge_answer',fact,artifact_sha256:target.artifact_sha256}));
const solver='// Synthetic artifact retention test, not a demonstrated solver.\n';fs.writeFileSync(path.join(analysis,'solver.cpp'),solver);
const inv=app(['harness','create'],{project:'proof-gate',target_id:target.id,objective:'Grade one exact synthetic answer',required_facts:[fact],proof_requirements:['independently_graded_challenge_solve'],owner:{mode:'external',name:'benchmark-contract'},budget:{max_actions:1,wall_ms:1000,output_bytes:65536}});
const submission={challenge:'synthetic-present',catalogue_sha256:catalog.catalogue_sha256,answer,attempt:1,solver_path:'solver.cpp',solver_sha256:sha(solver),run:{model:'synthetic-no-inference',profile_sha256:sha('fixture'),budget:{wall_ms:1000},usage:{wall_ms:1}}};
const request={catalogue,evaluator_root:evaluator,analysis_root:analysis,submission:'submission.json',verifier:'oracle.json'};
function submit(value){fs.writeFileSync(path.join(analysis,'submission.json'),JSON.stringify(value));}
submit({...submission,answer:'wrong'});check(cli('grade',request).status==='failed','Wrong answer passed');
submit(submission);check(cli('grade',request).verified_solve,'Correct answer rejected');
const certified=app(['benchmark','certify'],{...request,project:'proof-gate',id:inv.id,owner_token:inv.owner_token,expected_revision:inv.revision,fact_index:0});
const proof=certified.verifications.at(-1),claims=[{fact,text:'The submitted answer passed the independent question- and artifact-bound challenge grader.',proof_id:proof.id,proof_sha256:proof.record_sha256,proof_kind:proof.kind,limitations:proof.limitations}];
const finished=app(['harness','finish'],{project:'proof-gate',id:inv.id,owner_token:inv.owner_token,expected_revision:certified.revision,status:'answered',answer,claims,gaps:[]});
check(finished.status==='answered'&&finished.report.independently_graded===true&&finished.report.proof_kinds[0]==='independently_graded_challenge_solve','Independent grade did not pass the question-bound solve gate');
const score=cli('score',{catalogue,evaluator_root:evaluator,attempts:[request]});
check(score.denominator===2&&score.passed===1&&!score.all_solved,'Denominator or score wrong');
check(cli('score',{catalogue,evaluator_root:evaluator,attempts:[]}).passed===0,'Empty attempts reported a pass');
submit({...submission,outcome:'timeout'});check(cli('grade',request).failure_category==='timeout','Timeout failure category lost');submit(submission);
cli('score',{catalogue,evaluator_root:evaluator,attempts:[request,request]},true);
cli('grade',{...request,evaluator_root:analysis},true);
cli('grade',{...request,submission:'../seed.json'},true);
fs.appendFileSync(path.join(analysis,'solver.cpp'),'changed');cli('grade',request,true);
fs.writeFileSync(path.join(analysis,'solver.cpp'),solver);
fs.appendFileSync(path.join(analysis,prepared.artifacts[0].path),'changed');cli('grade',request,true);
const bad=JSON.parse(JSON.stringify(catalog));bad.denominator=1;const altered=save('altered.json',bad);cli('score',{catalogue:altered,evaluator_root:evaluator,attempts:[]},true);
const future=save('future.json',{challenges:[{id:'holdout',year:2025,inputs:[]}]});cli('freeze',{manifest:future,corpus_root:corpus,archive_tool:seven},true);
const traversal=save('traversal.json',{challenges:[{id:'traversal',year:2014,inputs:[{path:'../fixture.txt',password:''}]}]});cli('freeze',{manifest:traversal,corpus_root:corpus,archive_tool:seven},true);
// Minimal stored ZIP generation lets us exercise unsafe member names without
// asking an archiver to create filesystem traversal paths.
function zipEntry(name){
 const filename=Buffer.from(name),body=Buffer.from('diagnostic');let crc=0xffffffff;
 for(const b of body){crc^=b;for(let n=0;n<8;n++)crc=(crc>>>1)^((crc&1)?0xedb88320:0);}crc=(crc^0xffffffff)>>>0;
 const local=Buffer.alloc(30);local.writeUInt32LE(0x04034b50);local.writeUInt16LE(20,4);local.writeUInt32LE(crc,14);local.writeUInt32LE(body.length,18);local.writeUInt32LE(body.length,22);local.writeUInt16LE(filename.length,26);
 const central=Buffer.alloc(46);central.writeUInt32LE(0x02014b50);central.writeUInt16LE(20,4);central.writeUInt16LE(20,6);central.writeUInt32LE(crc,16);central.writeUInt32LE(body.length,20);central.writeUInt32LE(body.length,24);central.writeUInt16LE(filename.length,28);
 const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(central.length+filename.length,12);end.writeUInt32LE(local.length+filename.length+body.length,16);
 return Buffer.concat([local,filename,body,central,filename,end]);
}
for(const [n,member] of ['../escape.bin','solutions/answer.txt','NUL.txt'].entries()) {
 fs.writeFileSync(path.join(corpus,`unsafe${n}.zip`),zipEntry(member));
 const unsafe=save(`unsafe${n}.json`,{challenges:[{id:'unsafe',year:2014,inputs:[{path:`unsafe${n}.zip`,password:''}]}]});
 check(cli('freeze',{manifest:unsafe,corpus_root:corpus,archive_tool:seven}).challenges[0].status==='unsupported','Unsafe archive member accepted');
}
const report={status:'passed',checks:number,root,scope:'Generated contract checks, not FLARE-On qualification; no target execution'};
fs.writeFileSync(path.join(root,'summary.json'),JSON.stringify(report,null,2));console.log(JSON.stringify(report));
