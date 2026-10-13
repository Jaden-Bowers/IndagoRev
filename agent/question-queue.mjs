import fs from 'node:fs';
import path from 'node:path';
import {atomic,hash,hashFile} from './native.mjs';

const bounded=(s,n,label)=>{if(typeof s!=='string'||!s.trim()||s.length>n)throw Error(`Invalid ${label}`);return s;};
export class QuestionQueue {
 constructor(directory){this.directory=path.resolve(directory);this.file=path.join(this.directory,'questions.json');}
 read(){return JSON.parse(fs.readFileSync(this.file,'utf8'));}
 save(data){data.revision++;atomic(this.file,data);return data;}
 initialize(brief,artifact){
  bounded(brief,65536,'brief');
  if(fs.existsSync(this.file)){const d=this.read();if(d.brief_hash!==hash(brief)||d.artifact!==artifact)throw Error('Investigation brief or artifact changed; use a new investigation');return d;}
  const data={schema:'indago.question-queue.v1',artifact,brief,brief_hash:hash(brief),revision:0,questions:[{id:'q1',question:brief.slice(0,4000),parent:null,dependencies:[],status:'pending',attempts:0,summary:'',evidence:[],failed_approaches:[],next_action:'Decompose the original brief into bounded questions if needed.'}]};
  atomic(this.file,data);return data;
 }
 add(items,parent){
  const d=this.read();const p=d.questions.find(q=>q.id===parent);
  if(!p||!['active','pending','partial'].includes(p.status))throw Error('Parent must be an open question');
  if(!Array.isArray(items)||!items.length||items.length>12||d.questions.length+items.length>128)throw Error('Question capacity exceeded');
  const normalized=new Set(d.questions.map(q=>q.question.trim().toLowerCase()));
  for(const item of items){
   bounded(item.question,4000,'question');
   if(normalized.has(item.question.trim().toLowerCase()))throw Error('Duplicate question');
   const deps=item.dependencies??[];
   if(!Array.isArray(deps)||deps.length>16||deps.some(id=>id===parent||!d.questions.some(q=>q.id===id)))throw Error('Dependencies must name earlier questions other than the parent');
   normalized.add(item.question.trim().toLowerCase());
   d.questions.push({id:`q${d.questions.length+1}`,parent,question:item.question,dependencies:[...new Set(deps)],status:'pending',attempts:0,summary:'',evidence:[],failed_approaches:[],next_action:''});
  }
  p.status='decomposed';return this.save(d);
 }
 checkpoint(id,{status,summary,evidence=[],failed_approaches=[],next_action=''}){
  const d=this.read(),q=d.questions.find(q=>q.id===id);
  if(!q||q.status!=='active')throw Error('Only the active question can be checkpointed');
  if(!['partial','answered','blocked'].includes(status))throw Error('Invalid checkpoint status');
  bounded(summary,6000,'summary');
  if(!Array.isArray(evidence)||evidence.length>12||!Array.isArray(failed_approaches)||failed_approaches.length>12||typeof next_action!=='string'||next_action.length>2000)throw Error('Checkpoint bounds exceeded');
  const receipts=evidence.map(ref=>{
   bounded(ref,2048,'evidence path');const file=fs.realpathSync(path.resolve(this.directory,ref));
   const root=fs.realpathSync(this.directory),relative=path.relative(root,file);
   if(relative.startsWith('..')||path.isAbsolute(relative)||!fs.statSync(file).isFile()||fs.statSync(file).size>32*1024*1024)throw Error('Evidence must be a bounded file within this investigation');
   // A source receipt is required; the queue and model-authored reports are not proof.
   if(!relative.split(path.sep).some(p=>['receipts','tool-results'].includes(p)))throw Error('Use a native receipt or tool-result file');
   return {path:relative,sha256:hashFile(file)};
  });
  if(status==='answered'&&!receipts.length)throw Error('Answered requires source evidence; it is still a model assessment, not independent verification');
  failed_approaches.forEach(s=>bounded(s,1000,'failed approach'));
  Object.assign(q,{status,summary,evidence:receipts,failed_approaches,next_action,independently_verified:false});return this.save(d);
 }
 validateEvidence(){
  const d=this.read();
  let changed=false;
  for(const q of d.questions)if(q.status==='answered'&&q.evidence.some(e=>{try{return hashFile(path.join(this.directory,e.path))!==e.sha256;}catch{return true;}})){
   q.status='blocked';q.next_action='Cited evidence changed or disappeared; operator review required.';changed=true;
  }
  return changed?this.save(d):d;
 }
 next(maxAttempts=3){
  const d=this.validateEvidence();
  for(const q of d.questions)if(q.status==='active'){q.status='partial';q.next_action='Previous batch interrupted; inspect saved receipts before continuing.';}
  for(const q of d.questions)if(['pending','partial'].includes(q.status)&&q.attempts>=maxAttempts)q.status='blocked';
  const q=d.questions.find(q=>['pending','partial'].includes(q.status)&&q.dependencies.every(id=>d.questions.find(p=>p.id===id)?.status==='answered'));
  if(q){q.status='active';q.attempts++;}this.save(d);return q;
 }
 view(limit=8,offset=0){const d=this.read();return {artifact:d.artifact,revision:d.revision,questions:d.questions.slice(offset,offset+limit),total:d.questions.length,next_offset:offset+limit<d.questions.length?offset+limit:null};}
}
