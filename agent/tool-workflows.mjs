import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {atomic,hashFile,hash} from './native.mjs';
// Owner credentials stay in controller memory, never model parameters/results.
// The Pi host shell is still host access; this is not an OS security boundary.
export class Workflows {
 constructor(native,config){this.native=native;this.config=config;this.queue=Promise.resolve();this.owners=new Map();}
 call(op,p,signal){return this.native.call(['harness',op],{project:this.config.project,...p},{signal,timeout:150000});}
 execute(entry,input,signal){const task=this.queue.then(()=>this.dispatch(entry,input,signal));this.queue=task.catch(()=>{});return task;}
 async owner(signal){
  const active=this.native.active,key=active.artifact_sha256;
  const ownerKey=hash(JSON.stringify([key,active.id,active.path,this.config.authority,this.config.allowHelpers,this.config.workflowTargets,this.config.executionTargets,this.config.guestProfiles,this.config.runtimeObservationSessions]));
  const file=path.join(this.config.state,'workflow-owners',ownerKey+'.json');
  let owner=this.owners.get(ownerKey);
  if(owner){
   try{await this.call('renew',{id:owner.id,owner_token:owner.token},signal);return owner;}catch(error){if(signal?.aborted)throw error;}
  }
  if(fs.existsSync(file)){
   const saved=JSON.parse(fs.readFileSync(file));
   const current=(await this.call('show',{id:saved.id},signal)).data;
   const claimed=(await this.call('claim',{id:saved.id,expected_revision:current.revision},signal)).data;
   owner={id:claimed.id,token:claimed.owner_token,file};
  }else{
   const request={target_id:active.id,objective:'Pair reversing with bounded evidence-backed tool workflows',required_facts:['Produce evidence relevant to the current investigation'],stop_conditions:['Budget exhausted or operator interruption'],owner:{mode:'external',name:'pi-tool-adapter'},budget:{max_actions:64,wall_ms:3600000,output_bytes:16777216},scope:{target_ids:[...new Set([active.id,...(this.config.workflowTargets??[]),...(this.config.executionTargets??[]).map(t=>t.target_id)])]},workbench_mutations:true,analysis_helpers:this.config.allowHelpers===true,guest_profiles:this.config.guestProfiles??[],runtime_observation_sessions:this.config.runtimeObservationSessions??[]};
   if(this.config.authority==='host'){
    if(hashFile(active.path)!==key)throw Error('Execution target changed');
    request.runtime_execution={trusted_host_execution:true,targets:[{target_id:active.id,file:active.path,artifact_sha256:key},...(this.config.executionTargets??[]).filter(t=>t.target_id!==active.id)],engines:['io','debugger','frida','dynamorio',...(process.platform==='linux'?['rr']:[])]};
   }
   const created=(await this.call('create',request,signal)).data;
   owner={id:created.id,token:created.owner_token,file};atomic(file,{id:owner.id,artifact_sha256:key});
  }
  if(!owner.id||!owner.token)throw Error('Native controller did not return an external owner');
  this.owners.set(ownerKey,owner);return owner;
 }
 async dispatch(entry,input,signal){
  signal?.throwIfAborted();
  if(entry.effect==='execution'&&this.config.authority!=='host')throw Error('Host authority required for original-target experiments');
  if(entry.effect==='helper'&&!this.config.allowHelpers)throw Error('Controlled helper execution requires operator allowHelpers');
  if(entry.effect==='guest'&&!(this.config.guestProfiles??[]).includes(input.profile))throw Error('Guest profile not granted by operator');
  const owner=await this.owner(signal),{family,operation}=entry.route;
  if(family==='workflow'){
   const r=await this.call('actions',{id:owner.id,limit:128},signal),saved=JSON.parse(fs.readFileSync(owner.file));
   const action=r.data.records?.find(a=>a.id===saved.pending?.action_id||a.key===saved.pending?.key);
   if(action&&!action.result?.outcome_unknown&&['completed','failed','cancelled','partial','unsupported'].includes(action.status))atomic(owner.file,{id:owner.id,artifact_sha256:this.native.active.artifact_sha256});
   return {data:{investigation_id:owner.id,pending:JSON.parse(fs.readFileSync(owner.file)).pending??null,...r.data},receipt:r.receipt};
  }
  if(entry.effect==='read')return this.call('read',{id:owner.id,family,operation,request:input},signal);
  const saved=JSON.parse(fs.readFileSync(owner.file));
  if(saved.pending)throw Error(`Workflow ${saved.pending.action_id??saved.pending.key} has an uncertain outcome. Read experiment_reconcile or native action history before another mutation; no automatic replay.`);
  const args={...input};delete args.proposal;
  if(family==='reasoning'){
   const expected_revision=args.expected_revision;delete args.expected_revision;
   const current=(await this.call('show',{id:owner.id},signal)).data;
   return this.call('reason',{id:owner.id,owner_token:owner.token,expected_revision:current.revision,request:{operation,expected_revision,record:args}},signal);
  }
  let arguments_=args;
  if(family==='research')arguments_={body:{kind:({algorithm_candidate:'algorithm_candidate',algorithm_compare:'algorithm_comparison',service_contract:'service_contract',service_observe:'service_observation'})[entry.name],...args}};
  if(family==='guest')arguments_={body:args};
  const current=(await this.call('show',{id:owner.id},signal)).data;
  const key='pi_'+crypto.randomUUID().replaceAll('-','');
  atomic(owner.file,{...saved,pending:{key,status:'proposing'}});
  let action;
  try{action=(await this.call('propose',{id:owner.id,owner_token:owner.token,expected_revision:current.revision,key,proposal:input.proposal??{gap:`Collect ${entry.name} evidence`,expected_evidence:'Pinned native result and bounded observations',prediction:input.prediction??'The operation will produce inspectable evidence, not a solve certification',fallback:'Inspect diagnostics; change the hypothesis or report the limitation'},request:{backend:'workbench',operation:family+'.'+operation,arguments:arguments_}},signal)).data;}
  catch(error){
   // A native validation rejection is definitive; a transport failure is not.
   if(error.nativeStatus==='invalid_request')atomic(owner.file,{id:owner.id,artifact_sha256:this.native.active.artifact_sha256});
   throw error;
  }
  atomic(owner.file,{...saved,pending:{key,action_id:action.id,status:'running'}});
  const onAbort=()=>{this.call('cancel',{id:owner.id,owner_token:owner.token}).catch(()=>{});};
  signal?.addEventListener('abort',onAbort,{once:true});
  try{
   const r=await this.call('run',{id:owner.id,owner_token:owner.token,expected_revision:action.investigation_revision,action_id:action.id},signal);
   if(!r.data.outcome_unknown&&!r.data.result?.outcome_unknown&&!['running','waiting_for_job','proposed'].includes(r.data.status))atomic(owner.file,{id:owner.id,artifact_sha256:this.native.active.artifact_sha256});
   return r;
  }finally{signal?.removeEventListener('abort',onAbort);}
 }
}
