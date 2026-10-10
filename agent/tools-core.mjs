import {object,string,integer} from './tool-registry.mjs';
export function addCore(registry){
 const id=string('Previously returned native identity',128),paging={offset:integer(0,1000000),limit:integer(1,128)};
 for(const [name,family,operation,fields,required,effect] of [
  ['function_views','function','show',{id,...paging},['id'],'read'],
  ['function_inventory','functions','',{...paging},[],'read'],
  ['evidence_list','evidence','list',{...paging},[],'read'],
  ['evidence_show','evidence','show',{id,...paging},['id'],'read'],
  ['jobs_list','job','list',{},[],'read'],['job_show','job','show',{id},['id'],'read'],
  ['job_cancel','job','cancel',{id},['id'],'workspace'],['job_events','job','events',{id},['id'],'read'],
  ['jobs_recover','job','recover',{},[],'administration'],['index_rebuild','index','rebuild',{},[],'administration'],
 ])registry.add({name,group:family,effect,description:`${family} ${operation}: persisted native identities and evidence. Function views retain distinct backend claims; cancellation is explicit.`,schema:object(fields,required),route:{kind:'cli',family,operation},example:{}});
 for(const operation of ['capabilities','show','list','cancel','reconcile','export','prune'])registry.add({name:'guest_'+operation,group:'guest',effect:['cancel','prune'].includes(operation)?'administration':operation==='export'?'workspace':'read',description:`QEMU guest ${operation}; existing profile/run identities only. Provisioning and arbitrary guest configuration remain operator-side.`,schema:object(['capabilities','list'].includes(operation)?{}:{id},['capabilities','list'].includes(operation)?[]:['id']),route:{kind:'guest',family:'guest',operation},example:{}});
 return registry;
}
