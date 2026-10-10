import fs from 'node:fs';
import path from 'node:path';
import {hashFile,atomic} from './native.mjs';
import {addRuntime,runtimeReads} from './tools-runtime.mjs';
import {addWorkbench} from './tools-workbench.mjs';
import {addWorkflows} from './tools-workflows.mjs';
import {Workflows} from './tool-workflows.mjs';
import {addCore} from './tools-core.mjs';
import {addReasoning} from './tools-reasoning.mjs';
import {staticRegistry} from './tools-static.mjs';
import {validate} from './tool-registry.mjs';
import {ToolResults} from './tool-results.mjs';

export class ToolAdapters {
 constructor(native,config){this.native=native;this.config=config;this.registry=addReasoning(addCore(addWorkflows(addWorkbench(addRuntime(staticRegistry())))));this.results=new ToolResults(config.state);this.catalog=config.toolCapabilities;this.workflows=new Workflows(native,config);}
 async capabilities(signal){return this.catalog??=(await this.native.capabilities(signal)).data;}
 binding(){return {target_id:this.native.active?.id,artifact_sha256:this.native.active?.artifact_sha256};}
 async advancedAnalysis(p,signal){
  if(p.target_id&&p.target_id!==this.native.active.id)throw Error('Use program_open before analyzing a different target');
  if(p.backend==='ghidra'&&['annotate','analyze'].includes(p.operation)&&!this.config.allowAnnotations)throw Error('Annotation requires operator grant');
  return this.results.save('analyze',await this.native.analyze(p,signal),this.binding());
 }
 async advancedCommand(args,request={},signal){
  if(args.length!==2||args.some(a=>a.startsWith('-')))throw Error('Use a named tool or a two-word public family/operation; transport flags and internal workers are not model parameters');
  const [family,operation]=args;
  if(request.project&&request.project!==this.config.project)throw Error('Cross-project override denied');
  const p={...request};delete p.project;
  if(family==='runtime')return this.execute('runtime_'+operation.replaceAll('-','_'),p,signal);
  const e=this.registry.list().find(e=>e.route.kind==='workbench'&&e.route.family===family&&e.route.operation===operation);
  if(e)return this.execute(e.name,p,signal);
  throw Error('No model adapter for this CLI operation. Use tools_search for supported calls. Operator/installation commands remain in the explicit host CLI, not an implicit controller bypass.');
 }
 async address(value,signal){
  if(!['current','selection'].includes(value))return value;
  const refs=this.config.selection??[];
  if(!refs.length)throw Error('No GUI selection; provide an explicit hexadecimal address');
  if(refs.some(r=>r.artifact_sha256!==this.native.active.artifact_sha256||hashFile(r.file)!==r.artifact_sha256))throw Error('Selection belongs to another artifact or changed file');
  const revisions=new Set(refs.map(r=>r.program_revision).filter(r=>r!==null&&r!==undefined));
  if(revisions.size){const r=await this.native.analyze({backend:'ghidra',operation:'session'},signal);if(revisions.size!==1||!revisions.has(r.data.data?.program_revision))throw Error('Selection revision is stale; select code again');}
  const addresses=[...new Set(refs.flatMap(r=>value==='current'?[r.function_address]:r.locations?.map(l=>l.min_address)??[]).filter(Boolean))];
  if(addresses.length!==1)throw Error('Selection has multiple or no addresses; choose an explicit address from its locations');
  return addresses[0];
 }
 async execute(name,input,signal){
  try{return await this.dispatch(name,input,signal);}
  catch(error){if(error.nativeData)return this.results.save(name,{data:error.nativeData,receipt:error.receipt},this.binding());throw error;}
 }
 async dispatch(name,input,signal){
  if(Buffer.byteLength(JSON.stringify(input))>262144)throw Error('Tool input exceeds the 256 KiB adapter bound');
  const e=this.registry.get(name);validate(e.schema,input);signal?.throwIfAborted();
  if(e.effect==='annotation'&&!this.config.allowAnnotations)throw Error('Annotation requires an operator-granted session; model arguments cannot grant it');
  if(e.effect==='administration'&&!this.config.allowAdministration)throw Error('Requires operator administration grant; not a model parameter');
  const catalog=await this.capabilities(signal);
  if(e.route.kind==='runtime')return this.runtime(e,input,signal);
  if(e.route.kind==='workflow')return this.results.save(name,await this.workflows.execute(e,input,signal),this.binding());
  if(e.route.kind==='guest'){
   const p={...input};if(e.route.operation==='export')p.project=this.config.project;
   return this.results.save(name,await this.native.call(['guest',e.route.operation],p,{signal}),{scope:'guest-profile-or-run',id:input.id??null});
  }
  if(e.route.kind==='cli'){
   const args=[e.route.family,...(e.route.operation?[e.route.operation]:[]),'--project',this.config.project];
   if(e.route.family==='functions')args.push('--artifact',this.native.active.artifact_sha256);
   for(const [k,v] of Object.entries(input))args.push('--'+k,String(v));
   return this.results.save(name,await this.native.call(args,undefined,{signal}),e.route.family==='functions'?this.binding():{project:this.config.project,scope:'explicit-project-identity',id:input.id??null});
  }
  if(e.route.kind==='workbench'){
   const {family,operation}=e.route;
   const p={...input};
   if(!(family==='bundle'&&operation==='import')&&family!=='retention')p.project=this.config.project;
   if(['coverage','recognize','transform'].includes(family)||family==='graph'&&operation!=='event'||family==='knowledge'&&operation==='list')p.artifact=this.native.active.artifact_sha256;
   if(family==='knowledge'&&operation==='put')p.scope={artifact_sha256:this.native.active.artifact_sha256};
   const r=await this.native.call([family,operation],p,{signal});
   const artifactBound=['coverage','recognize','transform'].includes(family)||family==='graph'&&operation!=='event'||family==='knowledge'&&['put','list'].includes(operation);
   return this.results.save(name,r,artifactBound?this.binding():{project:this.config.project,scope:'explicit-project-identity',id:input.id??input.subject??null});
  }
  if(e.route.kind==='analysis'){
   const b=catalog.backends?.find(b=>b.name===e.route.backend);
   if(!b?.available||!b.operations.includes(e.route.operation))throw Error(`Unavailable ${e.route.backend}/${e.route.operation}; provision the matching native build/engine, not a shell fallback`);
   const p={...input},address=await this.address(p.address,signal);delete p.address;
   const limit=p.limit??128;delete p.limit;const view=p.view??'compact';delete p.view;
   if(p.function)p.function=await this.address(p.function,signal);
   if(e.route.backend==='sym')for(const key of ['max_states','max_queries','max_paths','function_depth','symbolic_timeout_ms'])if(p[key]!==undefined){p[key.replaceAll('_','-')]=p[key];delete p[key];}
   if(e.annotation){const expected_revision=p.expected_revision;delete p.expected_revision;const annotation={kind:e.annotation,...p};for(const k of Object.keys(p))delete p[k];Object.assign(p,{expected_revision,annotation});}
   const r=await this.native.analyze({backend:e.route.backend,operation:e.route.operation,address,arguments:p,view,limit},signal);
   return this.results.save(name,r,this.binding());
  }
  throw Error(`Adapter missing for ${name}`);
 }
 async runtime(e,input,signal){
  const op=e.route.operation;
  if(!runtimeReads.has(op)&&this.config.authority!=='host')throw Error('Target interaction requires operator host authority; tool arguments cannot grant it');
  const p={...input,project:this.config.project};
  if(op==='instrument'&&this.catalog?.runtime?.[p.backend]?.bundled===false)throw Error(`${p.backend} payload is unavailable in this native build`);
  if(['io-run','launch','instrument','record'].includes(op)&&!p.pid){
   if(hashFile(this.native.active.path)!==this.native.active.artifact_sha256)throw Error('Active target file changed; import it again before execution');
   p.file=this.native.active.path;
  }
  if(op==='io-run'){p.artifact=this.native.active.artifact_sha256;p.trusted_target_ack=true;}
  if(['record','replay'].includes(op))p.backend='rr';
  if(['record','replay'].includes(op)&&process.platform==='win32')throw Error('rr requires the supported Linux build/profile. No automatic WSL launch or engine substitution.');
  // Explicit durable pending marker: a timeout is not evidence the target stopped.
  const pending=path.join(this.config.state,'runtime-pending.json');
  const mutation=!runtimeReads.has(op)&&!['request','cancel','detach','terminate'].includes(op);
  if(mutation&&fs.existsSync(pending))throw Error('An earlier runtime operation has an uncertain outcome. Read runtime_status/runtime_request and reconcile before another mutation. See runtime-pending.json; no automatic retry.');
  if(mutation)atomic(pending,{operation:op,input,session:input.session,binding:this.binding(),status:'dispatching'});
  const r=await this.native.call(['runtime',op],p,{signal,timeout:Math.min(120000,(p.timeout_ms??60000)+30000)});
  if(mutation){
   if(['pending','starting','running'].includes(r.data.status)&&r.data.request_id)atomic(pending,{operation:op,session:r.data.session_id,request_id:r.data.request_id,status:r.data.status});
   else fs.rmSync(pending,{force:true});
  }
  // Only a terminal response for the exact pending request can automatically clear uncertainty.
  if(op==='request'&&fs.existsSync(pending)){
   const prior=JSON.parse(fs.readFileSync(pending));
   if(prior.session===p.session&&prior.request_id===p.id&&['completed','failed','cancelled'].includes(r.data.status))fs.rmSync(pending,{force:true});
  }
  if(op==='status'&&fs.existsSync(pending)){
   const prior=JSON.parse(fs.readFileSync(pending));
   if(prior.session===p.session&&!r.data.worker_alive&&['completed','detached','exited','terminated','cancelled','failed'].includes(r.data.state))fs.rmSync(pending,{force:true});
  }
  return this.results.save(e.name,r,{project:this.config.project,active_target_id:this.native.active.id,artifact_sha256:r.data.artifact_sha256??(p.file?this.native.active.artifact_sha256:null),session:input.session??r.data.session_id??r.data.id});
 }
 activeGroups(){
  const kind=this.config.toolRoute?.kind;
  const groups=new Set();
  if(['pe','pe_candidate','elf','elf_candidate','managed_pe'].includes(kind))for(const g of ['ghidra','xair','airece','sym','capa','floss','lief'])groups.add(g);
  if(['managed_pe','pdf','wasm','ole_container','zip_container','java_archive','android_package','office_document'].includes(kind))groups.add('ilspy');
  if(['dex','dex_candidate','jvm_class_candidate','class_or_fat_macho_candidate'].includes(kind))groups.add('ghidra');
  if(['zip_container','java_archive','ole_container','office_document'].includes(kind))groups.add('transform');
  if(kind==='capture')groups.add('wireshark');
  return groups;
 }
 async available(signal){const c=await this.capabilities(signal);return this.registry.list().filter(e=>{
  if(e.effect==='administration'&&!this.config.allowAdministration||e.effect==='annotation'&&!this.config.allowAnnotations)return false;
  if(['cli','guest'].includes(e.route.kind))return true;
  if(e.route.kind==='workflow')return e.effect==='helper'?this.config.allowHelpers===true&&process.platform==='linux':e.effect==='execution'?this.config.authority==='host':e.effect==='guest'?(this.config.guestProfiles??[]).length>0&&process.platform==='linux':true;
  if(e.route.kind==='workbench')return c.workbench?.families?.[e.route.family]?.includes(e.route.operation);
  if(e.route.kind==='runtime')return (runtimeReads.has(e.route.operation)||this.config.authority==='host')&&(!['record','replay'].includes(e.route.operation)||process.platform!=='win32');
  return e.route.kind==='analysis'&&c.backends?.some(b=>b.name===e.route.backend&&b.available&&b.operations.includes(e.route.operation));
 });}
}
