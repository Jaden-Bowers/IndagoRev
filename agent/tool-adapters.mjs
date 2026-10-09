import fs from 'node:fs';
import path from 'node:path';
import {hashFile} from './native.mjs';
import {staticRegistry} from './tools-static.mjs';
import {validate} from './tool-registry.mjs';
import {ToolResults} from './tool-results.mjs';

export class ToolAdapters {
 constructor(native,config){this.native=native;this.config=config;this.registry=staticRegistry();this.results=new ToolResults(config.state);this.catalog=config.toolCapabilities;}
 async capabilities(signal){return this.catalog??=(await this.native.capabilities(signal)).data;}
 binding(){return {target_id:this.native.active?.id,artifact_sha256:this.native.active?.artifact_sha256};}
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
  const e=this.registry.get(name);validate(e.schema,input);signal?.throwIfAborted();
  if(e.effect==='annotation'&&!this.config.allowAnnotations)throw Error('Annotation requires an operator-granted session; model arguments cannot grant it');
  const catalog=await this.capabilities(signal);
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
 activeGroups(){
  const kind=this.config.toolRoute?.kind;
  const groups=new Set();
  if(['pe','pe_candidate','elf','elf_candidate','managed_pe'].includes(kind))for(const g of ['ghidra','xair','airece','sym','capa','floss','lief'])groups.add(g);
  if(['managed_pe','pdf','wasm','ole_container','zip_container','java_archive','android_package','office_document'].includes(kind))groups.add('ilspy');
  if(['dex','dex_candidate','jvm_class_candidate'].includes(kind))groups.add('ghidra');
  if(kind==='capture')groups.add('wireshark');
  return groups;
 }
 async available(signal){const c=await this.capabilities(signal);return this.registry.list().filter(e=>e.route.kind==='analysis'&&c.backends?.some(b=>b.name===e.route.backend&&b.available&&b.operations.includes(e.route.operation)));}
}
