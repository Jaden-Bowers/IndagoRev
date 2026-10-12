import fs from 'node:fs';
import path from 'node:path';
import {staticRegistry} from './tools-static.mjs';
const named=new Set(staticRegistry().list().filter(e=>e.effect==='read').map(e=>e.name));
const local=new Set(['read','tools_search','analysis_tools','evidence_read','native_evidence_read','artifact_read','function_views','knowledge_show','knowledge_list','index_entities','index_relations','index_claims','index_revisions','investigation_update','investigation_focus','remember','question_list','question_add','question_checkpoint']);
export function staticToolAllowed(name,config={}){return named.has(name)||local.has(name)||(config.allowHelpers===true&&process.platform==='linux'&&['helper_run','helper_read','helper_capabilities','workflow_status'].includes(name));}
export function staticPolicy(config,name,input={}){
 if(!config.restrictedStatic)return;
 if(!staticToolAllowed(name,config))throw Error(`Restricted-static policy denies ${name}; no shell, target execution, generic dispatch, or arbitrary writes`);
 if(name==='read'){
  const file=fs.realpathSync(path.resolve(config.cwd,input.path??''));
  const roots=[config.state,config.queueDirectory,config.cwd].filter(Boolean).map(p=>fs.realpathSync(p));
  if(!roots.some(root=>{const rel=path.relative(root,file);return !rel.startsWith('..')&&!path.isAbsolute(rel);}))throw Error('Restricted read must remain in the case or investigation directories');
 }
}
