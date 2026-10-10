import contracts from './native-contracts.mjs';
import {object,string,integer,array} from './tool-registry.mjs';
// Fields/requirements mirror the operation validators, not merely the envelope schema.
export const workbenchRoutes={
 knowledge:{put:['id expected_revision kind title state body assumptions dependencies support counterevidence','kind title state body'],show:['id revision history','id'],list:['kind search limit offset history type',''],refresh:['id','id'],impact:['id type limit offset','id']},
 graph:{search:['search limit output_bytes','search'],neighborhood:['id anchor address search depth limit output_bytes direction kinds',''],packet:['id anchor address search depth limit output_bytes direction kinds',''],event:['observation depth limit output_bytes','observation']},
 coverage:{report:['limit scan_limit','']},
 system:{create:['title manifest','title manifest'],show:['id','id'],list:['limit offset',''],preflight:['id max_bytes','id']},
 recognize:{scan:['limit scan_limit publish','']},
 transform:{run:['offset size spec title assumptions','spec']},
 validate:{compare:['subject cases title dependencies','cases'],transform:['subject cases spec title dependencies','cases spec']},
 batch:{create:['steps budget title','steps'],show:['id','id'],run:['id retry_failed reset_cancel','id'],cancel:['id','id'],events:['id offset limit','id']},
 bundle:{export:['destination max_bytes','destination'],import:['source destination max_bytes','source destination']},
 retention:{plan:['limit',''],quarantine:['limit plan_digest','plan_digest']},
};
export function addWorkbench(registry){
 const props=contracts.workbench.properties.request.properties;
 for(const [family,operations] of Object.entries(workbenchRoutes))for(const [operation,[fields,required]] of Object.entries(operations)){
  const p=Object.fromEntries(fields.split(' ').filter(Boolean).map(k=>[k,props[k]]));
  if(p.limit)p.limit=integer(1,200);
  if(p.cases)p.cases={...array(object({input_artifact:props.artifact,actual_artifact:props.artifact,expected_artifact:props.artifact,expected_hex:{type:'string',pattern:'^([a-fA-F0-9]{2})*$',maxLength:8192},label:string('',256)},[operation==='transform'?'input_artifact':'actual_artifact']),64),minItems:1};
  const admin=['bundle','retention','system'].includes(family)&&!['show','list','preflight','plan'].includes(operation);
  registry.add({name:`${family}_${operation}`,group:family,effect:admin?'administration':['put','refresh','run','create','cancel'].includes(operation)?'workspace':'read',description:`${family} ${operation}: existing native workbench operation. Artifact/project are bound by the controller; native revisions, provenance and uncertainty are preserved.${admin?' Requires an operator administration grant.':''}`,schema:object(p,required.split(' ').filter(Boolean)),route:{kind:'workbench',family,operation},example:{}});
 }
 return registry;
}
