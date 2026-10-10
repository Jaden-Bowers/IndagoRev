import {object,string,integer,array,enumeration,boolean} from './tool-registry.mjs';
import contracts from './native-contracts.mjs';
const text=string('',2048),id=string('Returned native identity',128),pin=object({id,revision:integer(1,100000000)},['id','revision']);
const hex={type:'string',pattern:'^([a-f0-9]{2})*$',maxLength:8192};
const page=object({offset:integer(0,67108864),address:string('',64),max_bytes:integer(1,262144),raw_sha256:string('',64)});
const input=object({...page.properties,generated_hex:hex});
const proposal=object({gap:text,expected_evidence:text,prediction:text,fallback:text},['gap','expected_evidence','prediction','fallback']);
export function addWorkflows(registry){
 const add=(name,group,operation,properties,required,effect='workspace',description='')=>registry.add({name,group,effect,description:description||`${name}: bounded native workflow; outputs remain candidates until validated against original evidence.`,schema:object(properties,required),route:{kind:'workflow',family:group,operation},example:{}});
 add('helper_run','helper','run',{language:enumeration('c17','c++20','smt2','python3','unicorn-x86'),source_code:string('Complete bounded helper source',16384),input,inputs:array(object({name:id,target_id:id,offset:integer(),max_bytes:integer(1,262144),raw_sha256:string('',64)},['name','target_id']),4),output_files:array(id,4),validation:object({kind:enumeration('none','artifact_bytes','calculation'),expected:page,program:{type:'object'},output_file:id},['kind']),proposal},['language','source_code','input'],'helper','Compile/run confined analysis helpers with pinned inputs and native validation. Requires a supported helper environment; never silently falls back to host execution.');
 const props=contracts.workbench.properties.request.properties;
 const runtime=contracts['runtime-action'].properties;
 const cases={...array(object({label:string('',256),argv:runtime.argv,input_hex:runtime.input_hex,files:runtime.files,environment:runtime.environment,timeout_ms:integer(100,10000),engine:props.engine,managed_trace:boolean,solver_candidate:object({session:id,observation:id,terminal:integer(0,31),branch:integer(0,1),candidate:integer(0,15),receipt_sha256:string('',64)},['session','observation','terminal','branch','candidate'])},['label','input_hex']),2),minItems:1};
 add('experiment_run','experiment','run',{engine:props.engine,cases,steps:{...props.steps,maxItems:6},prediction:props.prediction,recipe:props.recipe,telemetry:props.telemetry,recover_code:boolean,managed_trace:boolean,companions:props.companions,proposal},['engine','cases','prediction'],'execution','Run reproducible positive/negative original-target experiments through the native controller, including debugger steps and bounded instrumentation. No acceptance oracle is granted by this call.');
 add('experiment_cleanup','experiment','cleanup',{action_id:id,proposal},['action_id'],'execution');
 add('algorithm_candidate','research','run',{domain:text,assumptions:array(text,32),evidence:array(pin,16),language:props.language,source_code:props.source_code,generator:object({seed_hex:hex,count:integer(2,16)},['seed_hex','count']),previous:pin,proposal},['domain','assumptions','evidence','language','source_code','generator']);
 add('algorithm_compare','research','run',{candidate:pin,pairs:array(object({helper:pin,experiment:pin,case:integer(0,1)},['helper','experiment','case']),16),proposal},['candidate','pairs']);
 const capture=object({target_id:id,offset:integer(0,67108864),max_bytes:integer(1,4096)},['target_id','offset','max_bytes']);
 add('service_contract','research','run',{hypothesis:text,responses:array(object({origin:enumeration('captured','inferred','invented_stimulus'),hex,capture,rationale:text,variable_ranges:array(object({offset:integer(),length:integer(1,4096),reason:text},['offset','length','reason']),32),timing:object({origin:enumeration('unknown','inferred','invented_stimulus'),min_ms:integer(0,100),max_ms:integer(0,100)},['origin','min_ms','max_ms'])},['origin','hex','rationale','variable_ranges','timing']),16),reject_if:array(text,32),previous:pin,proposal},['hypothesis','responses','reject_if']);
 add('service_observe','research','run',{contract:pin,response:integer(0,15),capture,proposal},['contract','response','capture']);
 add('guest_run','guest','run',{profile:id,actions:array(object({operation:enumeration('observe','pause','resume','warm_reset','snapshot','restore','registers'),duration_ms:integer(100,1000)},['operation']),16),previous:id,mode:enumeration('normal','record','replay'),proposal},['profile','actions'],'guest','Run a pre-provisioned, operator-granted QEMU profile via the native lifecycle. No arbitrary QMP, network or guest provisioning.');
 for(const family of ['helper','experiment','research','guest']){
  add(family+'_read',family,'read',{id,revision:integer(1,100000000),pointer:string('',256),offset:integer(0,131072),max_bytes:integer(1,2048)},['id'],'read');
 }
 for(const [family,operation] of [['helper','capabilities'],['experiment','capabilities'],['research','tools'],['experiment','reconcile']])add(family+'_'+operation,family,operation,operation==='reconcile'?{action_id:id}:{},operation==='reconcile'?['action_id']:[],'read');
 add('native_evidence_read','evidence','read',{id,pointer:string('',256),offset:integer(),limit:integer(1,16),max_bytes:integer(4,2048),raw_sha256:string('',64)},['id'],'read','Read pinned native evidence by ID and JSON pointer, distinct from evidence_read for adapter result pages.');
 add('artifact_read','artifact','read',page.properties,[],'read','Read bounded bytes of the active imported artifact by offset or address; preserves byte identity.');
 for(const operation of ['entities','relations','claims','revisions'])add('index_'+operation,'index',operation,{kind:id,name:text,search:text,limit:integer(1,16)},[],'read');
 add('workflow_status','workflow','status',{},[],'read','Inspect the controller-owned investigation and action history. Clears pending state only when the exact action has a definitive terminal outcome.');
 return registry;
}
