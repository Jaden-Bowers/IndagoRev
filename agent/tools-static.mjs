import {ToolRegistry,object,string,integer,enumeration,array,location} from './tool-registry.mjs';
const paging={cursor:string('Opaque next_cursor returned by this operation'),search:string('Filter this collection'),collection:string('Native paginated collection path'),scan_limit:integer(1,100000)};
const common={address:location,limit:integer(1,2048)};
export function staticRegistry(){
 const registry=new ToolRegistry();
 const add=(name,backend,operation,properties={},required=[],description='',effect='read')=>registry.add({name,group:backend,effect,description:description||`${backend}: ${operation}. Native semantics and partial results are preserved.`,schema:object(properties,required),route:{kind:'analysis',backend,operation},example:Object.fromEntries(required.map(k=>[k,k==='address'?'current':k==='expected_revision'?0:k==='source'?'funcarg(0)@0x140001000':'reach@0x140001020']))});
 for(const operation of ['import','inspect','functions','decompile','tokens','assembly','xrefs','calls','strings','imports','exports','types','variables','cfg','pcode','control_flow','session','annotations']){
  const needs=['decompile','tokens','xrefs','calls','variables','cfg','pcode','control_flow'].includes(operation);
  const name=['functions','decompile','xrefs'].includes(operation)?operation:`ghidra_${operation}`;
  add(name,'ghidra',operation,{...common,...paging},needs?['address']:[],`Ghidra ${operation}. ${needs?'Use address=current for the GUI function or address=selection for quoted code. ':''}Use returned pagination.next_cursor as cursor; no discovery step required.`);
 }
 for(const op of ['flush','close'])add(`ghidra_${op}`,'ghidra',op,{},[],`Explicitly ${op} the Ghidra session. Does not execute the target.`,'session');
 add('ghidra_analyze','ghidra','analyze',{address:location,expected_revision:integer()},['expected_revision'],'Explicitly rerun static analysis, optionally at a new function seed. Requires operator annotation grant.','annotation');
 for(const [kind,fields,required] of [
  ['rename',{name:string('New function name',256)},['name']],
  ['comment',{text:string('Function comment',4096)},['text']],
  ['create_structure',{name:string('Structure name',256),size:integer(1,65536),fields:array(object({offset:integer(0,65535),type_path:string('Existing type path',1024),name:string('Field name',256)},['offset','type_path','name']),256)},['name','size','fields']],
  ['signature',{prototype:string('C function prototype',4096)},['prototype']],
  ['variable_type',{symbol_id:string('Recovered Ghidra symbol ID',128),type_path:string('Existing Ghidra type path',1024)},['symbol_id','type_path']],
 ]){const name=`ghidra_${kind}`;add(name,'ghidra','annotate',{address:location,expected_revision:integer(),...fields},['address','expected_revision',...required],'Persist a revision-checked Ghidra annotation. Requires operator annotation grant.','annotation');registry.entries.set(name,{...registry.get(name),annotation:kind});}
 for(const op of ['inspect','functions','function','calls','xrefs','slice','path','flow','taint','evidence']){
  const required=op==='flow'?['source','target']:['function','calls','xrefs','slice','evidence'].includes(op)?['address']:[];
  add(`airece_${op}`,'airece',op,{...common,offset:integer(0,1000000),view:enumeration('compact','agent','pseudocode','disassembly','json'),source:string('AIRECE selector, e.g. funcarg(0)@0x140001000'),target:string('AIRECE selector, e.g. reach@0x140001020'),from:string('Native source selector'),to:string('Native destination selector'),mode:enumeration('taint','taint-symbolic','symbolic'),profile:enumeration('fast','balanced','exhaustive')},required);
 }
 for(const op of ['inventory','semantic','cfg'])add(`xair_${op}`,'xair',op,{...common,profile:enumeration('fast','balanced','exhaustive')},[],op==='cfg'?'XAIR_CFG functions, blocks, edges and native CFG analyses. Partial/indirect candidates are not proven edges.':op==='semantic'?'XAIR lifted instructions, SSA values, definitions/uses, flags and memory/call effects; retain semantic completeness.':'Inspect native format, architecture, entry and loader mappings with XAIR.');
 for(const op of ['solve_branch','source_to_sink','symbolic_slice','taint','path_condition'])add(`sym_${op}`,'sym',op,{address:location,function:location,source:string('Native symbolic source selector'),sink:string('Native symbolic sink selector'),max_states:integer(1,65536),max_queries:integer(1,4096),max_paths:integer(1,4096),function_depth:integer(1,16),symbolic_timeout_ms:integer(1,30000)},['source_to_sink','path_condition'].includes(op)?['source','sink']:op==='symbolic_slice'?['address','function']:['address'],`Bounded XAIR_SYM ${op}. Unknown/timeout is not unsatisfiable; validate generated candidates against evidence.`);
 for(const op of ['inventory','types','methods','decompile','assembly','references','member_refs','resources','trace','artifact'])add(`managed_${op}`,'ilspy',op,{address:{...string('MethodDef token, NOT a native VA'),pattern:'^0x06[0-9a-fA-F]{6}$'},offset:integer(0,1000000),dependencies:array(string('Previously imported dependency target ID'),8),pdb:string('Imported PDB target ID'),entry:string('Container member for artifact inspection',1024),limit:integer(1,2048)},['decompile','assembly'].includes(op)?['address']:[],`ILSpy ${op}; dependencies are imported target IDs. trace reads supported trace artifacts, it does not start managed execution.`);
 add('capability_leads','capa','capabilities',{format:enumeration('pe','elf','dotnet'),address:location},[],'capa capability findings are leads, not proof of behavior.');
 add('recover_strings','floss','strings',{mode:enumeration('static','stack','tight','decoded','all'),minimum_length:integer(4,256),address:location},[],'FLOSS static/stack/tight/decoded strings. Defaults to static; decoded results are not accepted inputs.');
 for(const op of ['inventory','sections','resources','notes','libraries'])add(`format_${op}`,'lief',op,{offset:integer(0,65536),limit:integer(1,2048)},[],`LIEF ${op}; bounded executable-format metadata.`);
 add('packet_inspect','wireshark','packets',{offset:integer(0,4096),limit:integer(1,2048)},[],'Offline TShark packet evidence. Does not initiate live capture or infer endpoint identity.');
 return registry;
}
