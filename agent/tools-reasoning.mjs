import {object,string,integer,array,enumeration} from './tool-registry.mjs';
export function addReasoning(registry){
 const id=string('',128),text=string('',2048),source=object({evidence_id:id,pointer:string('',256)},['evidence_id','pointer']);
 const fields={id,description:text,sources:array(source,16),obligation:id,statement:text,prediction:text,falsifier:text,checks:array({type:'object'},16),hex:{type:'string',pattern:'^([a-fA-F0-9]{2})*$',maxLength:8192},encoding:enumeration('hex','utf8'),assumptions:array(text,16),source,representation:enumeration('hex','utf8'),spec:object({method:enumeration('slice','xor','hex_decode','base64_decode'),key_hex:string('',8192)},['method']),expected:source,actual:source,hypothesis:id,candidate:id,observe:enumeration('branch_witness','capture_reanalyze','io_result'),pointer:string('',256),fact_index:integer(0,31),proof_kind:enumeration('observed_output','accepted_input'),session:id,observation:id,sha256:string('',64),experiment:id,answer:text,recovery:id,control_flow:source,entry_flow:source,proof:id};
 const operations={bind:'id description sources',hypothesize:'obligation statement prediction falsifier sources',revise_hypothesis:'id statement prediction falsifier sources',check_hypothesis:'id checks',candidate:'obligation hex encoding assumptions sources',derive:'obligation source representation spec encoding assumptions',validate_transform_candidate:'id expected representation spec',validate_candidate:'id actual',experiment:'hypothesis candidate prediction observe pointer expected sources fact_index proof_kind',feedback:'id session observation sha256',prove_observation:'experiment answer',recover_initialized_x86:'source fact_index',verify_transformation:'recovery control_flow entry_flow',solution:'proof answer'};
 for(const [operation,list] of Object.entries(operations)){
  const keys=list.split(' '),p=Object.fromEntries(keys.map(k=>[k,fields[k]]));
  if(p.assumptions)p.assumptions=string('Explicit assumptions',1024);
  if(p.hex)p.hex={...p.hex,maxLength:1024};
  if(operation==='experiment')p.expected={}; // Native planned observation can compare an exact scalar.
  registry.add({name:'reason_'+operation,group:'reasoning',effect:'workspace',description:`Native ${operation} reasoning/proof gate. expected_revision is the reasoning revision returned by reasoning_read. Never promotes a candidate to an independently graded solve.`,schema:object({expected_revision:integer(0,100000000),...p},['expected_revision',...keys.filter(k=>operation!=='experiment'||!['fact_index','proof_kind'].includes(k))]),route:{kind:'workflow',family:'reasoning',operation},example:{}});
 }
 for(const [name,family,operation,p,required] of [
  ['reasoning_read','investigation','reasoning',{collection:enumeration('questions','obligations','hypotheses','candidates','experiments','recoveries','proofs','solutions'),offset:integer(0,256),limit:integer(1,8),id,pointer:string('',256)},[]],
  ['reasoning_tools','investigation','reasoning_tools',{},[]],
  ['validation_check','validation','check',{checks:array({type:'object'},16)},['checks']],
  ['calculation_evaluate','calculation','evaluate',{source:object({offset:integer(0,67108864),address:string('',64),max_bytes:integer(1,1024),raw_sha256:string('',64)}),iterations:integer(1,256),variables:{type:'object',maxProperties:16,additionalProperties:integer(0,4294967295)},body:array(object({set:string('',32),value:{}},['set','value']),32),emit:{}},['source','emit']],
  ['investigation_scope','investigation','scope',{},[]],['investigation_manifest','investigation','manifest',{},[]],['investigation_audit','investigation','audit',{offset:integer(),limit:integer(1,128)},[]],
 ])registry.add({name,group:family,effect:'read',description:`Read bounded native ${family}/${operation}; source locations and proof requirements remain authoritative.`,schema:object(p,required),route:{kind:'workflow',family,operation},example:{}});
 return registry;
}
