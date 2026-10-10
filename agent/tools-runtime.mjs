import contracts from './native-contracts.mjs';
import {object} from './tool-registry.mjs';
export const runtimeReads=new Set(['capabilities','payloads','recipes','sessions','status','request','observations','network','identities','lineage']);
// Explicit per-operation fields avoid presenting the full transport envelope to the model.
export const runtimeFields={
 'capabilities':'','payloads':'','recipes':'','sessions':'',
 'io-run':'argv input_hex environment files managed_trace timeout_ms max_output_bytes',
 'launch':'argv cwd lifetime_ms terminate_on_expiry follow_children timeout_ms',
 'attach':'pid lifetime_ms terminate_on_expiry timeout_ms',
 'instrument':'backend recipe argv cwd pid timeout_ms max_events telemetry code_scope follow_children input_hex environment files',
 'record':'argv cwd timeout_ms trace_bytes input_hex environment files experiment_key',
 'replay':'session timeout_ms trace_bytes experiment_key',
 'status':'session','request':'session id wait timeout_ms',
 'modules':'session','threads':'session','processes':'session','select-process':'session pid',
 'continue':'session wait timeout_ms','pause':'session wait timeout_ms',
 'step':'session thread wait timeout_ms','step-over':'session thread wait timeout_ms','step-out':'session thread wait timeout_ms',
 'stack':'session thread limit','crash':'session','watchpoint':'session address size access condition one_shot',
 'breakpoints':'session','breakpoint':'session address static_address rva function module expression condition one_shot hardware',
 'remove-breakpoint':'session breakpoint_id','registers':'session thread','memory':'session address size',
 'capture':'session address size','resolve':'session address static_address rva artifact module',
 'trace':'session max_steps memory code_regions timeout_ms',
 'cancel':'session id','observations':'session kind offset limit','network':'session offset limit',
 'solve-input':'session observation',
 'symbolic':'session observation mode sink path symbolic_registers symbolic_memory input_ranges byte_constraints max_steps timeout_ms',
 'validate-witness':'session observation address path terminal_index branch_index',
 'detach':'session','terminate':'session','reanalyze':'session observation backend timeout_ms',
 'feedback':'session observation backend timeout_ms','lineage':'session artifact','identities':'session id kind offset limit',
};
const help={
 'io-run':'Run a bounded original-target input case. Stdout/exit alone is not an acceptance proof.',
 'launch':'Launch the active target with the existing platform debugger (DbgEng/GDB); returns an explicit session ID.',
 'attach':'Attach the existing debugger to an explicitly selected PID. Requires host authority.',
 'instrument':'Observe the active target with Frida recipes or DynamoRIO. Select backend explicitly.',
 'record':'Record the active ELF with bundled rr on supported Linux; never substitutes a different engine.',
 'replay':'Replay a returned, packed rr recording session on supported Linux.',
 'solve-input':'Generate bounded input candidates from runtime observations using existing XAIR symbolic machinery. Replay candidates separately.',
 'symbolic':'Concrete-seeded XAIR symbolic analysis of an explicit runtime observation.',
 'capture':'Capture a bounded executable/memory region for identity-preserving reanalysis.',
 'reanalyze':'Reanalyze an explicit captured artifact with XAIR/Ghidra; retain runtime provenance.',
 'network':'Page stored network observations; correlation is not proof of protocol causality.',
};
export function addRuntime(registry){
 const props=contracts['runtime-action'].properties;
 for(const operation of props.operation.enum){
  if(!Object.hasOwn(runtimeFields,operation))throw Error('Unmapped runtime operation '+operation);
  const fields=runtimeFields[operation].split(' ').filter(Boolean);
  const p=Object.fromEntries(fields.map(k=>[k,props[k]]));
  if(operation==='instrument')p.backend={enum:['frida','dynamorio'],type:'string'};
  if(['reanalyze','feedback'].includes(operation))p.backend={enum:['xair','ghidra','both'],type:'string'};
  if(p.limit)p.limit={type:'integer',minimum:1,maximum:256};
  if(p.offset)p.offset={type:'integer',minimum:0,maximum:1000000};
  if(p.size)p.size={type:'integer',minimum:1,maximum:65536};
  if(p.session)p.session={...p.session,minLength:1,description:'Explicit session ID returned by a prior runtime call. Never infer the most recent session.'};
  const required=fields.includes('session')?['session']:[];
  required.push(...({'io-run':['input_hex'],attach:['pid'],instrument:['backend'],memory:['address','size'],capture:['address','size'],'remove-breakpoint':['breakpoint_id'],'select-process':['pid'],'solve-input':['observation'],symbolic:['observation','mode'],request:['id'],reanalyze:['observation'],feedback:['observation'],lineage:['artifact']}[operation]??[]));
  registry.add({name:'runtime_'+operation.replaceAll('-','_'),group:'runtime',effect:runtimeReads.has(operation)?'read':'execution',description:help[operation]??`Existing runtime ${operation}; use returned session/observation identities. Results preserve native limitations.`,schema:object(p,required),route:{kind:'runtime',operation},example:Object.fromEntries(required.map(k=>[k,k==='session'?'run_RETURNED_ID':k==='input_hex'?'4142':k==='backend'?'frida':k==='mode'?'solve_branch':k==='pid'?1234:k==='size'?64:k==='input_ranges'?[]:'RETURNED_ID']))});
 }
 return registry;
}
