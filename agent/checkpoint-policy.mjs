import fs from 'node:fs';
import path from 'node:path';
import {atomic} from './native.mjs';

export const analysisCautions = `Analysis discipline: Ghidra swi() is a processor/decompiler operation, not evidence of an API resolver or IAT lookup. Inspect the underlying instructions and call/dataflow before assigning semantics. Empty function-name searches do not inspect the import directory and do not prove obfuscation or API absence; use ghidra_imports and exact call-site evidence. Compiler security-cookie/fail-fast patterns and .pdata unwind metadata alone do not establish anti-tamper behavior or C++ exception handling. Unresolved branches and RWX sections are leads, not proof of a particular protection scheme. Retain hypotheses as unresolved, never as prerequisites asserted to be facts.`;

// Narrow review checks for observed failure modes, NOT a general semantic verifier.
export function checkpointWarnings(text){
 const issues=new Set();
 for(const claim of text.split(/\n|[.!?]\s+/)){
  if(/does not|do not|not evidence|not establish|unproven|unresolved|cannot|must not|incorrect|retract|not proof/i.test(claim))continue;
  if(/swi\s*\(/i.test(claim)&&/IAT|API.{0,35}(lookup|resol|ordinal)|(?:lookup|resol).{0,35}API/i.test(claim))issues.add('swi_to_api: inspect instruction bytes; swi() alone is not an API/IAT resolver');
  if(/(?:no|zero|0|absen|lack).{0,100}(?:symbol|function|name|import)|(?:symbol|function|name).{0,100}(?:zero|0|absen|lack)/i.test(claim)&&/(?:due to|therefore|indicat|consistent with|must|is through|via).{0,100}obfuscat|obfuscat.{0,60}(?:resol|lookup)/i.test(claim))issues.add('names_to_obfuscation: function-name searches do not establish import absence or obfuscated resolution');
  if(/\.pdata/i.test(claim)&&/C\+\+.{0,20}(?:EH|exception)/i.test(claim))issues.add('unwind_to_cpp: unwind metadata alone does not establish C++ EH');
  if(/(?:2b992ddfa232|security.cookie)/i.test(claim)&&/anti.reentry|anti.tamper|obfuscation indicator/i.test(claim))issues.add('cookie_to_protection: validate compiler/runtime initialization before asserting protection');
 }
 return [...issues];
}
export function checkpointOnly(payload){
 // LM Studio supports string choices, not the named-function object form.
 // Requiring a call with exactly one exposed tool preserves the same restriction.
 return {...payload,tools:(payload.tools??[]).filter(t=>t.function?.name==='question_checkpoint'),tool_choice:'required',messages:[...(payload.messages??[]),{role:'user',content:'The analysis budget is ending. Invoke question_checkpoint now through the actual tool interface. Use partial if unresolved, cite exact receipt paths, and retain a precise next action. Do not output XML/tool markup or perform further inspections.'}]};
}
export function preservePartial(queue,config,reason,draft=''){
 const current=queue.read().questions.find(q=>q.id===config.questionId);
 if(current?.status!=='active')return false;
 atomic(path.join(config.state,'unsubmitted-draft.json'),{reason,draft:draft.slice(0,24000),trusted:false,not_executed:true});
 const dir=path.join(config.state,'tool-results');
 const refs=fs.existsSync(dir)?fs.readdirSync(dir).filter(f=>f.endsWith('.json')).slice(-12).map(f=>path.join(dir,f)):[];
 queue.checkpoint(config.questionId,{status:'partial',summary:current.summary||'Controller checkpoint: this batch ended without a validated model checkpoint. Native results are retained for review; no new interpretation has been accepted.',evidence:current.evidence.length?current.evidence.map(e=>e.path):refs,failed_approaches:[...current.failed_approaches.slice(-10),reason],next_action:'Review the previous batch tool-results and unsubmitted-draft.json as untrusted material. Validate instruction-level interpretations, then continue the question or decompose it.'});
 atomic(path.join(config.state,'batch-checkpoint.json'),{question:config.questionId,queue_revision:queue.read().revision,kind:'controller_partial_checkpoint',reason,independently_verified:false});
 return true;
}
