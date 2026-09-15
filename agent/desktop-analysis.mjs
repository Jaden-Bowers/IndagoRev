import fs from 'node:fs';
import path from 'node:path';
import {atomic} from './native.mjs';

// Persist bounded pages, not one unbounded IPC response. A checkpoint survives cancellation.
export async function collect(native, operation, address, signal) {
 const items=[], evidence=new Set(), seen=new Set();let cursor, first, incomplete=false;
 for(let page=0;page<1000;page++){
  signal?.throwIfAborted();
  const {data:r}=await native.analyze({backend:'ghidra',operation,address,arguments:cursor?{cursor}:{}},signal);
  const d=r.data??{};first??=d;
  if(d.program_revision!==first.program_revision)throw Error('Program changed during listing; reload');
  for(const e of r.evidence_ids??[])evidence.add(e);
  const list=operation==='tokens'?d.decompilation?.tokens:d[operation==='assembly'?'instructions':operation];
  if(!Array.isArray(list))throw Error(`${operation}: ${r.diagnostic??d.diagnostic??r.status??'missing collection'}`);
  items.push(...list);
  const p=d.pagination??{};cursor=p.next_cursor;
  incomplete ||= !!d.analysis_timed_out || !!p.continuation_blocked;
  if(!cursor){incomplete ||= !!p.scan_may_be_incomplete || (r.status!=='completed'&&r.status!=='partial');break;}
  if(seen.has(cursor)||page===999)throw Error('Listing continuation did not converge');seen.add(cursor);
 }
 return {data:first,items,evidence_ids:[...evidence],incomplete};
}
export function makeListing(file, digest, address, kind, collected){
 const d=collected.data;let text='',tokens=[];
 if(kind==='tokens'){text=d.decompilation?.rendered_c??d.decompilation?.decompiled_c??'';tokens=collected.items;}
 else for(const i of collected.items){const start=text.length;text+=`${i.address}  ${i.text}\n`;tokens.push({rendered_offset:start,rendered_end:text.length,min_address:i.address,max_address:i.address});}
 const incomplete=collected.incomplete||!!d.decompilation?.text_truncated||(kind==='tokens'&&d.decompilation?.native_verdict!=='completed');
 if(!text)text=`/* ${kind}: ${d.decompilation?.diagnostic||'No listing available'} */\n`;
 return {file,hash:digest,address,kind,backend:'ghidra',revision:d.program_revision,text,tokens,evidence_ids:collected.evidence_ids,incomplete};
}
export function initialFunction(functions, entry=''){
 return functions.find(f=>/^(?:_?main|wmain|WinMain|wWinMain)$/i.test(f.name))?.entry
  ?? functions.find(f=>f.entry===entry)?.entry ?? entry ?? functions[0]?.entry ?? '';
}
export function cacheFile(state,digest){return path.join(state,'programs',digest,'manifest.json');}
export function readManifest(state,digest){try{
 const file=cacheFile(state,digest);if(fs.statSync(file).size>64*1024*1024)return null;
 const m=JSON.parse(fs.readFileSync(file,'utf8'));
 if(m.schema!==2||!Number.isInteger(m.revision)||m.revision<0||!Array.isArray(m.functions)||m.functions.length>100000||m.functions.some(f=>!/^0x[0-9a-f]+$/i.test(f.entry)))return null;
 if(!m.views||Object.keys(m.views).some(k=>!/^tokens-0x[0-9a-f]+$/i.test(k)))return null;
 if(m.assembly&&(!Array.isArray(m.assembly)||m.assembly.some(k=>!/^assembly-[0-9]+$/.test(k))))return null;
 return m;
}catch{return null;}}
export function saveManifest(state,digest,m){atomic(cacheFile(state,digest),m);}

export async function providerInfo(r,signal,fetcher=fetch){
 const endpoint=r.endpoint||'http://127.0.0.1:1234/v1',url=new URL(endpoint);
 if(!['http:','https:'].includes(url.protocol)||url.username||url.password)throw Error('Invalid provider URL');
 if(url.protocol==='http:'&&!['localhost','127.0.0.1','[::1]'].includes(url.hostname))throw Error('Remote providers require HTTPS');
 const headers={};if(r.apiKeyEnv&&process.env[r.apiKeyEnv])headers.Authorization=`Bearer ${process.env[r.apiKeyEnv]}`;
 const lm=(r.provider??'lmstudio')==='lmstudio';
 const modelsUrl=lm?new URL('/api/v1/models',url):new URL(endpoint.replace(/\/$/,'')+'/models');
 try{
  const res=await fetcher(modelsUrl,{headers,signal:AbortSignal.any([signal??new AbortController().signal,AbortSignal.timeout(5000)]),redirect:'error'});
  if(!res.ok)throw Error(`HTTP ${res.status}`);
  const body=await res.json();let context=null;
  if(lm){for(const m of body.models??[])for(const instance of m.loaded_instances??[])if(instance.id===r.model||m.key===r.model)context=instance.config?.context_length;}
  else {const m=(body.data??[]).find(m=>m.id===r.model);context=m?.context_length??m?.context_window;}
  if(!Number.isInteger(context)||context<4096||context>2097152)return {contextTokens:null,source:'Provider did not report a usable context limit'};
  return {contextTokens:context,source:lm?'LM Studio loaded-instance configuration':'Provider model metadata'};
 }catch(e){if(signal?.aborted)throw e;return {contextTokens:null,source:`Context unavailable: ${e.message}`};}
}
