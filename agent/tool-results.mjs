import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {atomic,redactControlSecrets} from './native.mjs';

export class ToolResults {
 constructor(state){this.dir=path.join(state,'tool-results');}
 save(name,result,binding){
  const id=crypto.randomUUID();const data=redactControlSecrets(result.data??result);
  const full={schema:'indago.tool-result.v1',id,tool:name,binding,receipt:result.receipt??null,data};
  atomic(path.join(this.dir,id+'.json'),full);
  return this.present(full);
 }
 present(full){
  const d=full.data,body=d.data??d.result?.data??d.result??d;
  const summary={result_id:full.id,tool:full.tool,binding:full.binding,status:d.status??body.status??'completed',partial:!!(d.partial||body.partial||d.completeness==='partial'||d.status==='partial'||body.status==='partial'),native_verdict:body.native_verdict??body.decompilation?.native_verdict,evidence_ids:d.evidence_ids??d.result?.evidence_ids??[],pagination:body.pagination??null,receipt:full.receipt};
  // Keep complete status/identity outside the bounded preview. Never truncate the JSON envelope.
  let preview=JSON.stringify(body);const truncated=preview.length>12000;
  if(truncated)preview=preview.slice(0,12000);
  const envelope={...summary,preview:truncated?preview:body,preview_truncated:truncated,more:truncated?{tool:'evidence_read',result_id:full.id,offset:12000}:null};
  return {content:[{type:'text',text:JSON.stringify(envelope)}],details:summary,isError:['failed','invalid_request','capability_blocked','unavailable','timeout','unsupported','cancelled','interrupted','transport_error'].includes(summary.status)};
 }
 read(id,offset=0,limit=8000){
  if(!/^[a-f0-9-]{36}$/.test(id))throw Error('Use a returned result_id');
  if(!Number.isSafeInteger(offset)||offset<0||!Number.isSafeInteger(limit)||limit<1||limit>16000)throw Error('Invalid evidence page');
  const full=JSON.parse(fs.readFileSync(path.join(this.dir,id+'.json'),'utf8')),text=JSON.stringify(full.data.data??full.data.result?.data??full.data.result??full.data);
  return {result_id:id,binding:full.binding,receipt:full.receipt,offset,text:text.slice(offset,offset+limit),next_offset:offset+limit<text.length?offset+limit:null,offset_unit:'UTF-16 code units; persisted original result, not a freshness assertion'};
 }
}
