import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {ToolRegistry,validate,object,string,integer} from '../tool-registry.mjs';
import {ToolResults} from '../tool-results.mjs';
test('registry rejects duplicate contracts and schema validator rejects transport injection',()=>{
 const r=new ToolRegistry(),e={name:'test',group:'static',effect:'read',description:'test',route:{kind:'analysis',backend:'xair',operation:'inventory'},schema:object({limit:integer(1,10)},[])};r.add(e);assert.throws(()=>r.add(e));
 assert.throws(()=>validate(e.schema,{project:'other'}));assert.throws(()=>validate(e.schema,{limit:11}));validate(e.schema,{limit:3});
 assert.equal(r.coverage({backends:[{name:'xair',available:true,operations:['inventory','cfg']}]} )[1].status,'advanced-only');
});
test('bounded result preserves partial verdict and supports exact persisted paging',t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'indago-results-'));t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 const results=new ToolResults(dir),data={status:'partial',evidence_ids:['ev1'],data:{native_verdict:'timeout',text:'x'.repeat(20000)}};
 const result=results.save('decompile',{data},{artifact:'abc'}),shown=JSON.parse(result.content[0].text);
 assert.equal(shown.status,'partial');assert.equal(shown.native_verdict,'timeout');assert.equal(shown.preview_truncated,true);
 const rest=results.read(shown.result_id,12000,16000);assert.equal(shown.preview+rest.text,JSON.stringify(data.data));
 assert.throws(()=>results.read('../secret'));assert.deepEqual(rest.binding,{artifact:'abc'});
});
