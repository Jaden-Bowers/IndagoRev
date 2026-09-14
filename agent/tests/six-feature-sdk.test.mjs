import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {launch} from '../cli.mjs';

test('Pi direct strings, compact state, successful stagnation and final repair', {skip:!process.env.INDAGO_TEST_EXE,timeout:30000},async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'indago-six-sdk-'));
  fs.writeFileSync(path.join(dir,'sample.txt'),'synthetic evidence');
  const requests=[];
  const steps=[
    ['artifact_inspect',{operation:'strings',file:'sample.txt'}],
    ['investigation_update',{facts:['sample.txt contains synthetic evidence'],candidate:'example',obligation:'Not a target acceptance proof'}],
    ['bash',{command:'echo constant'}],['bash',{command:'echo constant'}],['bash',{command:'echo constant'}],
  ];
  const server=http.createServer(async(req,res)=>{
    let raw='';for await(const b of req)raw+=b;
    const body=JSON.parse(raw);requests.push(body);const n=requests.length,step=steps[n-1];
    const delta=step?{role:'assistant',tool_calls:[{index:0,id:'six'+n,type:'function',function:{name:step[0],arguments:JSON.stringify(step[1])}}]}:{role:'assistant',content:n===6?'<tool_call><function=bash>':'Candidate example; acceptance remains unresolved.'};
    res.writeHead(200,{'Content-Type':'text/event-stream'});
    res.end('data: '+JSON.stringify({id:'six',model:body.model,choices:[{index:0,delta,finish_reason:step?'tool_calls':'stop'}],usage:{prompt_tokens:30,completion_tokens:10,total_tokens:40}})+'\n\ndata: [DONE]\n\n');
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  try {
    const state=path.join(dir,'state');
    const r=await launch({exe:process.env.INDAGO_TEST_EXE,cwd:dir,target:'sample.txt',state,mode:'knowledge',endpoint:`http://127.0.0.1:${server.address().port}/v1`,model:'mock',prompt:'Synthetic feature contract.',maxGenerations:7,timeout:25000});
    assert.equal(r.code,0);assert.equal(requests.length,7);
    assert(requests[0].tools.some(t=>t.function.name==='artifact_inspect'));
    assert(JSON.stringify(requests[2].messages).includes('Not a target acceptance proof'));
    assert(JSON.stringify(requests[5].messages).includes('Repeated unchanged inspection'));
    assert.equal(requests[6].tool_choice,'none');assert.equal(requests[6].tools,undefined);
    const unresolved=JSON.parse(fs.readFileSync(path.join(state,'unresolved.json')));
    assert.equal(unresolved.candidate,'example');
    assert.equal(unresolved.reason,'invalid_final_tool_markup');
    assert(fs.existsSync(path.join(state,'environment.json')));
  } finally {server.closeAllConnections();await new Promise(r=>server.close(r));}
});

test('queued length recovery cannot exceed budget after final synthesis',{skip:!process.env.INDAGO_TEST_EXE,timeout:30000},async()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'indago-budget-'));fs.writeFileSync(path.join(dir,'sample.txt'),'synthetic');
  let count=0;
  const server=http.createServer(async(req,res)=>{
    for await(const b of req){};const n=++count;
    const stop=n===1||n===3?'length':n===2?'tool_calls':'stop';
    const delta=stop==='tool_calls'?{role:'assistant',tool_calls:[{index:0,id:'budget',type:'function',function:{name:'read',arguments:JSON.stringify({path:'sample.txt'})}}]}:{role:'assistant',content:stop==='length'?'Partial':'Unresolved.'};
    res.writeHead(200,{'Content-Type':'text/event-stream'});res.end('data: '+JSON.stringify({id:'budget',choices:[{index:0,delta,finish_reason:stop}],usage:{prompt_tokens:10,completion_tokens:10,total_tokens:20}})+'\n\ndata: [DONE]\n\n');
  });
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  try{const r=await launch({exe:process.env.INDAGO_TEST_EXE,cwd:dir,target:'sample.txt',state:path.join(dir,'state'),mode:'knowledge',features:[],endpoint:`http://127.0.0.1:${server.address().port}/v1`,model:'mock',prompt:'Budget check',maxGenerations:4,timeout:20000});assert.equal(r.code,0);assert.equal(count,4);}finally{server.closeAllConnections();await new Promise(r=>server.close(r));}
});
