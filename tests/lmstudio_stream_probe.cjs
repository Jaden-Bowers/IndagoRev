// Diagnostic-only live request: saves bounded wire output, never executes tools.
const fs=require('node:fs'),path=require('node:path');
const source=process.argv[2];if(!source)throw Error('live summary path required');
const run=JSON.parse(fs.readFileSync(source,'utf8'));
const body={model:run.model,messages:run.controller.input_messages,
 tools:[{type:'function',function:{name:'investigate',description:'Select one bounded investigation decision.',parameters:{type:'object',additionalProperties:false,required:['kind','payload'],properties:{kind:{type:'string',enum:['analyze','retrieve','checkpoint','finish']},payload:{type:'object'}}}}}],tool_choice:'required',parallel_tool_calls:false,stream:true,stream_options:{include_usage:true},temperature:0,max_tokens:2048};
const nonstream=process.argv[3]==='nonstream';if(nonstream){body.stream=false;delete body.stream_options;}
(async()=>{
 const response=await fetch('http://127.0.0.1:1234/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body),signal:AbortSignal.timeout(60000)});
 let wire='';for await(const chunk of response.body){wire+=Buffer.from(chunk).toString('utf8');if(Buffer.byteLength(wire)>1048576)throw Error('Diagnostic wire budget exceeded');}
 const saved=path.join(path.dirname(source),`diagnostic-${Date.now()}-${nonstream?'nonstream.json':'stream.txt'}`);
 fs.writeFileSync(saved,wire,{flag:'wx'});
 if(nonstream){const r=JSON.parse(wire);console.log(JSON.stringify({http_status:response.status,choices:r.choices?.map(c=>({finish_reason:c.finish_reason,tools:c.message.tool_calls?.map(t=>({name:t.function?.name,argument_bytes:t.function?.arguments?.length})),content_bytes:c.message.content?.length,reasoning_bytes:c.message.reasoning_content?.length}))}));return;}
 const calls=[],finish=[];for(const line of wire.split('\n'))if(line.startsWith('data: ')&&!line.includes('[DONE]')){
  const event=JSON.parse(line.slice(6));for(const c of event.choices||[]){if(c.finish_reason)finish.push(c.finish_reason);for(const t of c.delta?.tool_calls||[])calls.push({index:t.index,id:t.id,name:t.function?.name,argument_bytes:t.function?.arguments?.length||0});}
 }
 console.log(JSON.stringify({http_status:response.status,finish,fragments:calls.filter(c=>c.id||c.name),tool_fragment_count:calls.length,wire_bytes:Buffer.byteLength(wire)}));
})().catch(e=>{console.error(e.message);process.exitCode=1;});
