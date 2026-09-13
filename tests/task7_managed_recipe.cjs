// Deterministic Frida contract simulation; not a claim of live Mono coverage.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const events=[],hooks=new Map();const p=n=>({toString:()=>String(n),isNull:()=>n===0,compare:()=>0,add:()=>p(n),readPointer:()=>p(1),readUtf8String:()=> 'FixtureMethod'});
const nativeExports={mono_runtime_invoke:p(1),mono_compile_method:p(2),mono_method_get_token:p(3),mono_method_get_name:p(4)};
const moduleInfo={name:'libmonosgen-2.0.so',base:p(1000),size:4096,path:'/fixture/mono',findExportByName:name=>nativeExports[name]||null};
const context={recipe:'managed',budget:32,send:x=>events.push(x),Process:{id:1,platform:'linux',getCurrentThreadId:()=>1,attachThreadObserver:()=>{},attachModuleObserver:o=>o.onAdded(moduleInfo)},Module:{findGlobalExportByName:()=>null},Interceptor:{attach:(address,callbacks)=>{hooks.set(address.toString(),callbacks);return {detach(){}};}},NativeFunction:function(address){return ()=>address.toString()==='3'?0x06000001:p(100);}};
vm.runInNewContext(fs.readFileSync('workers/frida/recipes.js','utf8'),context,{timeout:1000});
for(const address of ['1','2']){const hook=hooks.get(address),state={};hook.onEnter.call(state,[p(10),p(0),p(0),p(11)]);hook.onLeave.call(state,p(55));}
assert(events.some(e=>e.kind==='managed_method_enter'&&e.metadata_token==='0x6000001'));
assert(events.some(e=>e.kind==='managed_method_leave'&&e.exception_observed===true));
assert(events.some(e=>e.kind==='managed_jit_result'&&e.result_contents_collected===false));
assert(events.every(e=>!e.verified_solve));console.log('managed invoke/JIT/exception recipe contract passed; simulated runtime');
