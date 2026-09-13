'use strict';
// Fixed observation recipes; no replacement or arbitrary script endpoint.
let sequence=0, limited=false, serial=0;
const modules=new Map(), threads=new Map();
const sockets=new Map();
const socketApis=new Set(['connect','send','recv','sendto','recvfrom','WSASend','WSARecv','accept','accept4','bind','listen','shutdown']);
function socketState(handle,origin,replace) {
  const key=handle.toString();
  if(!replace&&sockets.has(key))return sockets.get(key);
  if(!sockets.has(key)&&sockets.size>=1024)return {handle:key,instance:null,origin:'tracking_limit',identity_complete:false};
  const state={handle:key,instance:token('socket_'),origin,creation_observed:origin==='created'||origin==='accepted',identity_complete:false,
    validity:origin==='created'||origin==='accepted'?'creation_api_succeeded':'candidate_handle_only',
    coverage:'selected API calls in this collection; aliases, inheritance and missed calls are not resolved'};
  sockets.set(key,state);return state;
}
function emit(record) {
  if(sequence>=budget) {
    if(!limited) { limited=true; send({kind:'collection_limit',partial:true}); }
    return;
  }
  send(Object.assign({sequence:++sequence,timestamp_ms:Date.now(),
    clock_domain:'target wall clock',pid:Process.id,thread_id:Process.getCurrentThreadId()},record));
}
function token(prefix) { return prefix+(++serial); }
function hexBytes(address,size) {
  return Array.from(new Uint8Array(address.readByteArray(size)),b=>b.toString(16).padStart(2,'0')).join('');
}
function sockaddrLength(value) {
  // Winsock uses signed int lengths; Linux socklen_t is unsigned 32-bit.
  const size=win?value.toInt32():value.toUInt32();
  if(size<0)throw new Error('negative sockaddr length');
  return size;
}
function returnedSockaddr(event,address,length,capacity) {
  if(capacity===undefined) {event.sockaddr_read_status='entry_capacity_unavailable';return;}
  const returned=length.readU32();
  if(win&&returned>0x7fffffff) {event.sockaddr_read_status='negative_returned_length';return;}
  const size=Math.min(returned,capacity,128);
  event.sockaddr_capacity=capacity;event.sockaddr_returned_length=returned;
  event.sockaddr_hex=hexBytes(address,size);event.sockaddr_truncated=returned>size;
  event.sockaddr_read_status='bounded_by_entry_capacity_and_returned_length';
}
function capture(address,requested,api) {
  if(limited || requested<=0) return;
  const size=Math.min(requested,4096);
  try { emit({kind:'code_capture',api,address:address.toString(),requested,size,
    hex:hexBytes(address,size),status:size===requested?'completed':'partial',
    arch:Process.arch==='ia32'?'x86':Process.arch,
    coherence:'asynchronous API-return read; other threads may write concurrently'}); }
  catch(e) { emit({kind:'capture_unavailable',api,address:address.toString(),diagnostic:String(e).slice(0,256)}); }
}
Process.attachThreadObserver({
  onAdded(t) { const instance=token('thread_'); threads.set(t.id,instance); emit({kind:'thread_created',native_thread_id:t.id,instance}); },
  onRemoved(t) { emit({kind:'thread_exited',native_thread_id:t.id,instance:threads.get(t.id)}); threads.delete(t.id); }
});
const win=Process.platform==='windows';
// Bounded input provenance. Only completed synchronous stdin reads and observed
// copies are admitted. Re-check the bytes at each use; arbitrary writes are not
// modeled and a changed range is never silently treated as an input alias.
const inputSpans=[];let stdinOffset=0,stdinInFlight=0,stdinOrderKnown=true;
let stdinHandle=null;
if(recipe==='input'&&win)try {
  const address=Module.findGlobalExportByName('GetStdHandle');
  if(address)stdinHandle=new NativeFunction(address,'pointer',['int'])(-10);
}catch(e){}
function inputSpan(address,count) {
  if(count<=0||count>256)return null;
  for(let i=inputSpans.length-1;i>=0;--i){const s=inputSpans[i];
    if(address.compare(s.address)>=0&&address.add(count).compare(s.address.add(s.hex.length/2))<=0){
      const delta=Number(address.sub(s.address).toString());
      if(hexBytes(address,count)!==s.hex.slice(delta*2,(delta+count)*2))return null;
      return {source:'stdin',offset:s.offset+delta,size:count,input_id:s.id,copy_chain:s.chain.slice()};}}
  return null;
}
function rememberInput(address,hex,offset,id,chain) {
  for(let i=inputSpans.length-1;i>=0;--i)if(address.compare(inputSpans[i].address.add(inputSpans[i].hex.length/2))<0&&address.add(hex.length/2).compare(inputSpans[i].address)>0)inputSpans.splice(i,1);
  if(inputSpans.length>=64)inputSpans.shift();inputSpans.push({address,hex,offset,id,chain});
}
function inputEnter(call,api,args) {
  if(recipe!=='input')return;
  if((api==='read'&&args[0].toInt32()===0)||(api==='ReadFile'&&stdinHandle&&args[0].equals(stdinHandle)&&args[4].isNull())) {
    call.inputRelevant=true;call.stdinRead=true;if(++stdinInFlight>1){stdinOrderKnown=false;inputSpans.length=0;}
  }
  if(api==='memcpy'||api==='memmove') {
    const size=Number(args[2].toString());if(Number.isSafeInteger(size)&&size>0&&size<=256){call.inputCopy=inputSpan(args[1],size);if(call.inputCopy){call.inputRelevant=true;call.copyHex=hexBytes(args[1],size);}}return;
  }
  if(api!=='memcmp')return;
  const count=Number(args[2].toString());if(!Number.isSafeInteger(count)||count<1||count>256)return;
  const left=inputSpan(args[0],count),right=inputSpan(args[1],count);
  if(Boolean(left)===Boolean(right))return;
  call.inputRelevant=true;
  call.inputComparison={kind:'input_comparison',api,call_id:call.call,caller:call.returnAddress.toString(),
    input:left||right,input_side:left?'left':'right',input_hex:hexBytes(left?args[0]:args[1],count),
    expected_hex:hexBytes(left?args[1]:args[0],count),address:(left?args[0]:args[1]).toString(),
    mapping:'completed stdin read, observed copies, byte equality checked at comparison',
    limitation:'selected API coverage; not a whole-process write or control-dependence proof'};
}
function inputLeave(call,api,retval) {
  if(recipe!=='input')return;
  const a=call.args;
  if(call.stdinRead) {
    --stdinInFlight;
    const count=api==='read'?retval.toInt32():(!retval.isNull()&&!a[3].isNull()?a[3].readU32():0);
    if(count>0&&count<=a[2].toUInt32()) {
      const offset=stdinOffset;stdinOffset+=count;
      if(count<=256&&stdinOrderKnown){const hex=hexBytes(a[1],count),id=token('input_');rememberInput(a[1],hex,offset,id,[]);
        emit({kind:'input_delivery',input_id:id,source:'stdin',offset,address:a[1].toString(),hex,call_id:call.call,api,complete:true});}
    }
  }
  if(call.inputCopy&&retval.equals(a[0])&&hexBytes(a[0],call.copyHex.length/2)===call.copyHex) {
    const s=call.inputCopy;if(s.copy_chain.length<8)rememberInput(a[0],call.copyHex,s.offset,s.input_id,s.copy_chain.concat(call.call));
  }
  if(call.inputComparison){
    call.inputComparison.return_value=retval.toInt32();
    call.inputComparison.arch=Process.arch==='ia32'?'x86':Process.arch==='x64'?'x64':'unsupported';
    call.inputComparison.caller_code={address:call.returnAddress.toString(),hex:hexBytes(call.returnAddress,64)};
    call.inputComparison.registers={};
    const names=Process.arch==='ia32'?['eax','ebx','ecx','edx','esi','edi','ebp','esp']:['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15'];
    for(const name of names)if(call.context[name]!==undefined)call.inputComparison.registers[name]=call.context[name].toString();
    call.inputComparison.memory=[];
    try {
      const m=Process.findModuleByAddress(call.returnAddress);
      if(m)for(const range of m.enumerateRanges('rw-').slice(0,2)) {
        const size=Math.min(range.size,4096);call.inputComparison.memory.push({address:range.base.toString(),hex:hexBytes(range.base,size)});
      }
    }catch(e){call.inputComparison.memory_status='partial';}
    emit(call.inputComparison);
  }
}
const names=recipe==='config'?(win?['RegOpenKeyExW','RegQueryValueExW','GetEnvironmentVariableW']:['getenv','fopen','access','stat']):recipe==='network'?(win?['socket','accept','bind','listen','connect','send','recv','sendto','recvfrom','shutdown','closesocket','WSASend','WSARecv']:['socket','accept','accept4','bind','listen','connect','send','recv','sendto','recvfrom','shutdown','close']):recipe==='io'
  ? (win?['CreateFileW','ReadFile','WriteFile','CloseHandle','connect','send','recv']:['open','openat','read','write','close','connect','send','recv'])
  : recipe==='code' ? (win?['VirtualAlloc','VirtualProtect']:['mmap','mprotect'])
  : recipe==='input' ? (win?['ReadFile','memcpy','memmove','memcmp']:['read','memcpy','memmove','memcmp']) : [];
const installed=new Map();
function installManaged(module) {
  if(recipe!=='managed'||!module)return;
  if(/(?:coreclr|clr\.dll|mono)/i.test(module.name))emit({kind:'managed_runtime_module',runtime_module:module.name,base:module.base.toString(),coverage:'Mono exported invoke/JIT hooks only; CLR/CoreCLR EventPipe not implemented'});
  if(!/mono/i.test(module.name))return;
  const exported=name=>module.findExportByName(name);
  for(const api of ['mono_runtime_invoke','mono_compile_method'])try {
    const address=exported(api);if(!address)continue;
    const key=api+'@'+address;if(installed.has(key))continue;
    const tokenAddress=exported('mono_method_get_token'),nameAddress=exported('mono_method_get_name');
    const getToken=tokenAddress?new NativeFunction(tokenAddress,'uint32',['pointer']):null;
    const getName=nameAddress?new NativeFunction(nameAddress,'pointer',['pointer']):null;
    const listener=Interceptor.attach(address,{
      onEnter(args){this.active=!limited;if(!this.active)return;this.call=token('managed_');this.method=args[0];this.exception=api==='mono_runtime_invoke'?args[3]:null;
        const record={kind:'managed_method_enter',api,call_id:this.call,method_handle:this.method.toString(),runtime_module:module.name,identity_scope:'runtime session; metadata token alone does not identify an assembly'};
        try{if(getToken)record.metadata_token='0x'+getToken(this.method).toString(16);if(getName)record.method_name=getName(this.method).readUtf8String(256);}catch(e){record.identity_partial=true;}
        emit(record);
      },
      onLeave(value){if(!this.active||limited)return;const record={kind:api==='mono_compile_method'?'managed_jit_result':'managed_method_leave',api,call_id:this.call,method_handle:this.method.toString(),result_handle:value.toString(),result_contents_collected:false};
        if(api==='mono_runtime_invoke'&&this.exception&&!this.exception.isNull())try{record.exception_observed=!this.exception.readPointer().isNull();}catch(e){record.exception_status='unavailable';}
        emit(record);
      }
    });installed.set(key,{address,listener});emit({kind:'hook_installed',api,address:address.toString()});
  }catch(e){emit({kind:'hook_unavailable',api,diagnostic:String(e).slice(0,256)});}
}
function installHooks(module) { for(const api of names) {
  if(recipe==='input'&&win&&api==='ReadFile'&&module&&module.name.toLowerCase()!=='kernelbase.dll')continue;
  if(recipe==='input'&&win&&api==='ReadFile'&&!module&&Array.from(installed.keys()).some(k=>k.startsWith('ReadFile@')))continue;
  try {
    let address=module?module.findExportByName(api):Module.findGlobalExportByName(api);
    if(address===null && win&&!module) for(const m of Process.enumerateModules()) { address=m.findExportByName(api); if(address!==null) break; }
    if(address===null) { if(!module)emit({kind:'hook_unavailable',api,diagnostic:'export not loaded at recipe installation'}); continue; }
    const hookKey=api+'@'+address.toString();if(installed.has(hookKey))continue;
    const listener=Interceptor.attach(address,{
      onEnter(args) {
        this.active=!limited; if(!this.active) return;
        this.args=[args[0],args[1],args[2],args[3],args[4],args[5]]; this.call=token('call_'); this.start=Date.now();
        const event={kind:'api_enter',api,call_id:this.call,thread_instance:threads.get(this.threadId),
          caller:this.returnAddress.toString(),args:this.args.slice(0,4).map(x=>x.toString())};
        if(socketApis.has(api)) {
          if(args[0].equals(ptr(-1))||(!win&&args[0].toInt32()<0))event.socket_argument_invalid=true;
          else this.socket=socketState(args[0],'first_observed',false);
        }
        else if(api==='close'||api==='closesocket')this.socket=sockets.get(args[0].toString());
        if(this.socket)event.socket=this.socket;
        if(['WSASend','WSARecv'].includes(api))event.network_completeness='overlapped/scatter-gather completion not modeled';
        try {
          if(api==='CreateFileW') event.path=args[0].readUtf16String(256);
          if(api==='open'||api==='openat') event.path=args[api==='open'?0:1].readUtf8String(256);
          if(['getenv','fopen','access','stat'].includes(api))event.name=args[0].readUtf8String(256);
          if(api==='GetEnvironmentVariableW')event.name=args[0].readUtf16String(256);
          if(['RegOpenKeyExW','RegQueryValueExW'].includes(api))event.name=args[1].readUtf16String(256);
          if(['write','send','sendto','WriteFile'].includes(api)) {
            const requested=win&&['send','sendto'].includes(api)?args[2].toInt32():Number(args[2].toString());
            if(Number.isSafeInteger(requested)&&requested>=0){event.buffer_hex=hexBytes(args[1],Math.min(requested,64));event.requested_bytes=requested;event.buffer_truncated=requested>64;}
            else event.argument_read_status='length_not_safely_representable';
          }
          if(api==='connect'||api==='bind') { const size=sockaddrLength(args[2]);event.sockaddr_hex=hexBytes(args[1],Math.min(size,128));event.sockaddr_capacity=size;event.sockaddr_truncated=size>128; }
          if(api==='sendto') { const size=sockaddrLength(args[5]);event.sockaddr_hex=hexBytes(args[4],Math.min(size,128));event.sockaddr_capacity=size;event.sockaddr_truncated=size>128; }
          if(api==='accept'||api==='accept4'||api==='recvfrom') {
            const address=args[api==='recvfrom'?4:1], length=args[api==='recvfrom'?5:2];
            if(!address.isNull()&&!length.isNull()) {
              const capacity=length.readU32();
              if(win&&capacity>0x7fffffff)event.sockaddr_read_status='negative_entry_capacity';
              else {this.sockaddrCapacity=capacity;event.sockaddr_capacity=capacity;}
            }
          }
        } catch(e) { event.argument_read_status='unavailable'; }
        try{inputEnter(this,api,args);}catch(e){event.input_mapping_status='unavailable';}
        if(recipe==='input'&&!this.inputRelevant)return;
        emit(event);
      },
      onLeave(retval) {
        if(!this.active||limited||(recipe==='input'&&!this.inputRelevant)) return;
        const event={kind:'api_leave',api,call_id:this.call,return_value:retval.toString(),
          thread_instance:threads.get(this.threadId),duration_ms:Date.now()-this.start,
          errno:win?undefined:this.errno,last_error:win?this.lastError:undefined};
        if(this.socket)event.socket=this.socket;
        if(api==='socket'||api==='accept'||api==='accept4') {
          const succeeded=win?!retval.equals(ptr(-1)):retval.toInt32()>=0;
          if(succeeded) {
            event.socket=socketState(retval,api==='socket'?'created':'accepted',true);
            event.socket_event=api==='socket'?'created':'accepted';
            if(this.socket)event.listener_socket=this.socket;
          } else event.socket_event='creation_failed';
        }
        if((api==='close'||api==='closesocket')&&this.socket) {
          if(retval.toInt32()===0) {
            const current=sockets.get(this.socket.handle);
            event.socket_event='close_api_success';
            if(current&&current.instance===this.socket.instance)sockets.delete(this.socket.handle);
            else event.socket_generation_race=true;
          } else event.socket_event='close_result_uncertain';
        }
        if(api==='connect')event.network_outcome=retval.toInt32()===0?'connect_api_success':'failed_or_pending';
        if(['send','recv','sendto','recvfrom'].includes(api)) {
          const count=win?retval.toInt32():Number(retval.toString());
          if((win&&count<0)||retval.equals(ptr(-1)))event.network_outcome='transfer_api_error';
          else if(Number.isSafeInteger(count)&&count>=0){event.transferred_bytes=count;event.network_outcome='api_returned_count';event.delivery_proven=false;}
          else event.network_outcome='return_count_not_safely_representable';
        }
        if(win&&(socketApis.has(api)||api==='socket'||api==='closesocket'))event.error_semantics='last_error is not WSAGetLastError; Winsock error code not collected';
        if(['WSASend','WSARecv'].includes(api))event.network_completeness='overlapped/scatter-gather completion not modeled';
        try { if(['read','recv','recvfrom'].includes(api)) {
          const count=win?retval.toInt32():Number(retval.toString());
          const requested=win?this.args[2].toInt32():Number(this.args[2].toString());
          if(Number.isSafeInteger(count)&&count>0&&Number.isSafeInteger(requested)&&requested>=0){const captured=Math.min(count,requested,64);event.buffer_hex=hexBytes(this.args[1],captured);event.buffer_truncated=count>captured;}
          if(api==='recvfrom'&&event.network_outcome==='api_returned_count'&&!this.args[4].isNull()&&!this.args[5].isNull())returnedSockaddr(event,this.args[4],this.args[5],this.sockaddrCapacity);
        } }
        catch(e) { event.return_read_status='unavailable'; }
        if((api==='accept'||api==='accept4')&&event.socket_event==='accepted') {
          try { if(!this.args[1].isNull()&&!this.args[2].isNull())returnedSockaddr(event,this.args[1],this.args[2],this.sockaddrCapacity); }
          catch(e){event.return_read_status='unavailable';}
        }
        emit(event);
        try{inputLeave(this,api,retval);}catch(e){emit({kind:'input_mapping_unavailable',api,diagnostic:String(e).slice(0,256)});}
        if(recipe!=='code') return;
        const a=this.args;
        if(api==='VirtualProtect'&&!retval.isNull()&&(a[2].toUInt32()&0xf0)) capture(a[0],a[1].toUInt32(),api);
        if(api==='VirtualAlloc'&&!retval.isNull()&&(a[3].toUInt32()&0xf0)) capture(retval,a[1].toUInt32(),api);
        if(api==='mprotect'&&retval.toInt32()===0&&(a[2].toUInt32()&4)) capture(a[0],a[1].toUInt32(),api);
        if(api==='mmap'&&!retval.equals(ptr(-1))&&(a[2].toUInt32()&4)) capture(retval,a[1].toUInt32(),api);
      }
    });
    installed.set(hookKey,{address,listener});
    emit({kind:'hook_installed',api,address:address.toString()});
  } catch(e) { emit({kind:'hook_unavailable',api,diagnostic:String(e).slice(0,256)}); }
}}
// Register only after the hook state is initialized. Install synchronously in
// onAdded so a caller immediately using a newly loaded API is not missed.
Process.attachModuleObserver({
  onAdded(m) { const instance=token('module_'); modules.set(m.base.toString(),instance);
    emit({kind:'module_loaded',instance,base:m.base.toString(),size:m.size,path:m.path.slice(0,2048)});
    installHooks(m); installManaged(m); },
  onRemoved(m) { emit({kind:'module_unloaded',instance:modules.get(m.base.toString()),base:m.base.toString()}); modules.delete(m.base.toString());
    for(const [key,hook] of installed)if(hook.address.compare(m.base)>=0&&hook.address.compare(m.base.add(m.size))<0){try{hook.listener.detach();}catch(e){}installed.delete(key);} }
});
installHooks(null);
emit({kind:'recipe_ready',recipe,coverage:'selected user-space exports; no direct syscall, child or pre-install coverage',observer_effect:'Frida hooks alter code and timing; cost not calibrated'});
