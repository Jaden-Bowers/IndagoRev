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
const names=recipe==='config'?(win?['RegOpenKeyExW','RegQueryValueExW','GetEnvironmentVariableW']:['getenv','fopen','access','stat']):recipe==='network'?(win?['socket','accept','bind','listen','connect','send','recv','sendto','recvfrom','shutdown','closesocket','WSASend','WSARecv']:['socket','accept','accept4','bind','listen','connect','send','recv','sendto','recvfrom','shutdown','close']):recipe==='io'
  ? (win?['CreateFileW','ReadFile','WriteFile','CloseHandle','connect','send','recv']:['open','openat','read','write','close','connect','send','recv'])
  : recipe==='code' ? (win?['VirtualAlloc','VirtualProtect']:['mmap','mprotect']) : [];
const installed=new Map();
function installHooks(module) { for(const api of names) {
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
        emit(event);
      },
      onLeave(retval) {
        if(!this.active||limited) return;
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
    installHooks(m); },
  onRemoved(m) { emit({kind:'module_unloaded',instance:modules.get(m.base.toString()),base:m.base.toString()}); modules.delete(m.base.toString());
    for(const [key,hook] of installed)if(hook.address.compare(m.base)>=0&&hook.address.compare(m.base.add(m.size))<0){try{hook.listener.detach();}catch(e){}installed.delete(key);} }
});
installHooks(null);
emit({kind:'recipe_ready',recipe,coverage:'selected user-space exports; no direct syscall, child or pre-install coverage',observer_effect:'Frida hooks alter code and timing; cost not calibrated'});
