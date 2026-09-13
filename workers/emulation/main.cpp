// SPDX-License-Identifier: GPL-2.0-only
#ifdef _WIN32
#define NOMINMAX
#endif
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
using J = nlohmann::json;
using U = std::uint64_t;
static void require(bool value, const char *message) { if (!value) throw std::runtime_error(message); }
static void ok(uc_err e) { if (e != UC_ERR_OK) throw std::runtime_error(uc_strerror(e)); }
static U number(const J &v) { require(v.is_number_unsigned() || (v.is_number_integer() && v.get<std::int64_t>() >= 0), "nonnegative integer required"); return v.get<U>(); }
static std::string read(const std::string &path, std::size_t maximum) {
  std::ifstream f(path, std::ios::binary); require(bool(f), "input missing");
  std::string out(maximum + 1, '\0'); f.read(out.data(), out.size()); out.resize(f.gcount());
  require(out.size() <= maximum, "input limit exceeded"); return out;
}
static std::string hex(const std::string &s) { std::string o; for (unsigned char c:s) {o += "0123456789abcdef"[c>>4]; o += "0123456789abcdef"[c&15];} return o; }
struct State {
  uc_engine *uc{}; J steps=J::array(), writes=J::array(), edges=J::array();
  std::map<U,U> visits; std::set<std::pair<U,U>> seen;
  U previous{}, count{}, limit{}, stop{}; bool have_previous{}, bounded{}, external{};
  std::string reason;
  J handlers=J::array(), handler_observations=J::array();
  std::map<std::size_t,J> active_handlers;
  std::map<std::string,int> registers;
  ~State(){if(uc)uc_close(uc);}
};
static void code(uc_engine *uc, U address, std::uint32_t size, void *opaque) {
  auto &s=*static_cast<State*>(opaque);
  auto snapshot=[&](const J &handler){
    J state{{"registers",J::object()}};
    for(const auto &name:handler.at("registers")){U value=0;const auto e=uc_reg_read(uc,s.registers.at(name.get<std::string>()),&value);if(e==UC_ERR_OK)state["registers"][name.get<std::string>()]=value;else state["partial"]=true;}
    if(handler.contains("virtual_state")){const auto &m=handler.at("virtual_state");std::string bytes(m.at("size").get<std::size_t>(),'\0');if(uc_mem_read(uc,m.at("address").get<U>(),bytes.data(),bytes.size())==UC_ERR_OK)state["virtual_state"]={{"address",m.at("address")},{"hex",hex(bytes)}};else state["partial"]=true;}
    return state;
  };
  for(std::size_t i=0;i<s.handlers.size();++i){const auto &h=s.handlers[i];
    if(h.at("exit").get<U>()==address&&s.active_handlers.contains(i)){
      if(s.handler_observations.size()<8)s.handler_observations.push_back({{"handler",i},{"entry",h.at("entry")},{"exit",address},{"before",s.active_handlers[i]},{"after",snapshot(h)},{"scope","one emulated traversal, not a generalized VM semantic summary"}});
      s.active_handlers.erase(i);
    }
    if(h.at("entry").get<U>()==address&&!s.active_handlers.contains(i))s.active_handlers[i]=snapshot(h);
  }
  if(address==s.stop) {s.reason="stop_address";uc_emu_stop(uc);return;}
  if(s.count++ >= s.limit){s.bounded=true;s.reason="instruction_limit";uc_emu_stop(uc);return;}
  s.visits[address]++;
  if(s.have_previous && s.seen.insert({s.previous,address}).second && s.edges.size()<128)
    s.edges.push_back({{"from",s.previous},{"to",address},{"basis","observed emulated transition"}});
  s.previous=address;s.have_previous=true;
  if(s.steps.size()<128)s.steps.push_back({{"address",address},{"size",size}});
}
static void write_hook(uc_engine*, uc_mem_type, U address,int size,std::int64_t value,void *opaque) {
  auto &s=*static_cast<State*>(opaque);if(s.writes.size()<128)s.writes.push_back({{"address",address},{"size",size},{"value_low64",static_cast<U>(value)}});
}
static void interrupt(uc_engine *uc,std::uint32_t,void *opaque){auto&s=*static_cast<State*>(opaque);s.external=true;s.reason="unmodeled_interrupt";uc_emu_stop(uc);}
static void syscall_hook(uc_engine *uc,void *opaque){auto&s=*static_cast<State*>(opaque);s.external=true;s.reason="unmodeled_syscall";uc_emu_stop(uc);}
static std::uint32_t port_in(uc_engine *uc,std::uint32_t,int,void *opaque){auto&s=*static_cast<State*>(opaque);s.external=true;s.reason="unmodeled_port_io";uc_emu_stop(uc);return 0;}
static void port_out(uc_engine *uc,std::uint32_t,int,std::uint32_t,void *opaque){(void)port_in(uc,0,0,opaque);}
int main(int argc,char **argv) {
  try {
    require(argc==3,"request and pinned input paths required");
    auto q=J::parse(read(argv[1],16384));auto input=read(argv[2],262144);
    for(auto it=q.begin();it!=q.end();++it)require(std::set<std::string>{"bits","base","entry","stop","instructions","registers","memory","observe","handlers"}.contains(it.key()),"unknown emulation field");
    const auto bits=q.value("bits",64);require(bits==32||bits==64,"x86 bits must be 32 or 64");
    const U maximum_address=bits==64?0x00007fffffffffffULL:0xffffffffULL;
    U base=number(q.at("base")),entry=number(q.at("entry")),stop=number(q.at("stop"));
    require(base>=4096 && base%4096==0 && base<=maximum_address-input.size()-4096 && stop<=maximum_address,"code mapping outside bounded address domain");
    require(!input.empty() && entry>=base && entry<base+input.size(),"entry outside original input");
    State s;s.stop=stop;s.limit=number(q.value("instructions",J(1000)));
    require(s.limit>0&&s.limit<=10000,"instruction limit must be 1..10000");
    ok(uc_open(UC_ARCH_X86,bits==64?UC_MODE_64:UC_MODE_32,&s.uc));
    ok(uc_ctl_set_tcg_buffer_size(s.uc,static_cast<std::uint32_t>(16777216)));
    U code_size=(input.size()+4095)&~U(4095);ok(uc_mem_map(s.uc,base,code_size,UC_PROT_ALL));ok(uc_mem_write(s.uc,base,input.data(),input.size()));
    J mappings=J::array({{{"address",base},{"size",code_size},{"origin","pinned helper input"},{"permissions","rwx"}}});
    auto memory=q.value("memory",J::array());require(memory.is_array()&&memory.size()<=8,"memory region bound exceeded");
    U total=code_size;
    for(const auto&m:memory){
      for(auto it=m.begin();it!=m.end();++it)require(std::set<std::string>{"address","size","hex","input","executable"}.contains(it.key()),"unknown memory field");
      U a=number(m.at("address")),n=number(m.at("size"));total+=n;
      require(a>=4096&&a%4096==0&&n>0&&n%4096==0&&n<=1048576&&total<=2097152&&a<=maximum_address-n,"invalid memory bounds");
      auto h=m.value("hex",std::string{});require(h.size()%2==0&&h.size()/2<=n&&h.find_first_not_of("0123456789abcdef")==h.npos,"invalid memory bytes");
      std::string bytes;for(std::size_t i=0;i<h.size();i+=2)bytes+=static_cast<char>(std::stoul(h.substr(i,2),nullptr,16));
      if(m.contains("input")){
        require(!m.contains("hex"),"select input or inline memory bytes, not both");
        const auto name=m.at("input").get<std::string>();require(!name.empty()&&name.size()<=64&&name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")==name.npos,"invalid scoped memory input name");
        bytes=read("/input/files/"+name,static_cast<std::size_t>(std::min<U>(n,262144)));
      }
      int prot=UC_PROT_READ|UC_PROT_WRITE;if(m.value("executable",false))prot|=UC_PROT_EXEC;
      ok(uc_mem_map(s.uc,a,n,prot));if(!bytes.empty())ok(uc_mem_write(s.uc,a,bytes.data(),bytes.size()));
      mappings.push_back({{"address",a},{"size",n},{"origin",m.contains("input")?"scoped helper input":"explicit model-supplied state"},{"input",m.value("input",std::string{})},{"executable",m.value("executable",false)}});
    }
    std::map<std::string,int> regs = bits==64 ? std::map<std::string,int>{{"rax",UC_X86_REG_RAX},{"rbx",UC_X86_REG_RBX},{"rcx",UC_X86_REG_RCX},{"rdx",UC_X86_REG_RDX},{"rsi",UC_X86_REG_RSI},{"rdi",UC_X86_REG_RDI},{"rsp",UC_X86_REG_RSP},{"rbp",UC_X86_REG_RBP},{"r8",UC_X86_REG_R8},{"r9",UC_X86_REG_R9},{"rip",UC_X86_REG_RIP},{"eflags",UC_X86_REG_EFLAGS}} : std::map<std::string,int>{{"eax",UC_X86_REG_EAX},{"ebx",UC_X86_REG_EBX},{"ecx",UC_X86_REG_ECX},{"edx",UC_X86_REG_EDX},{"esi",UC_X86_REG_ESI},{"edi",UC_X86_REG_EDI},{"esp",UC_X86_REG_ESP},{"ebp",UC_X86_REG_EBP},{"eip",UC_X86_REG_EIP},{"eflags",UC_X86_REG_EFLAGS}};
    auto initial=q.value("registers",J::object());require(initial.is_object(),"register object required");
    s.registers=regs;s.handlers=q.value("handlers",J::array());require(s.handlers.is_array()&&s.handlers.size()<=4,"handler selector limit exceeded");
    for(auto &h:s.handlers){
      for(auto it=h.begin();it!=h.end();++it)require(std::set<std::string>{"entry","exit","registers","virtual_state"}.contains(it.key()),"unknown handler field");
      number(h.at("entry"));number(h.at("exit"));require(h.at("registers").is_array()&&h.at("registers").size()<=4,"handler registers exceed four");
      for(const auto &r:h.at("registers"))require(r.is_string()&&regs.contains(r.get<std::string>()),"unknown handler register");
      if(h.contains("virtual_state")){number(h.at("virtual_state").at("address"));require(number(h.at("virtual_state").at("size"))<=64,"virtual state exceeds 64 bytes");}
    }
    for(auto it=initial.begin();it!=initial.end();++it){require(regs.contains(it.key())&&it.key()!="rip"&&it.key()!="eip","unsupported input register");U v=number(it.value());require(bits==64||v<=0xffffffffULL,"32-bit register overflow");ok(uc_reg_write(s.uc,regs.at(it.key()),&v));}
    uc_hook a,b,c,d,e;ok(uc_hook_add(s.uc,&a,UC_HOOK_CODE,reinterpret_cast<void*>(code),&s,1,0));ok(uc_hook_add(s.uc,&b,UC_HOOK_MEM_WRITE,reinterpret_cast<void*>(write_hook),&s,1,0));ok(uc_hook_add(s.uc,&c,UC_HOOK_INTR,reinterpret_cast<void*>(interrupt),&s,1,0));
    ok(uc_hook_add(s.uc,&d,UC_HOOK_INSN,reinterpret_cast<void*>(syscall_hook),&s,1,0,UC_X86_INS_SYSCALL));ok(uc_hook_add(s.uc,&e,UC_HOOK_INSN,reinterpret_cast<void*>(syscall_hook),&s,1,0,UC_X86_INS_SYSENTER));
    uc_hook in_hook,out_hook;ok(uc_hook_add(s.uc,&in_hook,UC_HOOK_INSN,reinterpret_cast<void*>(port_in),&s,1,0,UC_X86_INS_IN));ok(uc_hook_add(s.uc,&out_hook,UC_HOOK_INSN,reinterpret_cast<void*>(port_out),&s,1,0,UC_X86_INS_OUT));
    auto result=uc_emu_start(s.uc,entry,stop,0,0);
    U pc=0;ok(uc_reg_read(s.uc,bits==64?UC_X86_REG_RIP:UC_X86_REG_EIP,&pc));
    bool complete=result==UC_ERR_OK&&!s.bounded&&!s.external&&pc==stop;
    J out{{"schema","indago.bounded-emulation.v1"},{"engine","Unicorn 2.1.4"},{"status",complete?"completed":"partial"},{"native_error",uc_strerror(result)},{"stop_reason",s.reason.empty()?(pc==stop?"stop_address":"native_error"):s.reason},{"instructions",std::min(s.count,s.limit)},{"registers",J::object()},{"steps",s.steps},{"edges",s.edges},{"writes",s.writes},{"mappings",mappings},{"initial_registers",initial},{"verified_solve",false},{"target_execution",false},{"os_calls","unsupported; no host passthrough"},{"semantic_scope","bounded emulated state under explicit assumptions; not original target acceptance"}};
    out["trace_partial"]=s.count>128||s.writes.size()==128||s.edges.size()==128;
    out["location_space"]="emulated_guest_virtual; not automatically an original program address";
    out["code_input_mapping"]={{"guest_base",base},{"input_offset",0},{"input_bytes",input.size()},{"post_write_bytes_are_original",false}};
    out["handler_observations"]=s.handler_observations;out["unfinished_handlers"]=s.active_handlers.size();
    for(const auto &[name,id]:regs){U v=0;ok(uc_reg_read(s.uc,id,&v));out["registers"][name]=v;}
    out["dispatcher_candidates"]=J::array();for(const auto &[address,visits]:s.visits)if(visits>1){std::set<U> successors;for(auto [from,to]:s.seen)if(from==address)successors.insert(to);if(successors.size()>1)out["dispatcher_candidates"].push_back({{"address",address},{"visits",visits},{"successors",successors},{"verdict","candidate only; a loop or branch is not proof of a VM"}});}
    auto observe=q.value("observe",J::array());require(observe.is_array()&&observe.size()<=4,"observation bound exceeded");out["memory"]=J::array();
    for(const auto &m:observe){U address=number(m.at("address")),size=number(m.at("size"));require(size<=256,"memory observation exceeds 256 bytes");std::string bytes(size,'\0');ok(uc_mem_read(s.uc,address,bytes.data(),bytes.size()));out["memory"].push_back({{"address",address},{"hex",hex(bytes)}});}
    if(out.dump().size()>3800){out["steps"]=J::array();out["writes"]=J::array();out["trace_partial"]=true;while(out["edges"].size()>8)out["edges"].erase(out["edges"].size()-1);while(out["dispatcher_candidates"].size()>4)out["dispatcher_candidates"].erase(out["dispatcher_candidates"].size()-1);}
    require(out.dump().size()<=4096,"selected observation exceeds response limit; request smaller ranges");
    std::cout<<out.dump();return 0;
  }catch(const std::exception&e){std::cout<<J{{"status","failed"},{"diagnostic",e.what()},{"verified_solve",false}}.dump();return 1;}
}
