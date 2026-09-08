#include "indago/runtime.hpp"
#ifndef _WIN32
#include <chrono>
#include <deque>
#include <fstream>
#include <sstream>
#include <map>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace indago {
namespace {
using J = RuntimeJson;
// GDB/MI syntax only. GDB owns debugging, unwinding, expressions and register
// descriptions; this adapter does not implement an x86 execution model.
class MiParser {
  std::string_view s; size_t p{}; unsigned depth{};
  char peek() const { return p<s.size()?s[p]:0; }
  std::string key() {
    auto begin=p; while(p<s.size() && (isalnum((unsigned char)s[p])||s[p]=='-'||s[p]=='_'))++p;
    if(begin==p)throw std::runtime_error("invalid MI field");
    return std::string(s.substr(begin,p-begin));
  }
  std::string string() {
    ++p; std::string out;
    while(p<s.size()) {
      char c=s[p++]; if(c=='"')return out;
      if(c=='\\') {
        if(p==s.size())break; c=s[p++];
        if(c=='n')c='\n';else if(c=='r')c='\r';else if(c=='t')c='\t';
        else if(c>='0'&&c<='7'){unsigned v=c-'0';for(int i=0;i<2&&p<s.size()&&s[p]>='0'&&s[p]<='7';++i)v=v*8+s[p++]-'0';c=static_cast<char>(v);}
      }out+=c;
    }throw std::runtime_error("unterminated MI string");
  }
  J value() {
    if(++depth>32)throw std::runtime_error("MI nesting limit");
    J out;
    if(peek()=='"')out=string();
    else if(peek()=='{'||peek()=='[') {
      bool object=s[p++]=='{';out=object?J::object():J::array();char close=object?'}':']';
      while(peek()!=close) {
        if(!peek())throw std::runtime_error("truncated MI collection");
        if(object || (peek()!='{'&&peek()!='['&&peek()!='"')) {
          auto k=key();if(peek()!='=')throw std::runtime_error("invalid MI result");++p;
          auto v=value();if(object)out[k]=v;else out.push_back(J{{k,v}});
        }else out.push_back(value());
        if(peek()!=',')break;++p;
      }
      if(peek()!=close)throw std::runtime_error("invalid MI terminator");++p;
    }else throw std::runtime_error("invalid MI value");
    --depth;return out;
  }
public:
  explicit MiParser(std::string_view input):s(input){}
  J fields(){J out=J::object();while(p<s.size()){if(peek()==',')++p;auto k=key();if(peek()!='=')throw std::runtime_error("missing MI equals");++p;out[k]=value();}return out;}
};
std::string mi_quote(std::string_view s){return J(s).dump(-1,' ',false,J::error_handler_t::replace);}
class GdbRuntime final : public RuntimeBackend {
  pid_t engine_{};int input_{-1},output_{-1},tty_{-1};
  unsigned token_{};std::string pending_;std::deque<J> events_;
  bool alive_{},stopped_{},x86_{};uint64_t pid_{},tid_{};
  std::map<std::string,uint64_t> native_threads_,groups_;
  std::map<std::string,std::string> thread_groups_;
  std::map<uint64_t,std::string> breakpoints_;
  J register_names_=J::array();std::string diagnostics_;
  void require_stop(){if(!stopped_)throw std::runtime_error("GDB inspection requires stopped session");}
  void send(const std::string &s) {
    size_t p=0;while(p<s.size()){auto n=write(input_,s.data()+p,s.size()-p);if(n<0&&errno==EINTR)continue;if(n<=0)throw std::runtime_error("GDB input closed");p+=n;}
  }
  std::string line(unsigned ms) {
    auto end=std::chrono::steady_clock::now()+std::chrono::milliseconds(ms);
    do {
      auto nl=pending_.find('\n');if(nl!=std::string::npos){auto s=pending_.substr(0,nl);pending_.erase(0,nl+1);if(!s.empty()&&s.back()=='\r')s.pop_back();return s;}
      pollfd fds[2]{{output_,POLLIN,0},{tty_,POLLIN,0}};
      ::poll(fds,2,std::min<unsigned>(ms,10));char buffer[8192];
      if(fds[1].revents&POLLIN) {auto ignored=read(tty_,buffer,sizeof(buffer));(void)ignored;}
      if(fds[0].revents&POLLIN){auto n=read(output_,buffer,sizeof(buffer));if(n>0)pending_.append(buffer,n);}
      else if(fds[0].revents&(POLLHUP|POLLERR))throw std::runtime_error("GDB worker exited: "+diagnostics_);
      if(pending_.size()>2*1024*1024)throw std::runtime_error("GDB MI record exceeds 2MiB");
    }while(std::chrono::steady_clock::now()<end);
    return {};
  }
  void async(const std::string &s) {
    if(s.empty()||s=="(gdb) "||s=="(gdb)")return;
    if(s[0]=='~'||s[0]=='&'){if(diagnostics_.size()<4096)diagnostics_+=s.substr(0,4096-diagnostics_.size());return;}
    if(s[0]!='*'&&s[0]!='=')return;
    auto comma=s.find(',');auto kind=s.substr(1,comma==std::string::npos?comma:comma-1);
    J data=comma==std::string::npos?J::object():MiParser(std::string_view(s).substr(comma)).fields();
    if(kind=="thread-group-started"){auto child=std::stoull(data.at("pid").get<std::string>());groups_[data.at("id")]=child;std::ifstream status("/proc/"+std::to_string(child)+"/status");std::string row;while(std::getline(status,row))if(row.starts_with("PPid:")){data["parent_pid"]=std::stoull(row.substr(5));break;}}
    if(kind=="thread-created"){native_threads_[data.at("id")]=0;thread_groups_[data.at("id")]=data.value("group-id","");}
    if(kind=="thread-exited"){native_threads_.erase(data.at("id"));thread_groups_.erase(data.at("id"));}
    if(kind=="thread-group-exited"){auto group=data.at("id").get<std::string>();if(groups_.contains(group))data["pid"]=std::to_string(groups_[group]);groups_.erase(group);}
    if(kind=="running")return;
    if(kind=="stopped"||kind=="thread-group-started"||kind=="thread-group-exited"||kind=="library-loaded"||kind=="library-unloaded") {
      if(events_.size()>=4096)throw std::runtime_error("GDB event budget exceeded");
      events_.push_back({{"native_kind",kind},{"native",data},{"backend","gdb-mi"}});
    }
  }
  J command(const std::string &command) {
    auto id=std::to_string(++token_);send(id+command+"\n");
    auto end=std::chrono::steady_clock::now()+std::chrono::seconds(10);
    while(std::chrono::steady_clock::now()<end){auto s=line(50);if(s.starts_with(id+"^")){
      auto at=s.find(',');auto status=s.substr(id.size()+1,at==std::string::npos?at:at-id.size()-1);
      J result=at==std::string::npos?J::object():MiParser(std::string_view(s).substr(at)).fields();
      if(status=="error")throw std::runtime_error("GDB: "+result.value("msg","unknown error"));
      result["native_status"]=status;return result;
    }async(s);}throw std::runtime_error("GDB command deadline exceeded");
  }
  void select(uint64_t thread){if(!thread)thread=tid_;for(auto &[id,native]:native_threads_)if(native==thread){command("-thread-select "+id);return;}if(thread)throw std::runtime_error("unknown GDB thread");}
  void refresh_threads(){
    auto result=command("-thread-info");
    for(const auto &t:result.value("threads",J::array())){
      auto text=t.value("target-id","");auto pos=text.find("LWP ");uint64_t native{};
      if(pos!=std::string::npos)native=std::stoull(text.substr(pos+4));
      else if(text.starts_with("process "))native=std::stoull(text.substr(8));
      native_threads_[t.at("id")]=native;
      if(t.at("id")==result.value("current-thread-id",std::string{}))tid_=native;
    }
  }
public:
  ~GdbRuntime() override {
    try {if(alive_)detach(false);}catch(...){}
    if(engine_>0){kill(engine_,SIGTERM);waitpid(engine_,nullptr,0);}
    for(auto fd:{input_,output_,tty_})if(fd>=0)close(fd);
  }
  J start(const J &r) override {
    auto engine=bundled_engines()/"gdb/bin/gdb";
    if(!fs::exists(engine))throw std::runtime_error("private GDB payload missing; run tools/build-gdb.sh");
    int in[2],out[2];if(pipe2(in,O_CLOEXEC)||pipe2(out,O_CLOEXEC))throw std::runtime_error("GDB pipe creation failed");
    tty_=posix_openpt(O_RDWR|O_NOCTTY|O_NONBLOCK|O_CLOEXEC);
    if(tty_<0||grantpt(tty_)||unlockpt(tty_))throw std::runtime_error("GDB inferior PTY failed");
    std::string terminal=ptsname(tty_);
    engine_=fork();if(engine_<0)throw std::runtime_error("GDB fork failed");
    if(!engine_){dup2(in[0],0);dup2(out[1],1);dup2(out[1],2);for(auto fd:{in[0],in[1],out[0],out[1]})close(fd);
      auto libs=engine.parent_path().parent_path()/"lib";setenv("LD_LIBRARY_PATH",libs.c_str(),1);
      execl(engine.c_str(),engine.c_str(),"--nx","--nh","--quiet","--interpreter=mi3",nullptr);_exit(127);}
    close(in[0]);close(out[1]);input_=in[1];output_=out[0];
    command("-gdb-set pagination off");command("-gdb-set confirm off");command("-gdb-set mi-async on");
    command("-gdb-set auto-load off");command("-gdb-set debuginfod enabled off");
    command("-gdb-set startup-with-shell off");command("-gdb-set may-call-functions off");
    command("-interpreter-exec console \"unset environment LD_LIBRARY_PATH\"");command("-inferior-tty-set "+mi_quote(terminal));
    command("-gdb-set detach-on-fork "+std::string(r.value("follow_children",false)?"off":"on"));
    command("-gdb-set schedule-multiple on");
    if(r.value("follow_children",false)){command("-interpreter-exec console \"catch fork\"");command("-interpreter-exec console \"catch vfork\"");command("-interpreter-exec console \"catch exec\"");}
    if(r.value("operation","")=="attach")command("-target-attach "+std::to_string(runtime_number(r.at("pid"))));
    else {
      command("-file-exec-and-symbols "+mi_quote(r.at("file").get<std::string>()));
      if(r.contains("cwd"))command("-environment-cd "+mi_quote(r.at("cwd").get<std::string>()));
      std::string args="-exec-arguments";for(const auto &a:r.value("argv",J::array()))args+=" "+mi_quote(a.get<std::string>());command(args);
      command("-interpreter-exec console \"starti\"");
    }
    alive_=true;
    auto end=std::chrono::steady_clock::now()+std::chrono::seconds(10);
    while(std::chrono::steady_clock::now()<end){if(!groups_.empty()&&std::any_of(events_.begin(),events_.end(),[](auto &e){return e["native_kind"]=="stopped";}))break;async(line(50));}
    if(groups_.empty())throw std::runtime_error("GDB did not report process identity");
    pid_=groups_.begin()->second;x86_=runtime_image(fs::path("/proc")/std::to_string(pid_)/"exe")["arch"]=="x86";
    register_names_=command("-data-list-register-names").at("register-names");
    return {{"pid",pid_},{"arch",x86_?"x86":"x64"},{"backend","gdb-mi"},{"engine_path",engine.string()},{"follow_children",r.value("follow_children",false)}};
  }
  J poll(unsigned ms) override {
    if(events_.empty())async(line(ms));
    if(events_.empty())return nullptr;
    J e=events_.front();events_.pop_front();auto &n=e["native"];auto kind=e["native_kind"].get<std::string>();
    if(kind!="stopped") {
      e["kind"]=kind=="thread-group-started"?"process_created":kind=="thread-group-exited"?"process_lifetime_exited":"module_inventory_changed";
      if(n.contains("pid"))e["event_pid"]=std::stoull(n["pid"].get<std::string>());
      if(n.contains("parent_pid"))e["parent_pid"]=n["parent_pid"];
      e["stopped"]=stopped_;return e;
    }
    auto reason=n.value("reason","");stopped_=true;
    if(reason=="exited-normally"||reason=="exited"||reason=="exited-signalled") {
      alive_=stopped_=!groups_.empty();e["kind"]=alive_?"process_lifetime_exited":"process_exited";
      if(alive_){auto group=groups_.begin()->first;command("-interpreter-exec console "+mi_quote("inferior "+group.substr(1)));pid_=groups_.begin()->second;refresh_threads();}
    }else {
      refresh_threads();
      if(n.contains("thread-id")&&native_threads_.contains(n["thread-id"]))tid_=native_threads_[n["thread-id"]];
      if(n.contains("thread-id")&&thread_groups_.contains(n["thread-id"])){auto group=thread_groups_[n["thread-id"]];if(groups_.contains(group))pid_=groups_[group];}
      x86_=runtime_image(fs::path("/proc")/std::to_string(pid_)/"exe")["arch"]=="x86";
      register_names_=command("-data-list-register-names").at("register-names");
      e["kind"]=reason=="exec"?"exec":reason=="breakpoint-hit"||reason=="watchpoint-trigger"||reason=="read-watchpoint-trigger"||reason=="access-watchpoint-trigger"?"breakpoint":reason=="end-stepping-range"||reason=="function-finished"?"step":reason=="signal-received"?"exception":"debug_event";
      if(n.contains("frame"))e["address"]=n["frame"].value("addr","");
    }
    e["pid"]=pid_;e["thread_id"]=tid_;e["stopped"]=stopped_;return e;
  }
  J registers(uint64_t thread) override {
    require_stop();select(thread);register_names_=command("-data-list-register-names").at("register-names");auto native=command("-data-list-register-values x");J values=J::object(),extended=J::array();
    for(auto &v:native.at("register-values")){
      auto i=std::stoul(v.at("number").get<std::string>());if(i>=register_names_.size())continue;
      auto name=register_names_[i].get<std::string>();auto value=v.value("value","");
      if(value.starts_with("0x")&&value.find_first_not_of("0123456789abcdefABCDEF",2)==std::string::npos)values[name]=value;
      else if(!name.empty())extended.push_back({{"name",name},{"native_value",value}});
    }
    return {{"thread_id",thread?thread:tid_},{"arch",x86_?"x86":"x64"},{"values",values},{"extended",extended},{"scope","GDB native registers including available SIMD/FPU"}};
  }
  J memory(uint64_t address,size_t size) override {
    require_stop();if(size>65536)throw std::runtime_error("memory limit 64KiB");
    try {auto r=command("-data-read-memory-bytes "+hex_address(address)+" "+std::to_string(size));std::string hex;
      for(const auto &m:r.at("memory"))hex+=m.at("contents").get<std::string>();
      return {{"address",hex_address(address)},{"requested",size},{"size",hex.size()/2},{"hex",hex},{"status",hex.size()/2==size?"completed":"partial"}};
    }catch(const std::exception &e){return {{"address",hex_address(address)},{"requested",size},{"size",0},{"hex",""},{"status","partial"},{"diagnostic",e.what()}};}
  }
  J modules() override {
    require_stop();std::ifstream input(fs::path("/proc")/std::to_string(pid_)/"maps");J result=J::array();std::map<std::string,size_t> groups;std::string line;
    while(std::getline(input,line)&&result.size()<4096){std::istringstream s(line);std::string range,perms,offset,dev,inode,path;s>>range>>perms>>offset>>dev>>inode;std::getline(s,path);auto p=path.find_first_not_of(' ');if(p==std::string::npos)continue;path.erase(0,p);if(path[0]!='/')continue;
      auto dash=range.find('-');auto begin=std::stoull(range.substr(0,dash),nullptr,16),end=std::stoull(range.substr(dash+1),nullptr,16),off=std::stoull(offset,nullptr,16);uint64_t base{};bool mapped=false;
      try {auto image=runtime_image(path);for(const auto &segment:image["segments"]){auto so=runtime_number(segment["file_offset"])&~uint64_t(4095),va=runtime_number(segment["va"])&~uint64_t(4095);if(off==so&&begin>=va){auto candidate=begin-va+runtime_number(image["image_base"]);if(groups.contains(path+"|"+hex_address(candidate))){base=candidate;mapped=true;break;}if(!mapped){base=candidate;mapped=true;}}}}catch(...){}
      if(!mapped)continue;auto key=path+"|"+hex_address(base);if(!groups.contains(key)){groups[key]=result.size();result.push_back({{"path",path},{"base",hex_address(base)},{"size",0},{"mappings",J::array()}});}auto &m=result[groups[key]];m["size"]=std::max<uint64_t>(m["size"].get<uint64_t>(),end>base?end-base:0);m["mappings"].push_back({{"begin",hex_address(begin)},{"end",hex_address(end)},{"file_offset",hex_address(off)},{"permissions",perms}});
    }return result;
  }
  J threads() override {require_stop();refresh_threads();J out=J::array();for(auto &[id,native]:native_threads_)if(native)out.push_back({{"thread_id",native},{"native_engine_id",id},{"stopped",true}});return out;}
  void resume(bool step,uint64_t thread,int signal) override {
    require_stop();select(thread);
    if(signal){if(signal<-1||signal>64)throw std::runtime_error("invalid signal");command("-interpreter-exec console "+mi_quote("queue-signal "+std::to_string(signal<0?0:signal)));}
    command(step?"-exec-step-instruction":"-exec-continue --all");stopped_=false;
  }
  void pause() override {if(alive_&&!stopped_)command("-exec-interrupt --all");}
  void breakpoint(uint64_t address,bool remove) override {
    require_stop();if(remove){if(breakpoints_.contains(address)){command("-break-delete "+breakpoints_[address]);breakpoints_.erase(address);}return;}
    auto result=command("-break-insert -t "+mi_quote("*"+hex_address(address)));breakpoints_[address]=result["bkpt"]["number"];
  }
  J control(std::string_view op,const J &r) override {
    require_stop();select(runtime_number(r.value("thread",J(0))));
    if(op=="apply-inputs") {
      for(const auto &model:r.at("models")){auto name=model.at("input").get<std::string>();auto value=runtime_number(model.at("value"));
        if(name.starts_with("memory_")){auto at=runtime_number(name.substr(7));char byte[3];snprintf(byte,sizeof(byte),"%02x",static_cast<unsigned>(value&255));command("-data-write-memory-bytes "+hex_address(at)+" "+byte);}
        else {size_t index=0;while(index<register_names_.size()&&register_names_[index]!=name)++index;if(index==register_names_.size())throw std::runtime_error("model register unavailable");command("-data-write-register-values x "+std::to_string(index)+" "+hex_address(value));}
      }return {{"inputs_applied",true}};
    }
    if(op=="stack"){auto count=std::min<uint64_t>(runtime_number(r.value("limit",J(64))),256);if(!count)throw std::runtime_error("stack limit must be positive");auto result=command("-stack-list-frames 0 "+std::to_string(count-1));result["frames"]=J::array();for(auto &f:result.value("stack",J::array()))result["frames"].push_back(f.value("frame",f));return result;}
    if(op=="breakpoints"){auto result=command("-break-list");result["breakpoints"]=J::array();for(auto &b:result.value("BreakpointTable",J::object()).value("body",J::array())){auto entry=b.value("bkpt",b);entry["native_breakpoint_id"]=entry.value("number","");result["breakpoints"].push_back(entry);}return result;}
    if(op=="processes")return command("-list-thread-groups");
    if(op=="select-process") {auto pid=runtime_number(r.at("pid"));for(auto &[group,native]:groups_)if(native==pid){command("-interpreter-exec console "+mi_quote("inferior "+group.substr(1)));pid_=pid;x86_=runtime_image(fs::path("/proc")/std::to_string(pid_)/"exe")["arch"]=="x86";refresh_threads();return {{"pid",pid_},{"arch",x86_?"x86":"x64"}};}throw std::runtime_error("unknown process");}
    if(op=="step-over"||op=="step-out"){auto result=command(op=="step-over"?"-exec-next-instruction":"-exec-finish");stopped_=false;return result;}
    if(op=="breakpoint") {
      auto spec=r.contains("expression")?r.at("expression").get<std::string>():"*"+hex_address(runtime_number(r.at("address")));
      std::string cmd="-break-insert -f";if(r.value("one_shot",true))cmd+=" -t";if(r.value("hardware",false))cmd+=" -h";
      if(r.contains("condition"))cmd+=" -c "+mi_quote(r.at("condition").get<std::string>());
      auto result=command(cmd+" "+mi_quote(spec));if(r.contains("address"))breakpoints_[runtime_number(r["address"])]=result["bkpt"]["number"];result["native_breakpoint_id"]=result["bkpt"]["number"];return result;
    }
    if(op=="remove-breakpoint") {if(!r.contains("breakpoint_id")){breakpoint(runtime_number(r.at("address")),true);return {{"removed",true}};}auto id=r.at("breakpoint_id").get<std::string>();if(id.find_first_not_of("0123456789.")!=std::string::npos)throw std::runtime_error("invalid breakpoint ID");return command("-break-delete "+id);}
    if(op=="watchpoint") {
      auto size=runtime_number(r.value("size",J(1)));if(size!=1&&size!=2&&size!=4&&size!=8)throw std::runtime_error("watch size must be 1,2,4,8");
      auto access=r.value("access","write");std::string option=access=="read"?"-r ":access=="readwrite"?"-a ":"";
      auto type=size==1?"char":size==2?"short":size==4?"int":"long long";
      auto expression=r.contains("expression")?r["expression"].get<std::string>():"*(unsigned "+std::string(type)+"*)"+hex_address(runtime_number(r.at("address")));
      auto result=command("-break-watch "+option+mi_quote(expression));for(auto key:{"wpt","hw-rwpt","hw-awpt"})if(result.contains(key))result["native_breakpoint_id"]=result[key]["number"];if(r.contains("condition"))command("-break-condition "+result.at("native_breakpoint_id").get<std::string>()+" "+mi_quote(r.at("condition").get<std::string>()));return result;
    }
    throw std::runtime_error("unsupported GDB control operation");
  }
  void detach(bool terminate) override {
    if(!alive_)return;if(!stopped_){pause();auto end=std::chrono::steady_clock::now()+std::chrono::seconds(3);while(!stopped_&&std::chrono::steady_clock::now()<end)poll(20);}
    auto groups=groups_;
    if(terminate){std::string ids="kill inferiors";for(auto &[group,pid]:groups)ids+=" "+group.substr(1);command("-interpreter-exec console "+mi_quote(ids));}
    else for(auto &[group,pid]:groups)command("-target-detach "+group);
    alive_=stopped_=false;
  }
  bool stopped()const override{return stopped_;}bool alive()const override{return alive_;}
  uint64_t pid()const override{return pid_;}uint64_t thread()const override{return tid_;}
};
}
std::unique_ptr<RuntimeBackend> make_runtime_backend(){return std::make_unique<GdbRuntime>();}
}
#endif
