#include "indago/runtime.hpp"
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <dbgeng.h>
#include <wrl/client.h>
#include <map>
#include <vector>
#include <thread>
#include <chrono>
#include <future>
#include <deque>
#include <mutex>
#include <condition_variable>

namespace indago {
fs::path bundled_dbgeng();
namespace {
using J = RuntimeJson;
using Microsoft::WRL::ComPtr;
void checked(HRESULT hr, const char *operation) {
  if (FAILED(hr))
    throw std::runtime_error(std::string(operation) + " (DbgEng " +
                             hex_address(static_cast<unsigned long>(hr)) + ")");
}
std::wstring quote(const std::wstring &s) {
  std::wstring result = L"\"";
  unsigned slashes = 0;
  for (auto ch : s) {
    if (ch == L'\\') {
      ++slashes;
      continue;
    }
    result.append(ch == L'"' ? slashes * 2 + 1 : slashes, L'\\');
    result += ch;
    slashes = 0;
  }
  result.append(slashes * 2, L'\\');
  return result + L'"';
}
class Events final : public DebugBaseEventCallbacks {
public:
  bool initial_stop=true;
  IDebugSystemObjects *system{};
  STDMETHOD_(ULONG, AddRef)() override { return 1; }
  STDMETHOD_(ULONG, Release)() override { return 1; }
  STDMETHOD(GetInterestMask)(PULONG mask) override {
    *mask = DEBUG_EVENT_BREAKPOINT | DEBUG_EVENT_EXCEPTION |
            DEBUG_EVENT_EXIT_PROCESS | DEBUG_EVENT_CREATE_PROCESS;
    return S_OK;
  }
  STDMETHOD(Breakpoint)(PDEBUG_BREAKPOINT) override {
    return DEBUG_STATUS_BREAK;
  }
  STDMETHOD(Exception)(PEXCEPTION_RECORD64, ULONG) override {
    ULONG process{};if(initial_stop&&system&&SUCCEEDED(system->GetCurrentProcessId(&process))&&process!=0)return DEBUG_STATUS_NO_CHANGE;
    return DEBUG_STATUS_BREAK;
  }
  STDMETHOD(ExitProcess)(ULONG) override { return DEBUG_STATUS_BREAK; }
  STDMETHOD(CreateProcess)(ULONG64,ULONG64,ULONG64,ULONG,PCSTR,PCSTR,ULONG,ULONG,ULONG64,ULONG64,ULONG64) override {return initial_stop?DEBUG_STATUS_NO_CHANGE:DEBUG_STATUS_BREAK;}
};
class DebugOutput final : public IDebugOutputCallbacks {
public:
  std::string text;
  STDMETHOD(QueryInterface)(REFIID iid, PVOID *value) override {
    if (iid == __uuidof(IUnknown) || iid == __uuidof(IDebugOutputCallbacks)) {
      *value = this;
      return S_OK;
    }
    *value = nullptr;
    return E_NOINTERFACE;
  }
  STDMETHOD_(ULONG, AddRef)() override { return 1; }
  STDMETHOD_(ULONG, Release)() override { return 1; }
  STDMETHOD(Output)(ULONG, PCSTR value) override {
    if (value && text.size() < 4096)
      text.append(value,
                  std::min<std::size_t>(strlen(value), 4096 - text.size()));
    return S_OK;
  }
};
class DbgEngRuntime final : public RuntimeBackend {
  HMODULE library_{};
  Events events_;
  DebugOutput output_;
  ComPtr<IDebugClient5> client_;
  ComPtr<IDebugControl4> control_;
  ComPtr<IDebugSystemObjects> system_;
  ComPtr<IDebugRegisters> registers_;
  ComPtr<IDebugDataSpaces> spaces_;
  ComPtr<IDebugSymbols3> symbols_;
  // Breakpoints are engine-owned; RemoveBreakpoint invalidates the interface.
  std::map<std::uint64_t, IDebugBreakpoint *> breaks_;
  std::map<ULONG,bool> one_shot_;
  ULONG pid_{}, tid_{};
  bool alive_{}, stopped_{}, pending_{}, wow_{}, stepping_{};
  void select(std::uint64_t thread) {
    ULONG id{};
    checked(system_->GetThreadIdBySystemId(
                static_cast<ULONG>(thread ? thread : tid_), &id),
            "thread lookup");
    checked(system_->SetCurrentThreadId(id), "thread selection");
  }

public:
  ~DbgEngRuntime() override { close(); }
  void close() {
    if (client_) {
      if (alive_)
        client_->DetachProcesses();
      client_->SetEventCallbacks(nullptr);
      client_->SetOutputCallbacks(nullptr);
    }
    breaks_.clear();
    symbols_.Reset();
    spaces_.Reset();
    registers_.Reset();
    system_.Reset();
    control_.Reset();
    client_.Reset();
    if (library_) {
      FreeLibrary(library_);
      library_ = nullptr;
    }
  }
  J start(const J &r) override {
    auto engine = bundled_dbgeng();
    library_ = LoadLibraryExW(engine.c_str(), nullptr,
                              LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
                                  LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!library_)
      throw std::runtime_error("bundled DbgEng load failed: " +
                               std::to_string(GetLastError()));
    using Create = HRESULT(WINAPI *)(REFIID, void **);
    auto create =
        reinterpret_cast<Create>(GetProcAddress(library_, "DebugCreate"));
    if (!create)
      throw std::runtime_error("DbgEng DebugCreate missing");
    checked(create(__uuidof(IDebugClient5),
                   reinterpret_cast<void **>(client_.GetAddressOf())),
            "DebugCreate");
    checked(client_.As(&control_), "control interface");
    checked(client_.As(&system_), "system interface");
    events_.system=system_.Get();
    checked(client_.As(&registers_), "register interface");
    checked(client_.As(&spaces_), "memory interface");
    checked(client_.As(&symbols_), "symbols interface");
    checked(client_->SetEventCallbacks(&events_), "event callbacks");
    checked(client_->SetOutputCallbacks(&output_), "output callbacks");
    checked(control_->AddEngineOptions(DEBUG_ENGOPT_INITIAL_BREAK),
            "engine options");
    // Do not inherit symbol-server paths or execute target-provided scripts.
    checked(symbols_->SetSymbolPath(""), "symbol path");
    if (r.value("operation", "") == "attach") {
      auto pid = runtime_number(r.at("pid"));
      if (!pid || pid == GetCurrentProcessId() || pid > MAXDWORD)
        throw std::runtime_error("invalid attach PID");
      checked(client_->AttachProcess(0, static_cast<ULONG>(pid),
                                     DEBUG_ATTACH_DEFAULT),
              "attach");
    } else {
      auto file = fs::path(r.at("file").get<std::string>());
      auto command = quote(file.wstring());
      for (const auto &arg : r.value("argv", J::array()))
        command += L" " + quote(fs::path(arg.get<std::string>()).wstring());
      auto cwd = fs::path(r.value("cwd", file.parent_path().string()));
      DEBUG_CREATE_PROCESS_OPTIONS options{};
      options.CreateFlags = (r.value("follow_children",false)?DEBUG_PROCESS:DEBUG_ONLY_THIS_PROCESS) | CREATE_NO_WINDOW;
      checked(client_->CreateProcessAndAttach2Wide(0, command.data(), &options,
                                                   sizeof(options), cwd.c_str(),
                                                   nullptr, 0, 0),
              "launch");
    }
    alive_ = true;
    auto hr = control_->WaitForEvent(0, 10000);
    checked(hr, "initial event");
    if (hr != S_OK)
      throw std::runtime_error("DbgEng initial stop deadline exceeded");
    checked(system_->GetCurrentProcessSystemId(&pid_), "process ID");
    events_.initial_stop=false;
    ULONG64 process_handle{};
    BOOL is_wow{};
    checked(system_->GetCurrentProcessHandle(&process_handle),
            "process handle");
    if (IsWow64Process(reinterpret_cast<HANDLE>(process_handle), &is_wow) &&
        is_wow)
      checked(control_->SetEffectiveProcessorType(IMAGE_FILE_MACHINE_I386),
              "WOW64 context");
    ULONG machine{};
    checked(control_->GetEffectiveProcessorType(&machine),
            "target architecture");
    wow_ = machine == IMAGE_FILE_MACHINE_I386;
    if (!wow_ && machine != IMAGE_FILE_MACHINE_AMD64)
      throw std::runtime_error("unsupported DbgEng target architecture");
    pending_ = true;
    return {{"pid", pid_},
            {"arch", wow_ ? "x86" : "x64"},
            {"backend", "dbgeng"},
            {"engine_version", "20260319.1511.0"},
            {"engine_path", engine.string()}};
  }
  J poll(unsigned ms) override {
    if (!alive_ || stopped_)
      return nullptr;
    if (!pending_) {
      auto hr = control_->WaitForEvent(0, ms);
      if (hr == S_FALSE)
        return nullptr;
      checked(hr, "WaitForEvent");
    }
    pending_ = false;
    ULONG type{}, process{}, thread{}, used{};
    union {
      DEBUG_LAST_EVENT_INFO_EXCEPTION exception;
      DEBUG_LAST_EVENT_INFO_BREAKPOINT breakpoint;
      DEBUG_LAST_EVENT_INFO_EXIT_PROCESS exit;
    } extra{};
    char description[2048]{};
    checked(control_->GetLastEventInformation(&type, &process, &thread, &extra,
                                              sizeof(extra), &used, description,
                                              sizeof(description), nullptr),
            "event information");
    system_->GetCurrentThreadSystemId(&tid_);
    system_->GetCurrentProcessSystemId(&pid_);
    stopped_ = true;
    J event{{"pid", pid_},          {"thread_id", tid_},
            {"native_event", type}, {"native_description", description},
            {"backend", "dbgeng"},  {"kind", "debug_event"}};
    if(stepping_&&type==0){event["kind"]="step";event["event_semantics"]="DbgEng completed a requested step without a separate native event record";}
    if(type==DEBUG_EVENT_CREATE_PROCESS){
      event["kind"]="process_created";event["event_pid"]=pid_;
      HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);if(snapshot!=INVALID_HANDLE_VALUE){PROCESSENTRY32 entry{};entry.dwSize=sizeof(entry);if(Process32First(snapshot,&entry))do{if(entry.th32ProcessID==pid_){event["parent_pid"]=entry.th32ParentProcessID;break;}}while(Process32Next(snapshot,&entry));CloseHandle(snapshot);}
    } else if (type == DEBUG_EVENT_EXIT_PROCESS) {
      alive_ = stopped_ = false;
      event["kind"] = "process_exited";
      event["exit_code"] = extra.exit.ExitCode;
      event["exited_pid"]=pid_;
      ULONG count{};if(SUCCEEDED(system_->GetNumberProcesses(&count))&&count>1&&count<=256){std::vector<ULONG> ids(count),pids(count);if(SUCCEEDED(system_->GetProcessIdsByIndex(0,count,ids.data(),pids.data())))for(ULONG i=0;i<count;++i)if(ids[i]!=process&&SUCCEEDED(system_->SetCurrentProcessId(ids[i]))){pid_=pids[i];system_->GetCurrentThreadSystemId(&tid_);alive_=stopped_=true;event["kind"]="process_lifetime_exited";event["pid"]=pid_;event["thread_id"]=tid_;break;}}
    } else if (type == DEBUG_EVENT_BREAKPOINT) {
      event["kind"] = "breakpoint";
      event["native_breakpoint_id"] = extra.breakpoint.Id;
      event["one_shot"] = one_shot_.contains(extra.breakpoint.Id)?one_shot_[extra.breakpoint.Id]:false;
      // DbgEng owns restoration and PC adjustment. Remove by ID, not raw bytes.
      for (auto it = breaks_.begin(); it != breaks_.end(); ++it) {
        ULONG id{};
        if (SUCCEEDED(it->second->GetId(&id)) && id == extra.breakpoint.Id) {
          event["address"] = hex_address(it->first);
          break;
        }
      }
      if(event["one_shot"]==true){
        IDebugBreakpoint* hit{};checked(control_->GetBreakpointById(extra.breakpoint.Id,&hit),"hit breakpoint lookup");
        for(auto it=breaks_.begin();it!=breaks_.end();)if(it->second==hit)it=breaks_.erase(it);else ++it;
        checked(control_->RemoveBreakpoint(hit),"remove hit breakpoint");one_shot_.erase(extra.breakpoint.Id);
      }
    } else if (type == DEBUG_EVENT_EXCEPTION) {
      auto code = extra.exception.ExceptionRecord.ExceptionCode;
      event["kind"] =
          stepping_ && (code == EXCEPTION_SINGLE_STEP || code == 0x4000001eUL)
              ? "step"
              : ((code == EXCEPTION_BREAKPOINT || code == 0x4000001fUL)
                     ? "loader_breakpoint"
                     : "exception");
      event["code"] = hex_address(code);
      event["first_chance"] = extra.exception.FirstChance != 0;
      event["address"] =
          hex_address(extra.exception.ExceptionRecord.ExceptionAddress);
      event["native_exception_flags"] =
          extra.exception.ExceptionRecord.ExceptionFlags;
    }
    stepping_ = false;
    event["stopped"] = stopped_;
    return event;
  }
  J registers(std::uint64_t thread) override {
    if (!stopped_)
      throw std::runtime_error("registers require a stopped session");
    select(thread);
    J values = J::object();
    const std::vector<const char *> names =
        wow_ ? std::vector<const char *>{"eax", "ebx", "ecx", "edx", "esi",
                                         "edi", "ebp", "esp", "eip", "eflags"}
             : std::vector<const char *>{"rax", "rbx", "rcx",   "rdx", "rsi",
                                         "rdi", "rbp", "rsp",   "rip", "r8",
                                         "r9",  "r10", "r11",   "r12", "r13",
                                         "r14", "r15", "eflags"};
    for (auto name : names) {
      ULONG index{};
      DEBUG_VALUE value{};
      checked(registers_->GetIndexByName(
                  std::string_view(name) == "eflags" ? "efl" : name, &index),
              "register lookup");
      checked(registers_->GetValue(index, &value), "register read");
      values[name] =
          hex_address(value.Type == DEBUG_VALUE_INT64 ? value.I64 : value.I32);
    }
    J extended=J::array();ULONG count{};checked(registers_->GetNumberRegisters(&count),"register inventory");
    for(ULONG i=0;i<count&&i<512;++i){char name[128]{};DEBUG_REGISTER_DESCRIPTION description{};DEBUG_VALUE value{};
      if(FAILED(registers_->GetDescription(i,name,sizeof(name),nullptr,&description))||FAILED(registers_->GetValue(i,&value))||values.contains(name))continue;
      std::string raw;const char* digits="0123456789abcdef";for(auto byte:value.RawBytes){raw+=digits[byte>>4];raw+=digits[byte&15];}
      extended.push_back({{"name",name},{"native_type",value.Type},{"raw_little_endian_hex",raw}});
    }
    return {{"thread_id", thread ? thread : tid_},
            {"arch", wow_ ? "x86" : "x64"},
            {"values", values},
            {"extended",extended},{"scope", "GP/flags plus available DbgEng register values; native DEBUG_VALUE encodings"}};
  }
  J memory(std::uint64_t address, std::size_t size) override {
    if (!stopped_ || size > 65536)
      throw std::runtime_error("memory requires stopped session and <=64KiB");
    std::vector<unsigned char> bytes(size);
    ULONG read{};
    auto hr = spaces_->ReadVirtual(address, bytes.data(),
                                   static_cast<ULONG>(size), &read);
    std::string hex;
    const char *digits = "0123456789abcdef";
    for (ULONG i = 0; i < read; ++i) {
      hex += digits[bytes[i] >> 4];
      hex += digits[bytes[i] & 15];
    }
    return {{"address", hex_address(address)},
            {"requested", size},
            {"size", read},
            {"hex", hex},
            {"native_hresult", hex_address(static_cast<ULONG>(hr))},
            {"status", read == size ? "completed" : "partial"}};
  }
  J modules() override {
    ULONG count{}, unloaded{};
    checked(symbols_->GetNumberModules(&count, &unloaded), "module count");
    J result = J::array();
    for (ULONG i = 0; i < count && i < 4096; ++i) {
      ULONG64 base{};
      DEBUG_MODULE_PARAMETERS parameters{};
      wchar_t path[32768]{};
      checked(symbols_->GetModuleByIndex(i, &base), "module base");
      checked(symbols_->GetModuleParameters(1, &base, 0, &parameters),
              "module parameters");
      auto hr = symbols_->GetModuleNameStringWide(DEBUG_MODNAME_LOADED_IMAGE, i,
                                                  base, path, 32768, nullptr);
      if (FAILED(hr) || !path[0])
        symbols_->GetModuleNameStringWide(DEBUG_MODNAME_IMAGE, i, base, path,
                                          32768, nullptr);
      if (fs::path(path).is_relative()) {
        ULONG64 handle{};
        if (SUCCEEDED(system_->GetCurrentProcessHandle(&handle))) {
          wchar_t full[32768]{};
          if (K32GetModuleFileNameExW(
                  reinterpret_cast<HANDLE>(handle),
                  reinterpret_cast<HMODULE>(wow_ ? base & 0xffffffffULL : base),
                  full, 32768))
            wcscpy_s(path, full);
        }
      }
      result.push_back(
          {{"base", hex_address(wow_ && (base >> 32) == 0xffffffffULL ? base & 0xffffffffULL : base)},
           {"size", parameters.Size},
           {"path", fs::path(path).string()}});
    }
    return result;
  }
  J threads() override {
    ULONG count{};
    checked(system_->GetNumberThreads(&count), "thread count");
    count = std::min<ULONG>(count, 4096);
    std::vector<ULONG> native(count), engine(count);
    if (count)
      checked(
          system_->GetThreadIdsByIndex(0, count, engine.data(), native.data()),
          "thread inventory");
    J result = J::array();
    for (ULONG i = 0; i < count; ++i)
      result.push_back(
          {{"thread_id", native[i]}, {"native_engine_id", engine[i]}});
    return result;
  }
  void resume(bool step, std::uint64_t thread, int signal) override {
    if (!stopped_)
      throw std::runtime_error("resume requires stopped session");
    if (signal > 1)
      throw std::runtime_error("Windows signal must be -1, 0 or 1");
    select(thread);
    checked(control_->SetExecutionStatus(
                step ? DEBUG_STATUS_STEP_INTO
                     : (signal == 1    ? DEBUG_STATUS_GO_NOT_HANDLED
                        : signal == -1 ? DEBUG_STATUS_GO_HANDLED
                                       : DEBUG_STATUS_GO)),
            "resume");
    stopped_ = false;
    stepping_ = step;
  }
  void pause() override {
    if (!alive_ || stopped_)
      return;
    checked(control_->SetInterrupt(DEBUG_INTERRUPT_ACTIVE), "pause");
  }
  // The only method callable off the engine owner thread (documented DbgEng
  // API).
  void interrupt() {
    checked(control_->SetInterrupt(DEBUG_INTERRUPT_ACTIVE), "interrupt");
  }
  void breakpoint(std::uint64_t address, bool remove) override {
    if (!stopped_)
      throw std::runtime_error("breakpoint requires stopped session");
    auto it = breaks_.find(address);
    if (it != breaks_.end()) {
      if (remove) {
        checked(control_->RemoveBreakpoint(it->second), "remove breakpoint");
        breaks_.erase(it);
      }
      return;
    }
    if (remove)
      return;
    IDebugBreakpoint *bp{};
    checked(control_->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &bp),
            "add breakpoint");
    try {
      checked(bp->SetOffset(address), "breakpoint address");
      checked(bp->AddFlags(DEBUG_BREAKPOINT_ENABLED), "enable breakpoint");
    } catch (...) {
      control_->RemoveBreakpoint(bp);
      throw;
    }
    breaks_.emplace(address, bp);ULONG id{};bp->GetId(&id);one_shot_[id]=true;
  }
  J control(std::string_view op,const J &r) override {
    if(!stopped_)throw std::runtime_error("control requires stopped session");
    select(runtime_number(r.value("thread",J(0))));
    if(op=="apply-inputs") {
      for(const auto &model:r.at("models")){auto name=model.at("input").get<std::string>();auto number=runtime_number(model.at("value"));
        if(name.starts_with("memory_")){BYTE value=static_cast<BYTE>(number);ULONG written{};checked(spaces_->WriteVirtual(runtime_number(name.substr(7)),&value,1,&written),"model memory input");if(written!=1)throw std::runtime_error("partial model input write");}
        else {ULONG index{};DEBUG_VALUE value{};checked(registers_->GetIndexByName(name.c_str(),&index),"model register lookup");value.Type=wow_?DEBUG_VALUE_INT32:DEBUG_VALUE_INT64;if(wow_)value.I32=static_cast<ULONG>(number);else value.I64=number;checked(registers_->SetValue(index,&value),"model register input");}
      }return {{"inputs_applied",true}};
    }
    if(op=="step-over"||op=="step-out") {
      if(op=="step-out")checked(control_->Execute(DEBUG_OUTCTL_IGNORE,"gu",DEBUG_EXECUTE_NOT_LOGGED),"step out");
      else checked(control_->SetExecutionStatus(DEBUG_STATUS_STEP_OVER),"step over");
      stopped_=false;stepping_=true;return {{"native_status","running"}};
    }
    if(op=="stack") {
      auto count=std::min<uint64_t>(runtime_number(r.value("limit",J(64))),256);if(!count)throw std::runtime_error("stack limit must be positive");
      std::vector<DEBUG_STACK_FRAME> frames(count);ULONG used{};checked(control_->GetStackTrace(0,0,0,frames.data(),static_cast<ULONG>(count),&used),"stack unwind");J out=J::array();
      for(ULONG i=0;i<used;++i){char name[1024]{};ULONG64 displacement{};symbols_->GetNameByOffset(frames[i].InstructionOffset,name,sizeof(name),nullptr,&displacement);out.push_back({{"level",i},{"address",hex_address(frames[i].InstructionOffset)},{"return_address",hex_address(frames[i].ReturnOffset)},{"stack",hex_address(frames[i].StackOffset)},{"symbol",name},{"displacement",hex_address(displacement)}});}
      return {{"frames",out},{"partial",used==count},{"producer","DbgEng native unwind"}};
    }
    if(op=="processes") {ULONG count{};checked(system_->GetNumberProcesses(&count),"process inventory");count=std::min<ULONG>(count,256);std::vector<ULONG> ids(count),pids(count);checked(system_->GetProcessIdsByIndex(0,count,ids.data(),pids.data()),"process identities");J out=J::array();for(ULONG i=0;i<count;++i)out.push_back({{"pid",pids[i]},{"native_engine_id",ids[i]}});return {{"processes",out}};}
    if(op=="select-process") {ULONG id{};checked(system_->GetProcessIdBySystemId(static_cast<ULONG>(runtime_number(r.at("pid"))),&id),"process lookup");checked(system_->SetCurrentProcessId(id),"process selection");checked(system_->GetCurrentProcessSystemId(&pid_),"selected PID");system_->GetCurrentThreadSystemId(&tid_);ULONG machine{};checked(control_->GetEffectiveProcessorType(&machine),"selected architecture");wow_=machine==IMAGE_FILE_MACHINE_I386;return {{"pid",pid_},{"arch",wow_?"x86":"x64"}};}
    if(op=="breakpoints") {J out=J::array();ULONG count{};checked(control_->GetNumberBreakpoints(&count),"breakpoint count");for(ULONG i=0;i<count&&i<1024;++i){IDebugBreakpoint* bp{};if(FAILED(control_->GetBreakpointByIndex(i,&bp)))continue;ULONG id{},flags{};ULONG64 address{};bp->GetId(&id);bp->GetFlags(&flags);bp->GetOffset(&address);out.push_back({{"native_breakpoint_id",std::to_string(id)},{"address",hex_address(address)},{"flags",flags},{"one_shot",one_shot_[id]}});}return {{"breakpoints",out}};}
    if(op=="remove-breakpoint") {
      if(!r.contains("breakpoint_id")){breakpoint(runtime_number(r.at("address")),true);return {{"removed",true}};}
      ULONG id=static_cast<ULONG>(runtime_number(r.at("breakpoint_id")));IDebugBreakpoint* bp{};checked(control_->GetBreakpointById(id,&bp),"breakpoint lookup");for(auto it=breaks_.begin();it!=breaks_.end();)if(it->second==bp)it=breaks_.erase(it);else ++it;checked(control_->RemoveBreakpoint(bp),"remove breakpoint");one_shot_.erase(id);return {{"removed",true}};
    }
    if(op=="breakpoint"||op=="watchpoint") {
      bool hardware=r.value("hardware",false);IDebugBreakpoint* bp{};checked(control_->AddBreakpoint(op=="watchpoint"||hardware?DEBUG_BREAKPOINT_DATA:DEBUG_BREAKPOINT_CODE,DEBUG_ANY_ID,&bp),"add breakpoint");ULONG id{};bp->GetId(&id);
      try {
        if(r.contains("expression"))checked(bp->SetOffsetExpression(r.at("expression").get<std::string>().c_str()),"deferred expression");else checked(bp->SetOffset(runtime_number(r.at("address"))),"breakpoint address");
        if(op=="watchpoint"||hardware) {auto size=hardware?1:runtime_number(r.value("size",J(1)));if(size!=1&&size!=2&&size!=4&&size!=8)throw std::runtime_error("watch size must be 1,2,4,8");auto access=r.value("access","write");if(!hardware&&access=="read")throw std::runtime_error("x86 hardware cannot watch reads without writes; choose readwrite");checked(bp->SetDataParameters(static_cast<ULONG>(size),hardware?DEBUG_BREAK_EXECUTE:access=="write"?DEBUG_BREAK_WRITE:DEBUG_BREAK_READ|DEBUG_BREAK_WRITE),"watchpoint access");}
        if(r.contains("condition")){auto condition=r.at("condition").get<std::string>();if(condition.find_first_of(";{}\r\n")!=std::string::npos)throw std::runtime_error("condition must be a single debugger expression");auto cmd=".if (!("+condition+")) { gc }";checked(bp->SetCommand(cmd.c_str()),"breakpoint condition");}
        checked(bp->AddFlags(DEBUG_BREAKPOINT_ENABLED),"enable breakpoint");one_shot_[id]=r.value("one_shot",op!="watchpoint");if(r.contains("address"))breaks_[runtime_number(r["address"])]=bp;
      }catch(...){control_->RemoveBreakpoint(bp);throw;}
      return {{"native_breakpoint_id",std::to_string(id)},{"one_shot",one_shot_[id]}};
    }
    throw std::runtime_error("unsupported DbgEng operation");
  }
  void detach(bool terminate) override {
    if (!alive_)
      return;
    checked(terminate ? client_->TerminateProcesses()
                      : client_->DetachProcesses(),
            terminate ? "terminate" : "detach");
    checked(client_->EndSession(DEBUG_END_PASSIVE), "end session");
    alive_ = stopped_ = false;
    breaks_.clear();
  }
  bool stopped() const override { return stopped_; }
  bool alive() const override { return alive_; }
  std::uint64_t pid() const override { return pid_; }
  std::uint64_t thread() const override { return tid_; }
};
// DbgEng stays inside a real event wait while the CLI worker polls its queue.
// Ordinary engine calls never move threads; only SetInterrupt crosses threads.
class DbgEngOwner final : public RuntimeBackend {
  std::mutex mutex_;
  std::condition_variable ready_;
  std::deque<std::function<void()>> queue_;
  bool quit_{};
  DbgEngRuntime engine_;
  std::thread owner_;
  std::future<J> event_;
  bool alive_{}, stopped_{};
  std::uint64_t pid_{}, tid_{};
  template <class F> auto submit(F f) {
    using R = decltype(f());
    auto task = std::make_shared<std::packaged_task<R()>>(std::move(f));
    auto future = task->get_future();
    {
      std::lock_guard lock(mutex_);
      queue_.emplace_back([task] { (*task)(); });
    }
    ready_.notify_one();
    return future;
  }
  void wait_event() {
    event_ = submit([this] { return engine_.poll(INFINITE); });
  }

public:
  DbgEngOwner()
      : owner_([this] {
          while (true) {
            std::function<void()> action;
            {
              std::unique_lock lock(mutex_);
              ready_.wait(lock, [&] { return quit_ || !queue_.empty(); });
              if (quit_ && queue_.empty())
                break;
              action = std::move(queue_.front());
              queue_.pop_front();
            }
            action();
          }
        }) {}
  ~DbgEngOwner() override {
    try {
      if (alive_) {
        if (event_.valid()) {
          engine_.interrupt();
          event_.wait();
          event_.get();
        }
        submit([&] { engine_.detach(false); }).get();
      }
    } catch (...) {
    }
    submit([&] { engine_.close(); }).get();
    {
      std::lock_guard lock(mutex_);
      quit_ = true;
    }
    ready_.notify_one();
    owner_.join();
  }
  J start(const J &request) override {
    auto result = submit([&] { return engine_.start(request); }).get();
    pid_ = result.at("pid").get<std::uint64_t>();
    alive_ = true;
    wait_event();
    return result;
  }
  J poll(unsigned ms) override {
    if (!event_.valid() || event_.wait_for(std::chrono::milliseconds(ms)) !=
                               std::future_status::ready)
      return nullptr;
    auto event = event_.get();
    if (!event.is_null()) {
      stopped_ = event.value("stopped", false);
      pid_ = event.value("pid",pid_);
      if (event.value("kind", "") == "process_exited")
        alive_ = false;
      tid_ = event.value("thread_id", tid_);
    }
    if (alive_ && !stopped_)
      wait_event();
    return event;
  }
  void require_stop() {
    if (!stopped_)
      throw std::runtime_error(
          "DbgEng inspection requires a stopped session; use runtime pause");
  }
  J registers(std::uint64_t thread) override {
    require_stop();
    return submit([&] { return engine_.registers(thread); }).get();
  }
  J memory(std::uint64_t address, std::size_t size) override {
    require_stop();
    return submit([&] { return engine_.memory(address, size); }).get();
  }
  J modules() override {
    require_stop();
    return submit([&] { return engine_.modules(); }).get();
  }
  J threads() override {
    require_stop();
    return submit([&] { return engine_.threads(); }).get();
  }
  J control(std::string_view op,const J &r) override {
    require_stop();auto result=submit([&]{return engine_.control(op,r);}).get();
    if(op=="step-over"||op=="step-out"){stopped_=false;wait_event();}
    if(op=="select-process"){pid_=engine_.pid();tid_=engine_.thread();}
    return result;
  }
  void resume(bool step, std::uint64_t thread, int signal) override {
    require_stop();
    submit([&] { engine_.resume(step, thread, signal); }).get();
    stopped_ = false;
    wait_event();
  }
  void pause() override {
    if (alive_ && !stopped_)
      engine_.interrupt();
  }
  void breakpoint(std::uint64_t address, bool remove) override {
    require_stop();
    submit([&] { engine_.breakpoint(address, remove); }).get();
  }
  void detach(bool terminate) override {
    submit([&] { engine_.detach(terminate); }).get();
    alive_ = stopped_ = false;
  }
  bool alive() const override { return alive_; }
  bool stopped() const override { return stopped_; }
  std::uint64_t pid() const override { return pid_; }
  std::uint64_t thread() const override { return tid_; }
};
} // namespace
std::unique_ptr<RuntimeBackend> make_runtime_backend() {
  return std::make_unique<DbgEngOwner>();
}
} // namespace indago
#endif
