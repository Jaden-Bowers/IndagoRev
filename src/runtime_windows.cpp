#include "indago/runtime.hpp"
#ifdef _WIN32
#define NOMINMAX
#include <map>
#include <windows.h>

#include <tlhelp32.h>
#include <vector>

namespace indago {
namespace {
using J = RuntimeJson;
void check(bool ok, const char *what) {
  if (!ok)
    throw std::runtime_error(std::string(what) + " (Win32 " +
                             std::to_string(GetLastError()) + ")");
}
struct Handle {
  HANDLE h{};
  Handle(HANDLE value = nullptr) : h(value) {}
  Handle(const Handle &) = delete;
  Handle(Handle &&other) noexcept : h(other.h) { other.h = nullptr; }
  ~Handle() {
    if (h && h != INVALID_HANDLE_VALUE)
      CloseHandle(h);
  }
  operator HANDLE() const { return h; }
};
std::wstring quoted(const std::wstring &s) {
  std::wstring r = L"\"";
  unsigned n = 0;
  for (auto c : s) {
    if (c == L'\\') {
      ++n;
      continue;
    }
    r.append(c == L'"' ? 2 * n + 1 : n, L'\\');
    r += c;
    n = 0;
  }
  r.append(2 * n, L'\\');
  return r + L'"';
}
class WindowsRuntime final : public RuntimeBackend {
  Handle process_;
  DWORD pid_{}, tid_{}, step_tid_{};
  bool alive_{}, stopped_{}, wow_{}, initial_break_{true}, stepping_{};
  DEBUG_EVENT event_{};
  DWORD disposition_{DBG_CONTINUE};
  std::map<std::uint64_t, unsigned char> breaks_;
  std::vector<DWORD> frozen_;
  J modules_ = J::array();
  void add_module(HANDLE file, void *base) {
    std::wstring path(32768, L'\0');
    DWORD n = file ? GetFinalPathNameByHandleW(
                         file, path.data(), static_cast<DWORD>(path.size()), 0)
                   : 0;
    if (!n) {
      n = static_cast<DWORD>(path.size());
      if (!QueryFullProcessImageNameW(process_, 0, path.data(), &n))
        return;
    }
    path.resize(n);
    if (path.starts_with(L"\\\\?\\"))
      path.erase(0, 4);
    J m{{"path", fs::path(path).string()},
        {"base", hex_address(reinterpret_cast<std::uintptr_t>(base))},
        {"size", 0}};
    try {
      m["size"] = runtime_image(fs::path(path))["image_size"];
    } catch (...) {
    }
    modules_.push_back(m);
  }
  Handle open_thread(DWORD tid) {
    Handle h{OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                            THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                        FALSE, tid)};
    check(h.h != nullptr, "OpenThread");
    if (GetProcessIdOfThread(h) != pid_)
      throw std::runtime_error("thread does not belong to this session");
    return h;
  }
  void pc_flags(DWORD tid, std::uint64_t pc, bool setpc, bool step) {
    auto h = open_thread(tid);
    if (wow_) {
      WOW64_CONTEXT c{};
      c.ContextFlags = WOW64_CONTEXT_CONTROL;
      check(Wow64GetThreadContext(h, &c), "Wow64GetThreadContext");
      if (setpc)
        c.Eip = static_cast<DWORD>(pc);
      c.EFlags = step ? (c.EFlags | 0x100) : (c.EFlags & ~0x100UL);
      check(Wow64SetThreadContext(h, &c), "Wow64SetThreadContext");
    } else {
      CONTEXT c{};
      c.ContextFlags = CONTEXT_CONTROL;
      check(GetThreadContext(h, &c), "GetThreadContext");
      c.Rip = setpc ? pc : c.Rip;
      c.EFlags = step ? (c.EFlags | 0x100) : (c.EFlags & ~0x100UL);
      check(SetThreadContext(h, &c), "SetThreadContext");
    }
  }
  void put(std::uint64_t address, unsigned char byte) {
    SIZE_T wrote{};
    check(WriteProcessMemory(process_, reinterpret_cast<void *>(address), &byte,
                             1, &wrote) &&
              wrote == 1,
          "WriteProcessMemory breakpoint");
    check(FlushInstructionCache(process_, reinterpret_cast<void *>(address), 1),
          "FlushInstructionCache");
  }
  void thaw() {
    for (auto id : frozen_) {
      Handle h{OpenThread(THREAD_SUSPEND_RESUME, FALSE, id)};
      if (h.h)
        ResumeThread(h);
    }
    frozen_.clear();
  }

public:
  ~WindowsRuntime() override {
    if (alive_)
      try {
        detach(false);
      } catch (...) {
      }
  }
  J start(const J &r) override {
    if (r.value("operation", "") == "attach") {
      pid_ = static_cast<DWORD>(runtime_number(r.at("pid")));
      check(pid_ != GetCurrentProcessId() && pid_ != 0, "invalid attach PID");
      check(DebugActiveProcess(pid_), "DebugActiveProcess");
    } else {
      auto path = fs::path(r.at("file").get<std::string>());
      std::wstring cmd = quoted(path.wstring());
      for (const auto &arg : r.value("argv", J::array()))
        cmd += L" " + quoted(fs::path(arg.get<std::string>()).wstring());
      STARTUPINFOW si{};
      si.cb = sizeof(si);
      PROCESS_INFORMATION pi{};
      auto cwd = fs::path(r.value("cwd", path.parent_path().string()));
      check(CreateProcessW(path.c_str(), cmd.data(), nullptr, nullptr, FALSE,
                           DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, nullptr,
                           cwd.c_str(), &si, &pi),
            "CreateProcessW debug launch");
      pid_ = pi.dwProcessId;
      CloseHandle(pi.hThread);
      CloseHandle(pi.hProcess);
    }
    alive_ = true;
    check(DebugSetProcessKillOnExit(FALSE), "DebugSetProcessKillOnExit");
    process_.h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD |
                                 PROCESS_VM_READ | PROCESS_VM_WRITE |
                                 PROCESS_VM_OPERATION | PROCESS_TERMINATE,
                             FALSE, pid_);
    check(process_.h != nullptr, "OpenProcess");
    BOOL wow{};
    check(IsWow64Process(process_, &wow), "IsWow64Process");
    wow_ = wow != FALSE;
    return {{"pid", pid_},
            {"arch", wow_ ? "x86" : "x64"},
            {"backend", "windows-debug-api"}};
  }
  J poll(unsigned ms) override {
    if (!alive_ || stopped_)
      return nullptr;
    if (!WaitForDebugEvent(&event_, ms)) {
      if (GetLastError() == ERROR_SEM_TIMEOUT)
        return nullptr;
      check(false, "WaitForDebugEvent");
    }
    tid_ = event_.dwThreadId;
    J out{{"pid", pid_},
          {"thread_id", tid_},
          {"native_event", event_.dwDebugEventCode}};
    disposition_ = DBG_CONTINUE;
    switch (event_.dwDebugEventCode) {
    case CREATE_PROCESS_DEBUG_EVENT:
      add_module(event_.u.CreateProcessInfo.hFile,
                 event_.u.CreateProcessInfo.lpBaseOfImage);
      if (event_.u.CreateProcessInfo.hFile)
        CloseHandle(event_.u.CreateProcessInfo.hFile);
      out["kind"] = "process_created";
      stopped_ = true;
      break;
    case CREATE_THREAD_DEBUG_EVENT:
      out["kind"] = "thread_created";
      break;
    case EXIT_THREAD_DEBUG_EVENT:
      out["kind"] = "thread_exited";
      out["exit_code"] = event_.u.ExitThread.dwExitCode;
      break;
    case LOAD_DLL_DEBUG_EVENT:
      if (event_.u.LoadDll.hFile)
        add_module(event_.u.LoadDll.hFile, event_.u.LoadDll.lpBaseOfDll);
      if (event_.u.LoadDll.hFile)
        CloseHandle(event_.u.LoadDll.hFile);
      out["kind"] = "module_loaded";
      out["base"] = hex_address(
          reinterpret_cast<std::uintptr_t>(event_.u.LoadDll.lpBaseOfDll));
      break;
    case UNLOAD_DLL_DEBUG_EVENT:
      for (auto it = modules_.begin(); it != modules_.end();)
        if ((*it)["base"] == hex_address(reinterpret_cast<std::uintptr_t>(
                                 event_.u.UnloadDll.lpBaseOfDll)))
          it = modules_.erase(it);
        else
          ++it;
      out["kind"] = "module_unloaded";
      out["base"] = hex_address(
          reinterpret_cast<std::uintptr_t>(event_.u.UnloadDll.lpBaseOfDll));
      break;
    case EXIT_PROCESS_DEBUG_EVENT:
      out["kind"] = "process_exited";
      out["exit_code"] = event_.u.ExitProcess.dwExitCode;
      alive_ = false;
      thaw();
      break;
    case EXCEPTION_DEBUG_EVENT: {
      auto code = event_.u.Exception.ExceptionRecord.ExceptionCode;
      auto address = reinterpret_cast<std::uintptr_t>(
          event_.u.Exception.ExceptionRecord.ExceptionAddress);
      out["kind"] = "exception";
      out["code"] = hex_address(code);
      out["address"] = hex_address(address);
      out["first_chance"] = event_.u.Exception.dwFirstChance != 0;
      stopped_ = true;
      disposition_ = DBG_EXCEPTION_NOT_HANDLED;
      if (code == EXCEPTION_BREAKPOINT || code == 0x4000001fUL) {
        auto b = breaks_.find(address);
        if (b != breaks_.end()) {
          put(address, b->second);
          breaks_.erase(b);
          pc_flags(tid_, address, true, false);
          out["kind"] = "breakpoint";
          out["one_shot"] = true;
          disposition_ = DBG_CONTINUE;
        } else if (initial_break_) {
          initial_break_ = false;
          out["kind"] = "loader_breakpoint";
          disposition_ = DBG_CONTINUE;
        }
      }
      if ((code == EXCEPTION_SINGLE_STEP || code == 0x4000001eUL) &&
          stepping_ && tid_ == step_tid_) {
        pc_flags(tid_, 0, false, false);
        stepping_ = false;
        thaw();
        out["kind"] = "step";
        disposition_ = DBG_CONTINUE;
      }
      if (stepping_) {
        pc_flags(step_tid_, 0, false, false);
        stepping_ = false;
        thaw();
      }
      break;
    }
    default:
      out["kind"] = "debug_event";
      break;
    }
    out["stopped"] = stopped_;
    if (!stopped_)
      check(ContinueDebugEvent(pid_, tid_, DBG_CONTINUE), "ContinueDebugEvent");
    return out;
  }
  J registers(std::uint64_t thread) override {
    if (!stopped_)
      throw std::runtime_error("registers require a stopped session");
    auto h = open_thread(static_cast<DWORD>(thread ? thread : tid_));
    J regs = J::object();
    if (wow_) {
      WOW64_CONTEXT c{};
      c.ContextFlags = WOW64_CONTEXT_FULL;
      check(Wow64GetThreadContext(h, &c), "Wow64GetThreadContext");
      regs = {{"eax", hex_address(c.Eax)}, {"ebx", hex_address(c.Ebx)},
              {"ecx", hex_address(c.Ecx)}, {"edx", hex_address(c.Edx)},
              {"esi", hex_address(c.Esi)}, {"edi", hex_address(c.Edi)},
              {"ebp", hex_address(c.Ebp)}, {"esp", hex_address(c.Esp)},
              {"eip", hex_address(c.Eip)}, {"eflags", hex_address(c.EFlags)}};
    } else {
      CONTEXT c{};
      c.ContextFlags = CONTEXT_FULL;
      check(GetThreadContext(h, &c), "GetThreadContext");
      regs = {{"rax", hex_address(c.Rax)}, {"rbx", hex_address(c.Rbx)},
              {"rcx", hex_address(c.Rcx)}, {"rdx", hex_address(c.Rdx)},
              {"rsi", hex_address(c.Rsi)}, {"rdi", hex_address(c.Rdi)},
              {"rbp", hex_address(c.Rbp)}, {"rsp", hex_address(c.Rsp)},
              {"rip", hex_address(c.Rip)}, {"r8", hex_address(c.R8)},
              {"r9", hex_address(c.R9)},   {"r10", hex_address(c.R10)},
              {"r11", hex_address(c.R11)}, {"r12", hex_address(c.R12)},
              {"r13", hex_address(c.R13)}, {"r14", hex_address(c.R14)},
              {"r15", hex_address(c.R15)}, {"eflags", hex_address(c.EFlags)}};
    }
    return {{"thread_id", thread ? thread : tid_},
            {"arch", wow_ ? "x86" : "x64"},
            {"values", regs},
            {"scope", "general-purpose and flags; SIMD/FPU not captured"}};
  }
  J memory(std::uint64_t address, std::size_t size) override {
    if (!stopped_)
      throw std::runtime_error("memory capture requires stopped session");
    std::vector<unsigned char> b(size);
    SIZE_T n{};
    ReadProcessMemory(process_, reinterpret_cast<void *>(address), b.data(),
                      size, &n);
    std::string hex;
    const char *digits = "0123456789abcdef";
    for (std::size_t i = 0; i < n; ++i) {
      hex += digits[b[i] >> 4];
      hex += digits[b[i] & 15];
    }
    return {{"address", hex_address(address)},
            {"requested", size},
            {"size", n},
            {"hex", hex},
            {"status", n == size ? "completed" : "partial"}};
  }
  J modules() override {
    if (!modules_.empty())
      return modules_;
    J list = J::array();
    Handle snap{CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_)};
    check(snap.h != INVALID_HANDLE_VALUE, "module snapshot");
    MODULEENTRY32W e{};
    e.dwSize = sizeof(e);
    if (Module32FirstW(snap, &e))
      do {
        list.push_back({{"path", fs::path(e.szExePath).string()},
                        {"base", hex_address(reinterpret_cast<std::uintptr_t>(
                                     e.modBaseAddr))},
                        {"size", e.modBaseSize}});
      } while (list.size() < 4096 && Module32NextW(snap, &e));
    return list;
  }
  J threads() override {
    J list = J::array();
    Handle snap{CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)};
    check(snap.h != INVALID_HANDLE_VALUE, "thread snapshot");
    THREADENTRY32 e{};
    e.dwSize = sizeof(e);
    if (Thread32First(snap, &e))
      do {
        if (e.th32OwnerProcessID == pid_)
          list.push_back({{"thread_id", e.th32ThreadID}});
      } while (list.size() < 4096 && Thread32Next(snap, &e));
    return list;
  }
  void resume(bool step, std::uint64_t thread, int signal) override {
    if (signal < -1 || signal > 1)
      throw std::runtime_error("Windows signal must be -1 (handled), 0 (native "
                               "default), or 1 (not handled)");
    if (!stopped_)
      throw std::runtime_error("session is not stopped");
    auto selected = static_cast<DWORD>(thread ? thread : tid_);
    if (step && selected != tid_)
      throw std::runtime_error("step requires the event thread");
    if (step) {
      try {
        for (auto &t : threads()) {
          auto id = t["thread_id"].get<DWORD>();
          if (id == selected)
            continue;
          auto h = open_thread(id);
          check(SuspendThread(h) != DWORD(-1), "SuspendThread");
          frozen_.push_back(id);
        }
        pc_flags(selected, 0, false, true);
        step_tid_ = selected;
        stepping_ = true;
      } catch (...) {
        thaw();
        throw;
      }
    }
    auto disposition = signal == 1   ? DBG_EXCEPTION_NOT_HANDLED
                       : signal == 0 ? disposition_
                                     : DBG_CONTINUE;
    check(ContinueDebugEvent(pid_, tid_, disposition), "ContinueDebugEvent");
    stopped_ = false;
  }
  void pause() override {
    if (alive_ && !stopped_) {
      check(DebugBreakProcess(process_), "DebugBreakProcess");
      initial_break_ = true;
    }
  }
  void breakpoint(std::uint64_t address, bool remove) override {
    if (!stopped_)
      throw std::runtime_error("breakpoint changes require stopped session");
    auto it = breaks_.find(address);
    if (remove) {
      if (it == breaks_.end())
        throw std::runtime_error("no breakpoint at address");
      put(address, it->second);
      breaks_.erase(it);
      return;
    }
    if (it != breaks_.end())
      return;
    auto m = memory(address, 1);
    if (m["size"] != 1)
      throw std::runtime_error("breakpoint address is unreadable");
    auto byte = static_cast<unsigned char>(
        std::stoul(m["hex"].get<std::string>(), nullptr, 16));
    if (byte == 0xcc)
      throw std::runtime_error("address already contains INT3");
    put(address, 0xcc);
    breaks_[address] = byte;
  }
  void detach(bool terminate) override {
    if (!alive_)
      return;
    if (!stopped_)
      throw std::runtime_error("pause before detach or terminate");
    for (auto [address, byte] : breaks_)
      put(address, byte);
    breaks_.clear();
    if (stepping_) {
      pc_flags(step_tid_, 0, false, false);
      stepping_ = false;
    }
    thaw();
    if (terminate)
      check(TerminateProcess(process_, 1), "TerminateProcess");
    check(DebugActiveProcessStop(pid_), "DebugActiveProcessStop");
    alive_ = false;
    stopped_ = false;
  }
  bool stopped() const override { return stopped_; }
  bool alive() const override { return alive_; }
  std::uint64_t pid() const override { return pid_; }
  std::uint64_t thread() const override { return tid_; }
};
} // namespace
std::unique_ptr<RuntimeBackend> make_runtime_backend() {
  return std::make_unique<WindowsRuntime>();
}
} // namespace indago
#endif
