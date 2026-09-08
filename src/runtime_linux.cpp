#include "indago/runtime.hpp"
#ifndef _WIN32
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <set>
#include <signal.h>
#include <sstream>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace indago {
namespace {
using J = RuntimeJson;
void check(bool ok, const char *what) {
  if (!ok)
    throw std::runtime_error(std::string(what) + ": " + std::strerror(errno));
}
long trace(enum __ptrace_request op, pid_t tid, void *address = nullptr,
           void *data = nullptr) {
  errno = 0;
  auto r = ptrace(op, tid, address, data);
  check(r != -1 || errno == 0, "ptrace");
  return r;
}
class LinuxRuntime final : public RuntimeBackend {
  pid_t pid_{}, tid_{};
  bool alive_{}, stopped_{}, launching_{}, stepping_{};
  std::set<pid_t> tids_, held_;
  std::map<pid_t, int> signals_;
  std::map<std::uint64_t, unsigned char> breaks_;
  bool x86() const {
    try {
      return runtime_image(fs::path("/proc") / std::to_string(pid_) /
                           "exe")["arch"] == "x86";
    } catch (...) {
      return false;
    }
  }
  user_regs_struct regs(pid_t id) {
    user_regs_struct r{};
    trace(PTRACE_GETREGS, id, nullptr, &r);
    return r;
  }
  void put(std::uint64_t address, unsigned char byte) {
    auto aligned = address & ~std::uint64_t(sizeof(long) - 1);
    auto word = trace(PTRACE_PEEKDATA, tid_, reinterpret_cast<void *>(aligned));
    auto shift = (address - aligned) * 8;
    auto changed = (static_cast<unsigned long>(word) & ~(0xffUL << shift)) |
                   (static_cast<unsigned long>(byte) << shift);
    trace(PTRACE_POKEDATA, tid_, reinterpret_cast<void *>(aligned),
          reinterpret_cast<void *>(changed));
  }
  void hold_all() {
    for (auto id : tids_)
      if (!held_.contains(id)) {
        if (ptrace(PTRACE_INTERRUPT, id, nullptr, nullptr) == -1 &&
            errno != ESRCH)
          check(false, "interrupt peer thread");
      }
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (held_.size() < tids_.size() &&
           std::chrono::steady_clock::now() < deadline) {
      int status{};
      auto id = waitpid(-1, &status, __WALL | WNOHANG);
      if (id > 0) {
        if (WIFSTOPPED(status)) {
          held_.insert(id);
          if ((status >> 16) == PTRACE_EVENT_CLONE) {
            unsigned long child{};
            trace(PTRACE_GETEVENTMSG, id, nullptr, &child);
            tids_.insert(static_cast<pid_t>(child));
          }
          if ((status >> 16) == 0)
            signals_[id] = WSTOPSIG(status);
        } else {
          held_.erase(id);
          tids_.erase(id);
        }
      } else
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (held_.size() != tids_.size())
      throw std::runtime_error(
          "could not stop every traced thread; retry pause before capture");
  }

public:
  ~LinuxRuntime() override {
    if (alive_)
      try {
        pause();
        for (int i = 0; i < 200 && !stopped_; ++i)
          poll(10);
        if (stopped_)
          detach(false);
      } catch (...) {
      }
  }
  J start(const J &request) override {
    constexpr unsigned long options = PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
    if (request.value("operation", "") == "attach") {
      pid_ = static_cast<pid_t>(runtime_number(request.at("pid")));
      if (pid_ <= 1 || pid_ == getpid())
        throw std::runtime_error("invalid attach PID");
      for (const auto &entry : fs::directory_iterator(
               fs::path("/proc") / std::to_string(pid_) / "task")) {
        auto id =
            static_cast<pid_t>(std::stol(entry.path().filename().string()));
        trace(PTRACE_SEIZE, id, nullptr, reinterpret_cast<void *>(options));
        tids_.insert(id);
        alive_ = true;
        trace(PTRACE_INTERRUPT, id);
      }
    } else {
      auto file = request.at("file").get<std::string>();
      auto cwd = request.value("cwd", fs::path(file).parent_path().string());
      std::vector<std::string> strings{file};
      for (auto &a : request.value("argv", J::array()))
        strings.push_back(a.get<std::string>());
      std::vector<char *> argv;
      for (auto &a : strings)
        argv.push_back(a.data());
      argv.push_back(nullptr);
      int gate[2];
      check(pipe2(gate, O_CLOEXEC) == 0, "pipe2");
      pid_ = fork();
      if (pid_ == -1) {
        close(gate[0]);
        close(gate[1]);
        check(false, "fork");
      }
      if (pid_ == 0) {
        close(gate[1]);
        char c{};
        auto n = read(gate[0], &c, 1);
        close(gate[0]);
        if (n != 1)
          _exit(125);
        if (chdir(cwd.c_str()) != 0)
          _exit(126);
        execv(file.c_str(), argv.data());
        _exit(127);
      }
      close(gate[0]);
      try {
        trace(PTRACE_SEIZE, pid_, nullptr, reinterpret_cast<void *>(options));
      } catch (...) {
        close(gate[1]);
        waitpid(pid_, nullptr, 0);
        throw;
      }
      tids_.insert(pid_);
      alive_ = true;
      launching_ = true;
      char c = 1;
      auto wrote = write(gate[1], &c, 1);
      close(gate[1]);
      check(wrote == 1, "launch gate");
    }
    return {{"pid", pid_},
            {"backend", "linux-ptrace"},
            {"arch", x86() ? "x86" : "x64"}};
  }
  J poll(unsigned ms) override {
    if (!alive_ || stopped_)
      return nullptr;
    auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    int status{};
    pid_t id{};
    do {
      id = waitpid(-1, &status, __WALL | WNOHANG);
      if (id > 0)
        break;
      if (id < 0 && errno != EINTR && errno != ECHILD)
        check(false, "waitpid");
      if (ms)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } while (std::chrono::steady_clock::now() < end);
    if (id <= 0)
      return nullptr;
    tid_ = id;
    J e{{"pid", pid_}, {"thread_id", id}, {"native_status", status}};
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      tids_.erase(id);
      held_.erase(id);
      e["kind"] = id == pid_ ? "process_exited" : "thread_exited";
      e["exit_code"] = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
      e["signal"] = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
      if (id == pid_)
        alive_ = false;
      return e;
    }
    if (!WIFSTOPPED(status))
      return nullptr;
    held_.insert(id);
    tids_.insert(id);
    auto event = status >> 16;
    auto sig = WSTOPSIG(status);
    if (event == PTRACE_EVENT_CLONE) {
      unsigned long child{};
      trace(PTRACE_GETEVENTMSG, id, nullptr, &child);
      tids_.insert(static_cast<pid_t>(child));
      e["kind"] = "thread_created";
      e["new_thread_id"] = child;
      trace(PTRACE_CONT, id);
      held_.erase(id);
      return e;
    }
    if (event == PTRACE_EVENT_STOP && id != pid_ && sig == SIGSTOP) {
      trace(PTRACE_CONT, id);
      held_.erase(id);
      return {{"kind", "thread_started"}, {"thread_id", id}};
    }
    e["kind"] = event == PTRACE_EVENT_EXEC   ? "exec"
                : event == PTRACE_EVENT_STOP ? "paused"
                                             : "signal";
    e["signal"] = sig;
    signals_[id] = event ? 0 : sig;
    if (event == PTRACE_EVENT_EXEC) {
      launching_ = false;
      breaks_.clear();
      tids_ = {id};
      held_ = {id};
    }
    if (sig == SIGTRAP && event == 0) {
      auto r = regs(id);
      auto bp = breaks_.find(r.rip - 1);
      if (bp != breaks_.end()) {
        put(bp->first, bp->second);
        r.rip = bp->first;
        trace(PTRACE_SETREGS, id, nullptr, &r);
        e["address"] = hex_address(bp->first);
        breaks_.erase(bp);
        e["kind"] = "breakpoint";
        e["one_shot"] = true;
        signals_[id] = 0;
      } else if (stepping_) {
        e["kind"] = "step";
        signals_[id] = 0;
      }
    }
    stepping_ = false;
    hold_all();
    stopped_ = true;
    e["stopped"] = true;
    return e;
  }
  J registers(std::uint64_t thread) override {
    if (!stopped_)
      throw std::runtime_error("registers require stopped session");
    auto id = static_cast<pid_t>(thread ? thread : tid_);
    if (!held_.contains(id))
      throw std::runtime_error("thread is not stopped in this session");
    auto r = regs(id);
    J v;
    if (x86())
      v = {{"eax", hex_address(r.rax & 0xffffffff)},
           {"ebx", hex_address(r.rbx & 0xffffffff)},
           {"ecx", hex_address(r.rcx & 0xffffffff)},
           {"edx", hex_address(r.rdx & 0xffffffff)},
           {"esi", hex_address(r.rsi & 0xffffffff)},
           {"edi", hex_address(r.rdi & 0xffffffff)},
           {"ebp", hex_address(r.rbp & 0xffffffff)},
           {"esp", hex_address(r.rsp & 0xffffffff)},
           {"eip", hex_address(r.rip & 0xffffffff)},
           {"eflags", hex_address(r.eflags)}};
    else
      v = {{"rax", hex_address(r.rax)}, {"rbx", hex_address(r.rbx)},
           {"rcx", hex_address(r.rcx)}, {"rdx", hex_address(r.rdx)},
           {"rsi", hex_address(r.rsi)}, {"rdi", hex_address(r.rdi)},
           {"rbp", hex_address(r.rbp)}, {"rsp", hex_address(r.rsp)},
           {"rip", hex_address(r.rip)}, {"r8", hex_address(r.r8)},
           {"r9", hex_address(r.r9)},   {"r10", hex_address(r.r10)},
           {"r11", hex_address(r.r11)}, {"r12", hex_address(r.r12)},
           {"r13", hex_address(r.r13)}, {"r14", hex_address(r.r14)},
           {"r15", hex_address(r.r15)}, {"eflags", hex_address(r.eflags)}};
    return {{"thread_id", id},
            {"arch", x86() ? "x86" : "x64"},
            {"values", v},
            {"scope", "general-purpose and flags; SIMD/FPU not captured"}};
  }
  J memory(std::uint64_t address, std::size_t size) override {
    if (!stopped_)
      throw std::runtime_error("memory requires stopped session");
    std::string hex;
    const char *digits = "0123456789abcdef";
    std::size_t n = 0;
    while (n < size) {
      auto at = address + n, aligned = at & ~std::uint64_t(sizeof(long) - 1);
      errno = 0;
      auto word = ptrace(PTRACE_PEEKDATA, tid_,
                         reinterpret_cast<void *>(aligned), nullptr);
      if (word == -1 && errno)
        break;
      for (auto i = at - aligned; i < sizeof(long) && n < size; ++i, ++n) {
        auto b = static_cast<unsigned char>(static_cast<unsigned long>(word) >>
                                            (8 * i));
        hex += digits[b >> 4];
        hex += digits[b & 15];
      }
    }
    return {{"address", hex_address(address)},
            {"requested", size},
            {"size", n},
            {"hex", hex},
            {"status", n == size ? "completed" : "partial"}};
  }
  J modules() override {
    std::ifstream in(fs::path("/proc") / std::to_string(pid_) / "maps");
    if (!in)
      throw std::runtime_error("cannot read process maps");
    J list = J::array();
    std::map<std::string, std::size_t> groups;
    std::string line;
    while (std::getline(in, line) && list.size() < 4096) {
      std::istringstream s(line);
      std::string range, perms, offset, dev, inode, path;
      s >> range >> perms >> offset >> dev >> inode;
      std::getline(s, path);
      auto p = path.find_first_not_of(' ');
      if (p == std::string::npos)
        continue;
      path.erase(0, p);
      if (path.empty() || path[0] != '/')
        continue;
      auto dash = range.find('-');
      auto begin = std::stoull(range.substr(0, dash), nullptr, 16),
           end = std::stoull(range.substr(dash + 1), nullptr, 16),
           off = std::stoull(offset, nullptr, 16);
      std::uint64_t base = begin;
      bool mapped = false;
      try {
        auto image = runtime_image(path);
        for (auto &segment : image["segments"]) {
          auto so = runtime_number(segment["file_offset"]) &
                    ~std::uint64_t(4095),
               va = runtime_number(segment["va"]) & ~std::uint64_t(4095);
          if (off == so && begin >= va) {
            auto candidate = begin - va + runtime_number(image["image_base"]);
            // ELF PT_LOAD file pages can overlap (notably RELRO). Prefer
            // a load bias already established by another mapping.
            if (groups.contains(path + "|" + hex_address(candidate))) {
              base = candidate;
              mapped = true;
              break;
            }
            if (!mapped) {
              base = candidate;
              mapped = true;
            }
          }
        }
      } catch (...) {
      }
      auto key = path + "|" + hex_address(base);
      if (!mapped)
        continue;
      auto it = groups.find(key);
      if (it == groups.end()) {
        groups[key] = list.size();
        list.push_back({{"path", path},
                        {"base", hex_address(base)},
                        {"size", end > base ? end - base : 0},
                        {"mappings", J::array()}});
        it = groups.find(key);
      }
      auto &m = list[it->second];
      m["size"] = std::max<std::uint64_t>(m["size"].get<std::uint64_t>(),
                                          end > base ? end - base : 0);
      m["mappings"].push_back({{"begin", hex_address(begin)},
                               {"end", hex_address(end)},
                               {"file_offset", hex_address(off)},
                               {"permissions", perms}});
    }
    return list;
  }
  J threads() override {
    J result = J::array();
    for (auto id : tids_)
      result.push_back({{"thread_id", id}, {"stopped", held_.contains(id)}});
    return result;
  }
  void resume(bool step, std::uint64_t thread, int signal) override {
    if (!stopped_)
      throw std::runtime_error("session is not stopped");
    auto selected = static_cast<pid_t>(thread ? thread : tid_);
    if (!held_.contains(selected))
      throw std::runtime_error("thread is not stopped in this session");
    if (signal < -1 || signal > 64)
      throw std::runtime_error("signal must be -1 (suppress), 0 (native "
                               "default), or Linux signal 1..64");
    auto run = [&](pid_t id, bool single) {
      int deliver = id == selected ? (signal == -1 ? 0
                                      : signal     ? signal
                                                   : signals_[id])
                                   : signals_[id];
      trace(single ? PTRACE_SINGLESTEP : PTRACE_CONT, id, nullptr,
            reinterpret_cast<void *>(static_cast<std::intptr_t>(deliver)));
      signals_[id] = 0;
    };
    if (step) {
      run(selected, true);
      held_.erase(selected);
      stepping_ = true;
    } else {
      for (auto id : held_)
        run(id, false);
      held_.clear();
    }
    stopped_ = false;
  }
  void pause() override {
    if (alive_ && !stopped_)
      for (auto id : tids_)
        if (!held_.contains(id))
          trace(PTRACE_INTERRUPT, id);
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
      throw std::runtime_error("breakpoint address unreadable");
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
    if (terminate)
      check(kill(pid_, SIGKILL) == 0, "terminate");
    for (auto id : held_)
      if (ptrace(PTRACE_DETACH, id, nullptr,
                 reinterpret_cast<void *>(
                     static_cast<std::intptr_t>(signals_[id]))) == -1 &&
          errno != ESRCH)
        check(false, "detach");
    alive_ = false;
    stopped_ = false;
    held_.clear();
    tids_.clear();
  }
  bool stopped() const override { return stopped_; }
  bool alive() const override { return alive_; }
  std::uint64_t pid() const override { return pid_; }
  std::uint64_t thread() const override { return tid_; }
};
} // namespace
std::unique_ptr<RuntimeBackend> make_runtime_backend() {
  return std::make_unique<LinuxRuntime>();
}
} // namespace indago
#endif
