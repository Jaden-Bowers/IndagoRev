#pragma once
#include "indago/core.hpp"
#include <memory>

namespace indago {
using RuntimeJson = nlohmann::json;
// One owner thread performs all debugger calls. No target executes on import.
class RuntimeBackend {
public:
  virtual ~RuntimeBackend() = default;
  virtual RuntimeJson start(const RuntimeJson &request) = 0;
  virtual RuntimeJson poll(unsigned milliseconds) = 0;
  virtual RuntimeJson registers(std::uint64_t thread) = 0;
  virtual RuntimeJson memory(std::uint64_t address, std::size_t size) = 0;
  virtual RuntimeJson modules() = 0;
  virtual RuntimeJson threads() = 0;
  virtual RuntimeJson control(std::string_view, const RuntimeJson &) {
    throw std::runtime_error("operation unavailable in this debugger backend");
  }
  virtual void resume(bool step, std::uint64_t thread, int signal) = 0;
  virtual void pause() = 0;
  virtual void breakpoint(std::uint64_t address, bool remove) = 0;
  virtual void detach(bool terminate) = 0;
  virtual bool stopped() const = 0;
  virtual bool alive() const = 0;
  virtual std::uint64_t pid() const = 0;
  virtual std::uint64_t thread() const = 0;
};
std::unique_ptr<RuntimeBackend> make_runtime_backend();
fs::path bundled_engines(std::string_view group = "runtime");
RuntimeJson runtime_command(ProjectStore &store, const fs::path &executable,
                            RuntimeJson request);
int runtime_worker(ProjectStore &store, const std::string &session);
RuntimeJson runtime_capabilities();
RuntimeJson bundled_payload_inventory();
RuntimeJson runtime_symbolic(const RuntimeJson &capture,
                             const RuntimeJson &request);
std::uint64_t runtime_number(const RuntimeJson &value);
// Small format metadata reader, not an instruction semantics implementation.
RuntimeJson runtime_image(const fs::path &file);
RuntimeJson runtime_code_epoch(const RuntimeJson &session, RuntimeJson &location,
                              const RuntimeJson &memory, std::string_view method);
RuntimeJson runtime_reanalyze(ProjectStore &store, const RuntimeJson &session,
                             const RuntimeJson &observation, const RuntimeJson &request);
} // namespace indago
