#pragma once
#include "indago/core.hpp"
#include <memory>

namespace indago {
using RuntimeJson = nlohmann::json;
// One owner thread performs all debugger calls. No target executes on import.
class RuntimeBackend {
public:
  virtual ~RuntimeBackend() = default;
  // Starts or attaches per the request and returns the initial session state.
  virtual RuntimeJson start(const RuntimeJson &request) = 0;
  // Pumps debugger events for up to milliseconds and returns updated state.
  virtual RuntimeJson poll(unsigned milliseconds) = 0;
  // Returns the registers of a thread.
  virtual RuntimeJson registers(std::uint64_t thread) = 0;
  // Reads size bytes of target memory at address.
  virtual RuntimeJson memory(std::uint64_t address, std::size_t size) = 0;
  // Returns the loaded modules.
  virtual RuntimeJson modules() = 0;
  // Returns the live threads.
  virtual RuntimeJson threads() = 0;
  // Runs a backend-specific control command (unavailable by default).
  virtual RuntimeJson control(std::string_view, const RuntimeJson &) {
    throw std::runtime_error("operation unavailable in this debugger backend");
  }
  // Resumes or single-steps a thread, optionally delivering a signal.
  virtual void resume(bool step, std::uint64_t thread, int signal) = 0;
  // Interrupts target execution.
  virtual void pause() = 0;
  // Adds or removes a breakpoint at address.
  virtual void breakpoint(std::uint64_t address, bool remove) = 0;
  // Detaches from the target, optionally terminating it.
  virtual void detach(bool terminate) = 0;
  // True while the target is stopped at an event or breakpoint.
  virtual bool stopped() const = 0;
  // True while the debugger/target session is still alive.
  virtual bool alive() const = 0;
  // Process id of the debuggee, or 0 if not attached.
  virtual std::uint64_t pid() const = 0;
  // Id of the thread currently reported by the backend.
  virtual std::uint64_t thread() const = 0;
};
// Creates the platform's default runtime backend.
std::unique_ptr<RuntimeBackend> make_runtime_backend();
// Returns the configured bundled-engines directory for a group.
fs::path bundled_engines(std::string_view group = "runtime");
// Executes a runtime command, dispatching to the worker process.
RuntimeJson runtime_command(ProjectStore &store, const fs::path &executable,
                            RuntimeJson request);
// Runs the runtime worker loop for one session.
int runtime_worker(ProjectStore &store, const std::string &session);
// Reports runtime backends, features and limits.
RuntimeJson runtime_capabilities();
// Lists bundled payloads and their versions.
RuntimeJson bundled_payload_inventory();
// Evaluates a symbolic query over a runtime capture.
RuntimeJson runtime_symbolic(const RuntimeJson &capture,
                             const RuntimeJson &request);
// Solves for input satisfying a comparison/delivery/session constraint.
RuntimeJson runtime_solve_input(const RuntimeJson &comparison,const RuntimeJson &delivery,
                               const RuntimeJson &session);
// Coerces a JSON number or numeric string to an unsigned 64-bit value.
std::uint64_t runtime_number(const RuntimeJson &value);
// Small format metadata reader, not an instruction semantics implementation.
RuntimeJson runtime_image(const fs::path &file);
// Computes a code epoch for a location from memory contents and method.
RuntimeJson runtime_code_epoch(const RuntimeJson &session, RuntimeJson &location,
                              const RuntimeJson &memory, std::string_view method);
// Re-runs analysis for a session observation.
RuntimeJson runtime_reanalyze(ProjectStore &store, const RuntimeJson &session,
                             const RuntimeJson &observation, const RuntimeJson &request);
} // namespace indago
