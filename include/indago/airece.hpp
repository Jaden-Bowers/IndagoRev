#pragma once
#include "indago/core.hpp"
#include <map>
#include <functional>

namespace indago {
// Options for spawning an isolated native worker process.
struct NativeProcessOptions {
    std::uint64_t wall_time_ms{120000};
    std::size_t max_output_bytes{1024 * 1024};
    fs::path cancel_file;
    fs::path stdin_file;
    fs::path working_directory;
    bool clear_environment{};
    // Opt-in OS per-process memory limit: address space on POSIX, committed
    // memory on Windows. Not an aggregate process-tree or filesystem sandbox.
    std::uint64_t process_memory_bytes{};
    std::map<std::string,std::string> environment;
    std::function<bool()> should_cancel;
};
// Outcome of a native worker process, including bounded-output and
// timeout/cancellation flags.
struct NativeProcessResult {
    int exit_code{-1};
    bool timed_out{}, cancelled{}, truncated{};
    bool output_complete{}; // Both pipes reached EOF, not merely parent exit.
    std::string output, error;
};
// Runs executable with literal argv (no shell) under the given time, output and
// cancellation limits.
NativeProcessResult run_native_process(const fs::path& executable,
    const std::vector<std::string>& arguments, const NativeProcessOptions& options);

// AIRECE worker request: operation, view, address, arguments and limits.
struct AireceOptions : NativeProcessOptions {
    std::string operation{"inspect"};
    std::string view{"compact"};
    std::string address;
    std::map<std::string, std::string> arguments;
    // Only source/target can repeat; pairs preserve selector order.
    std::vector<std::pair<std::string, std::string>> repeated_arguments;
    fs::path executable; // Test injection only; production uses indago's internal worker.
};
// Locates the internal AIRECE worker executable, if available.
std::optional<fs::path> find_airece();
// Locates the generic native worker executable, if available.
std::optional<fs::path> find_native_worker();
// Runs an AIRECE operation on a target and returns its command result.
CommandResult run_airece(const TargetRecord& target, const AireceOptions& options);
}
