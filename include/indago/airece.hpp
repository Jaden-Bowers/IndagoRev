#pragma once
#include "indago/core.hpp"
#include <map>
#include <functional>

namespace indago {
struct NativeProcessOptions {
    std::uint64_t wall_time_ms{120000};
    std::size_t max_output_bytes{1024 * 1024};
    fs::path cancel_file;
    fs::path stdin_file;
    fs::path working_directory;
    std::function<bool()> should_cancel;
};
struct NativeProcessResult {
    int exit_code{-1};
    bool timed_out{}, cancelled{}, truncated{};
    bool output_complete{}; // Both pipes reached EOF, not merely parent exit.
    std::string output, error;
};
// No shell is involved. Each argument is passed as one literal argument.
NativeProcessResult run_native_process(const fs::path& executable,
    const std::vector<std::string>& arguments, const NativeProcessOptions& options);

struct AireceOptions : NativeProcessOptions {
    std::string operation{"inspect"};
    std::string view{"compact"};
    std::string address;
    std::map<std::string, std::string> arguments;
    // Only source/target can repeat; pairs preserve selector order.
    std::vector<std::pair<std::string, std::string>> repeated_arguments;
    fs::path executable; // Test injection only; production uses indago's internal worker.
};
std::optional<fs::path> find_airece();
std::optional<fs::path> find_native_worker();
CommandResult run_airece(const TargetRecord& target, const AireceOptions& options);
}
