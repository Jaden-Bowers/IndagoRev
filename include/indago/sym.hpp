#pragma once
#include "indago/airece.hpp"
namespace indago {
struct SymOptions : NativeProcessOptions {
    std::string operation{"solve_branch"};
    std::string address; // containing function for branch/taint; seed for slice
    std::string function; // required for symbolic_slice enrichment
    std::string source; // native AIRECE selector
    std::string sink; // native AIRECE selector
    std::size_t max_states{256}, max_queries{16}, max_paths{4};
    std::size_t function_depth{3};
    std::uint64_t solver_time_ms{1000};
    fs::path executable;
};
CommandResult query_sym(const TargetRecord& target, const SymOptions& options);
}
