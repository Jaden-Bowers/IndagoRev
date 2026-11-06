#pragma once
#include "indago/core.hpp"
#include <atomic>

namespace indago {
// In-process xair query options: operation, optional function and limits.
struct XairQuery {
    std::string operation{"cfg"}; // cfg or semantic
    std::optional<std::uint64_t> function;
    std::size_t max_items{10000};
    std::size_t max_output_bytes{4 * 1024 * 1024};
    XairOptions analysis;
    const std::atomic_bool* cancellation{};
};
// Runs an xair query on a target and returns its command result.
CommandResult query_xair(const TargetRecord& target, const XairQuery& query);
}
