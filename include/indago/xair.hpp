#pragma once
#include "indago/core.hpp"
#include <atomic>

namespace indago {
struct XairQuery {
    std::string operation{"cfg"}; // cfg or semantic
    std::optional<std::uint64_t> function;
    std::size_t max_items{10000};
    std::size_t max_output_bytes{4 * 1024 * 1024};
    XairOptions analysis;
    const std::atomic_bool* cancellation{};
};
CommandResult query_xair(const TargetRecord& target, const XairQuery& query);
}
