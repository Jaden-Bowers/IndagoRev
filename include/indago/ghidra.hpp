#pragma once
#include "indago/core.hpp"
namespace indago {
struct GhidraOptions {
    std::string operation{"inspect"};
    std::string address;
    std::uint64_t max_items{2048};
    std::uint64_t max_output_bytes{2 * 1024 * 1024};
    std::uint64_t timeout_ms{120000};
    fs::path cancel_file;
    nlohmann::json arguments = nlohmann::json::object();
};
CommandResult query_ghidra(const TargetRecord&, const ProjectStore&, const GhidraOptions&);
}
