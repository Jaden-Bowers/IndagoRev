#pragma once
#include "indago/core.hpp"
namespace indago {
// Runs a LIEF metadata operation for a request.
CommandResult query_lief(const TargetRecord&, const nlohmann::json&, const fs::path& cancel);
// In-process worker entrypoint for LIEF requests.
nlohmann::json lief_worker(const nlohmann::json& request);
}
