#pragma once
#include "indago/core.hpp"
namespace indago {
CommandResult query_lief(const TargetRecord&, const nlohmann::json&, const fs::path& cancel);
nlohmann::json lief_worker(const nlohmann::json& request);
}
