#pragma once
#include "indago/core.hpp"
namespace indago {
CommandResult query_ilspy(const TargetRecord& target, const nlohmann::json& request,
                          const fs::path& cancel_file);
}
