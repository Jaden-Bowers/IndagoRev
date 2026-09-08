#pragma once
#include "indago/core.hpp"
namespace indago {
CommandResult query_enrichment(const TargetRecord&,const nlohmann::json&,const fs::path& cancel);
}
