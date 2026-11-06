#pragma once
#include "indago/core.hpp"
namespace indago {
// Runs the capa/FLOSS enrichment backend for a request.
CommandResult query_enrichment(const TargetRecord&,const nlohmann::json&,const fs::path& cancel);
}
