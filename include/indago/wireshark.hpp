#pragma once
#include "indago/core.hpp"
namespace indago {
// Runs an offline packet query for a capture.
CommandResult query_wireshark(const TargetRecord&,const nlohmann::json&,const fs::path& cancel);
// In-process worker entrypoint for offline packet requests.
nlohmann::json wireshark_worker(const nlohmann::json& request);
}
