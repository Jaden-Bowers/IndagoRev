#pragma once
#include "indago/core.hpp"
namespace indago {
CommandResult query_wireshark(const TargetRecord&,const nlohmann::json&,const fs::path& cancel);
nlohmann::json wireshark_worker(const nlohmann::json& request);
}
