#pragma once
#include "indago/core.hpp"
namespace indago {
// Runs an ILSpy operation, optionally with managed dependencies, a PDB and a
// private output directory.
CommandResult query_ilspy(const TargetRecord& target, const nlohmann::json& request,
                          const fs::path& cancel_file, const std::vector<TargetRecord>& dependencies = {}, const TargetRecord* pdb = nullptr, const fs::path& private_output = {});
}
