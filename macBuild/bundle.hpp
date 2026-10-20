#pragma once
#include "project.hpp"

namespace macbuild {
struct AnalysisInput {
  fs::path executable;
  Json bundle = Json::object();
};
// Resolve a bundle's declared main executable without loading or launching it.
// Ordinary executable files pass through unchanged.
AnalysisInput ResolveAnalysisInput(const fs::path& selected);
} // namespace macbuild
