#pragma once
#include "harness_scope.hpp"
namespace indago {
wb::J normalize_research(const ProjectStore &, const wb::J &, const wb::J &, wb::J);
wb::J execute_research(const ProjectStore &, const wb::J &);
wb::J evaluation_action(const ProjectStore &, const std::string &, const wb::J &);
} // namespace indago
