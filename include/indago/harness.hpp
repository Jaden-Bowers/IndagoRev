#pragma once
#include "indago/service.hpp"

namespace indago {
// Runs one harness action (create/import/explore/...) through the workbench.
// External mode never calls a model; built-in explore requires explicit
// inference authorization.
nlohmann::json harness_action(StaticService &, std::string_view operation,
                              const nlohmann::json &request);
// Reports harness operations, modes and safety constraints.
nlohmann::json harness_capabilities();
// Operator-only bridge: re-runs an independent benchmark verifier. Never a model tool.
nlohmann::json harness_certify(StaticService &, const nlohmann::json &request);
// Internal child-process dispatch for a queued workbench action; requires the
// existing action runner lease.
nlohmann::json harness_workbench_worker(StaticService &,
                                        const std::string &project,
                                        const std::string &investigation,
                                        const std::string &action,
                                        const std::string &runner);
} // namespace indago
