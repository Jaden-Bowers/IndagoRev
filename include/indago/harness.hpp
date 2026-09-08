#pragma once
#include "indago/service.hpp"

namespace indago {
// External mode never calls a model. Built-in explore requires explicit
// inference authorization.
nlohmann::json harness_action(StaticService &, std::string_view operation,
                              const nlohmann::json &request);
nlohmann::json harness_capabilities();
// Internal child-process dispatch; requires the existing action runner lease.
nlohmann::json harness_workbench_worker(StaticService &,
                                        const std::string &project,
                                        const std::string &investigation,
                                        const std::string &action,
                                        const std::string &runner);
} // namespace indago
