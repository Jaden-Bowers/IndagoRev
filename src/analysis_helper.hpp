#pragma once
#include "indago/service.hpp"
namespace indago {
nlohmann::json helper_capabilities();
nlohmann::json normalize_helper(const ProjectStore &,
                                const nlohmann::json &component,
                                const nlohmann::json &arguments,
                                const nlohmann::json &components = nlohmann::json::array());
nlohmann::json execute_helper(const ProjectStore &,
                              const nlohmann::json &arguments);
int helper_worker(int argc, char **argv);
} // namespace indago
