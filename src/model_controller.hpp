#pragma once
#include "indago/model_provider.hpp"
#include "workbench_db.hpp"
namespace indago {
bool model_controller_internal();
bool model_controller_running(wb::Db &, const std::string &,
                              const std::string &);
nlohmann::json harness_explore(StaticService &, const nlohmann::json &,
                               ModelTransport = {});
nlohmann::json investigation_recipes();
} // namespace indago
