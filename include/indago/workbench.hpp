#pragma once
#include "indago/service.hpp"

namespace indago {
// Structured error carrying a stable code for client-side error mapping.
class WorkbenchError : public std::runtime_error {
public:
  std::string code;
  WorkbenchError(std::string category, const std::string &message)
      : std::runtime_error(message), code(std::move(category)) {}
};
// Dispatches a deterministic investigation family/operation; no model, target
// execution or shell.
nlohmann::json workbench_action(StaticService &service, std::string_view family,
                                std::string_view operation,
                                const nlohmann::json &request);
// Reports workbench families, operations and limits.
nlohmann::json workbench_capabilities();
} // namespace indago
