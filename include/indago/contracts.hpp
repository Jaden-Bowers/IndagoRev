#pragma once
#include <nlohmann/json.hpp>
namespace indago {
// Returns the JSON schema for a named contract (e.g. action/evidence/result).
nlohmann::json contract_schema(const std::string& name);
// Throws if value does not satisfy the named contract schema.
void validate_contract(const std::string& name, const nlohmann::json& value);
}
