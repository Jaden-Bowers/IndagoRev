#pragma once
#include <nlohmann/json.hpp>
namespace indago {
nlohmann::json contract_schema(const std::string& name);
void validate_contract(const std::string& name, const nlohmann::json& value);
}
