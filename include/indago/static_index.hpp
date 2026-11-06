#pragma once
#include "indago/core.hpp"
namespace indago {
// Normalizes a backend result into revision-scoped entities, relations and
// claims. Anchors assert same static location, never equivalent semantics or
// agreement between two backend views.
nlohmann::json normalize_static(const TargetRecord&, const nlohmann::json& job,
    std::string_view backend, std::string_view evidence, const nlohmann::json& native,
    const nlohmann::json& layout = nlohmann::json::object());
}
