#pragma once
#include "indago/service.hpp"
namespace indago {
nlohmann::json guest_action(const ProjectStore &, const std::string &,
                            const nlohmann::json &);
}
