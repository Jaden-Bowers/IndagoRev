#pragma once
#include "indago/core.hpp"
namespace indago {
class StaticService {
public:
    explicit StaticService(fs::path workspace): store_(std::move(workspace)) { store_.initialize(); }
    ProjectStore& store() { return store_; }
    nlohmann::json capabilities() const;
    nlohmann::json normalize(nlohmann::json request) const;
    nlohmann::json prepare(nlohmann::json request) const;
    nlohmann::json execute(const nlohmann::json& job) const;
private:
    ProjectStore store_;
};
int result_exit_code(std::string_view status);
}
