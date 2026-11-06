#pragma once
#include "indago/core.hpp"
namespace indago {
// Front door to the static-analysis backends. Owns a ProjectStore and turns
// validated action requests into durable jobs, executes them and publishes the
// result as evidence plus derived index rows.
class StaticService {
public:
    // Opens (and initializes) the workspace store at the given root.
    explicit StaticService(fs::path workspace): store_(std::move(workspace)) { store_.initialize(); }
    // Mutable access to the underlying workspace store.
    ProjectStore& store() { return store_; }
    // Reports available backends, their operations and workbench support.
    nlohmann::json capabilities() const;
    // Validates and canonicalizes an action request (backend/operation,
    // address, project/target identity, budgets and backend arguments).
    nlohmann::json normalize(nlohmann::json request) const;
    // Validates a request and enqueues it as a durable job.
    nlohmann::json prepare(nlohmann::json request) const;
    // Claims and runs a submitted job, heartbeating its lease, then publishes
    // the result; returns the (budget-clamped) result envelope.
    nlohmann::json execute(const nlohmann::json& job) const;
private:
    ProjectStore store_;
};
// Maps a result status word to a process exit code (0 ok, 3 partial, 130
// cancelled, 2 invalid/not-found, 1 otherwise).
int result_exit_code(std::string_view status);
}
