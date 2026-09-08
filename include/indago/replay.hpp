#pragma once
#include "indago/runtime.hpp"
#include <functional>
namespace indago {
// Called in an isolated runtime worker, not from the static service/harness.
RuntimeJson run_rr_session(const fs::path& directory, const RuntimeJson& request,
    const std::function<bool()>& cancelled,
    const std::function<void(const RuntimeJson&)>& phase);
int rr_exec_worker(const RuntimeJson& request);
}
