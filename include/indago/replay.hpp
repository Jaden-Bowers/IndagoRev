#pragma once
#include "indago/runtime.hpp"
#include <functional>
namespace indago {
// Runs an rr record/replay session in an isolated runtime worker (not from the
// static service or harness), reporting phase updates to the callback.
RuntimeJson run_rr_session(const fs::path& directory, const RuntimeJson& request,
    const std::function<bool()>& cancelled,
    const std::function<void(const RuntimeJson&)>& phase);
// Child-process entrypoint that executes the rr replay worker.
int rr_exec_worker(const RuntimeJson& request);
}
