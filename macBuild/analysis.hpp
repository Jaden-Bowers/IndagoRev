#pragma once
#include "project.hpp"
#include <atomic>

namespace macbuild {
struct Tools {
  fs::path ghidra, java, scripts;
};
Tools DefaultTools();
// Runs on a worker thread or in the CLI. It never launches the analyzed file.
// Cancellation retains the last successful report and terminates the tool group.
Json Analyze(const Project& project, const Tools& tools, const std::atomic_bool& cancel,
             unsigned timeoutSeconds = 180);
Json LoadAnalysis(const Project& project);
} // namespace macbuild
