#pragma once
#include "project.hpp"
#include <atomic>

namespace macbuild {
struct Tools {
  fs::path ghidra, java, scripts;
};
Tools DefaultTools();
// Automatic analysis and the entire worker have separate deadlines: exporting
// pseudocode needs additional time after Ghidra finishes finding functions.
struct AnalysisSettings {
  unsigned analysisSeconds = 60;
  unsigned workerSeconds = 180;
  int memoryGiB = 2; // Maximum Java heap, not total memory used by all tools.
};
AnalysisSettings SettingsForAnalysis(int seconds, int memoryGiB = 2);
// Runs on a worker thread or in the CLI. It never launches the analyzed file.
// Cancellation retains the last successful report and terminates the tool group.
Json Analyze(const Project& project, const Tools& tools, const std::atomic_bool& cancel,
             AnalysisSettings settings = {});
Json LoadAnalysis(const Project& project);
} // namespace macbuild
