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
struct AnalysisTiming {
  unsigned analysisSeconds = 60;
  unsigned workerSeconds = 180;
};
AnalysisTiming TimingForSeconds(int seconds);
// Runs on a worker thread or in the CLI. It never launches the analyzed file.
// Cancellation retains the last successful report and terminates the tool group.
Json Analyze(const Project& project, const Tools& tools, const std::atomic_bool& cancel,
             AnalysisTiming timing = {});
Json LoadAnalysis(const Project& project);
} // namespace macbuild
