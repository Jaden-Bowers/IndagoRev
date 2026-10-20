#pragma once
#include "analysis.hpp"
#include "../gui/workbench.hpp"
#include "../gui/mock_workbench.hpp"
#include <future>
#include <optional>

namespace macbuild {
// The existing mock namespace also contains the reusable panel view model.
// Real mode reuses its selection/notes behavior, never its fake analysis/chat.
class Controller {
public:
  Controller(mock::Workbench& state, fs::path workspace, Tools tools = DefaultTools());
  ~Controller();
  WorkbenchIntegration view;
  void Open(const fs::path& file);
  void ResumeLastProject();
  void StartAnalysis();
  void Tick();
  void SaveNotes();
  void Execute(const std::string& command);
private:
  void ShowProject(Project project);
  void ShowReport(const Json& report);
  mock::Workbench& state;
  fs::path workspace;
  Tools tools;
  std::optional<Project> project;
  std::future<Json> pending;
  std::atomic_bool cancelled{false};
};
} // namespace macbuild

// Cocoa provides only the file chooser and application lifecycle hooks.
void InitializeMacWorkbench();
void ShutdownMacWorkbench();
