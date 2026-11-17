#pragma once
#include "analysis.hpp"
#include "chat.hpp"
#include "../gui/workbench.hpp"
#include "../gui/mock_workbench.hpp"
#include <future>
#include <optional>

namespace macbuild {
// The existing mock namespace also contains the reusable panel view model.
// Real mode reuses its selection/notes behavior, never its fake analysis/chat.
class Controller {
public:
  Controller(mock::Workbench& state, fs::path workspace, Tools tools = DefaultTools(),
             ChatProvider chatProvider = {});
  ~Controller();
  WorkbenchIntegration view;
  void Open(const fs::path& file);
  void ResumeLastProject();
  void StartAnalysis();
  void Tick();
  void SaveNotes();
  void Execute(const std::string& command);
  bool PrepareChat(const std::string& question);
  bool SendChat(const std::string& question);
  void ClearChat();
private:
  void ShowProject(Project project);
  void ShowReport(const Json& report);
  void LoadSelectedFunction();
  void PollChat();
  void SaveChat();
  void RestoreChat();
  mock::Workbench& state;
  fs::path workspace;
  Tools tools;
  std::optional<Project> project;
  std::future<Json> pending;
  Json activeReport;
  std::string requestedAddress, attemptedAddress;
  int requestRevision = 0;
  bool preparingDatabase = false;
  std::atomic_bool cancelled{false};
  ChatProvider chatProvider;
  std::future<std::string> chatPending;
  std::atomic_bool chatCancelled{false};
  Json lastChatRequest;
};
} // namespace macbuild

// Cocoa provides only the file chooser and application lifecycle hooks.
void InitializeMacWorkbench();
void ShutdownMacWorkbench();
bool MacWorkbenchSmokeTesting();
void MacWorkbenchRendered(bool graphicsCompleted);
