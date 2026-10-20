#pragma once
#include <functional>
#include <string>

namespace mock { class Workbench; }

// Optional live-data connection. The existing mock window needs no provider.
// The provider owns tool execution/storage; these panels only draw its state.
struct WorkbenchIntegration {
  bool busy = false, loaded = false;
  std::string target = "No ARM64 file open", producer, evidence;
  std::function<void()> tick, open, analyze, cancel, saveNotes;
  std::function<void(const std::string&)> execute;
};
void ConfigureWorkbench(WorkbenchIntegration* integration);
mock::Workbench& WorkbenchModel();

// #pragma once prevents this header being included more than once in a source
// file. These declarations let main_macos.mm call functions whose implementations
// live in workbench.cpp; the header does not draw anything itself.

// Set the colors once when the app starts, then draw the layout each frame.
void SetWorkbenchStyle();
void DrawWorkbench();

// Native window adapters can warn before quitting with an unfinished edit.
// These functions do not depend on Cocoa, Win32, or a graphics API.
bool WorkbenchHasUnsavedNotes();
void DiscardWorkbenchNotes();
