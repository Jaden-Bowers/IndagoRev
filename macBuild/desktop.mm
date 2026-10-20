#import <Cocoa/Cocoa.h>
#include "controller.hpp"
#include <memory>

namespace {
std::unique_ptr<macbuild::Controller> controller;
bool smokeTest = false;
macbuild::fs::path smokeReceipt;
int renderedFrames = 0;
}
void InitializeMacWorkbench() {
  macbuild::fs::path workspace = macbuild::fs::path(INDAGO_MAC_ROOT) / ".indago/mac-arm64";
  std::string initialFile;
  NSArray<NSString*>* arguments = NSProcessInfo.processInfo.arguments;
  smokeTest = [arguments containsObject:@"--smoke-test"];
  for (NSUInteger i = 1; i + 1 < arguments.count; ++i) {
    if ([arguments[i] isEqualToString:@"--workspace"]) workspace = [arguments[++i] UTF8String];
    else if ([arguments[i] isEqualToString:@"--file"]) initialFile = [arguments[++i] UTF8String];
  }
  controller = std::make_unique<macbuild::Controller>(WorkbenchModel(), workspace);
  smokeReceipt = workspace / "native-smoke.json";
  controller->view.open = [] {
    // File selection is the only Cocoa-dependent part of opening a project.
    NSOpenPanel* panel = [NSOpenPanel openPanel];
    panel.canChooseDirectories = NO;
    panel.allowsMultipleSelection = NO;
    panel.message = @"Choose an ARM64 Mach-O executable or dynamic library. It will be analyzed, not executed.";
    if ([panel runModal] == NSModalResponseOK) controller->Open(panel.URL.path.UTF8String);
  };
  ConfigureWorkbench(&controller->view);
  if (initialFile.empty()) controller->ResumeLastProject(); else controller->Open(initialFile);
}

void ShutdownMacWorkbench() {
  ConfigureWorkbench(nullptr);
  controller.reset();
}

bool MacWorkbenchSmokeTesting() { return smokeTest; }

void MacWorkbenchRendered(bool graphicsCompleted) {
  if (!smokeTest) return;
  ++renderedFrames;
  // A bounded diagnostic mode checks the real Cocoa/Metal window, not just
  // headless ImGui. It waits for analysis, writes a receipt, then quits normally.
  if (graphicsCompleted && renderedFrames < 3000 &&
      (renderedFrames < 30 || controller->view.busy)) return;
  const auto& state = WorkbenchModel();
  const bool passed = graphicsCompleted && !controller->view.busy && !state.functions.empty();
  macbuild::Json receipt{{"passed", passed}, {"metal_completed", graphicsCompleted},
      {"frames", renderedFrames}, {"functions", state.functions.size()},
      {"producer", controller->view.producer}, {"status", state.status}};
  try { macbuild::WriteAtomic(smokeReceipt, receipt.dump(2)); }
  catch (const std::exception& error) { NSLog(@"Smoke receipt failed: %s", error.what()); }
  smokeTest = false;
  [NSApp terminate:nil];
}
