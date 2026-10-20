#import <Cocoa/Cocoa.h>
#include "controller.hpp"
#include <memory>

namespace {
std::unique_ptr<macbuild::Controller> controller;
}
void InitializeMacWorkbench() {
  macbuild::fs::path workspace = macbuild::fs::path(INDAGO_MAC_ROOT) / ".indago/mac-arm64";
  std::string initialFile;
  NSArray<NSString*>* arguments = NSProcessInfo.processInfo.arguments;
  for (NSUInteger i = 1; i + 1 < arguments.count; ++i) {
    if ([arguments[i] isEqualToString:@"--workspace"]) workspace = [arguments[++i] UTF8String];
    else if ([arguments[i] isEqualToString:@"--file"]) initialFile = [arguments[++i] UTF8String];
  }
  controller = std::make_unique<macbuild::Controller>(WorkbenchModel(), workspace);
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
