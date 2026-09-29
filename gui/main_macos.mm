// This file opens the Mac window. The visible GUI is in workbench.cpp.
// Based on Dear ImGui's MIT-licensed example_apple_metal at our vendored pin.
#import <Cocoa/Cocoa.h>
#import <MetalKit/MetalKit.h>
#include "imgui.h"
#include "imgui_impl_osx.h"
#include "imgui_impl_metal.h"
#include "workbench.hpp"

@interface WorkbenchApp : NSObject <NSApplicationDelegate, MTKViewDelegate>
@property(nonatomic, strong) NSWindow* window;
@property(nonatomic, strong) MTKView* view;
@property(nonatomic, strong) id<MTLCommandQueue> queue;
@end

@implementation WorkbenchApp
- (void)applicationDidFinishLaunching:(NSNotification*)notification {
  id<MTLDevice> device = MTLCreateSystemDefaultDevice();
  self.queue = [device newCommandQueue];
  if (!device || !self.queue) {
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = @"IndagoRev could not start Metal.";
    [alert runModal];
    [NSApp terminate:nil];
    return;
  }

  NSRect bounds = NSMakeRect(0, 0, 1400, 850);
  self.window = [[NSWindow alloc] initWithContentRect:bounds
      styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable
      backing:NSBackingStoreBuffered defer:NO];
  self.window.title = @"IndagoRev - Mock Workbench";
  self.window.contentMinSize = NSMakeSize(1000, 680);
  self.window.releasedWhenClosed = NO;
  self.view = [[MTKView alloc] initWithFrame:bounds device:device];
  self.view.clearColor = MTLClearColorMake(0.08, 0.10, 0.13, 1);
  self.view.preferredFramesPerSecond = 60;
  self.window.contentView = self.view;

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGui::GetIO().IniFilename = nullptr;
  ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  SetWorkbenchStyle();
  ImGui_ImplMetal_Init(device);
  ImGui_ImplOSX_Init(self.view);
  self.view.delegate = self;

  // A normal Mac Quit menu also makes Command-Q work.
  NSMenu* menu = [[NSMenu alloc] init];
  NSMenuItem* appItem = [[NSMenuItem alloc] init];
  NSMenu* appMenu = [[NSMenu alloc] initWithTitle:@"IndagoRev"];
  [appMenu addItemWithTitle:@"Quit IndagoRev" action:@selector(terminate:) keyEquivalent:@"q"];
  appItem.submenu = appMenu;
  [menu addItem:appItem];
  NSApp.mainMenu = menu;
  [self.window center];
  [self.window makeKeyAndOrderFront:nil];
  [NSApp activateIgnoringOtherApps:YES];
}

// Metal calls this method every frame. ImGui describes what to draw;
// the official Metal backend turns those instructions into visible pixels.
- (void)drawInMTKView:(MTKView*)view {
  MTLRenderPassDescriptor* pass = view.currentRenderPassDescriptor;
  id<CAMetalDrawable> drawable = view.currentDrawable;
  if (!pass || !drawable)
    return;
  ImGuiIO& io = ImGui::GetIO();
  io.DisplaySize = ImVec2(view.bounds.size.width, view.bounds.size.height);
  const CGFloat scale = view.window.backingScaleFactor;
  io.DisplayFramebufferScale = ImVec2(scale, scale);
  ImGui_ImplMetal_NewFrame(pass);
  ImGui_ImplOSX_NewFrame(view);
  ImGui::NewFrame();
  DrawWorkbench();
  ImGui::Render();

  id<MTLCommandBuffer> commands = [self.queue commandBuffer];
  id<MTLRenderCommandEncoder> encoder = [commands renderCommandEncoderWithDescriptor:pass];
  ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), commands, encoder);
  [encoder endEncoding];
  [commands presentDrawable:drawable];
  [commands commit];
}

- (void)mtkView:(MTKView*)view drawableSizeWillChange:(CGSize)size {
  // The next frame reads the new window size in drawInMTKView.
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)app {
  return YES;
}

- (void)applicationWillTerminate:(NSNotification*)notification {
  if (!ImGui::GetCurrentContext())
    return;
  self.view.paused = YES;
  self.view.delegate = nil;
  // Finish queued drawing before releasing the renderer's resources.
  id<MTLCommandBuffer> last = [self.queue commandBuffer];
  [last commit];
  [last waitUntilCompleted];
  ImGui_ImplMetal_Shutdown();
  ImGui_ImplOSX_Shutdown();
  ImGui::DestroyContext();
}
@end

int main() {
  @autoreleasepool {
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    WorkbenchApp* app = [[WorkbenchApp alloc] init];
    NSApp.delegate = app;
    [NSApp run];
  }
  return 0;
}
