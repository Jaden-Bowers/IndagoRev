// This file opens the Mac window. The visible GUI is in workbench.cpp.
// Based on Dear ImGui's MIT-licensed example_apple_metal at our vendored pin.
// The .mm extension means Objective-C++: C++ and Apple's Objective-C can coexist.
// [object method] calls an Objective-C method; @"text" is an Apple string object.
#import <Cocoa/Cocoa.h>
#import <MetalKit/MetalKit.h>
#include "imgui.h"
#include "imgui_impl_osx.h"
#include "imgui_impl_metal.h"
#include "workbench.hpp"
#ifdef INDAGO_MAC_LIVE
#include "controller.hpp"
#endif

// A delegate receives callbacks from macOS. This object handles both app events
// (launch/quit) and requests from the Metal view to draw another frame.
// "strong" properties keep these objects alive; ARC releases them automatically.
@interface WorkbenchApp : NSObject <NSApplicationDelegate, NSWindowDelegate, MTKViewDelegate>
@property(nonatomic, strong) NSWindow* window;
@property(nonatomic, strong) MTKView* view;
@property(nonatomic, strong) id<MTLCommandQueue> queue;
@end

@implementation WorkbenchApp
- (void)applicationDidFinishLaunching:(NSNotification*)notification {
  // The device represents the GPU; the queue accepts batches of drawing work.
  // macOS calls this setup method once, after the application has launched.
  id<MTLDevice> device = MTLCreateSystemDefaultDevice();
  self.queue = [device newCommandQueue];
  if (!device || !self.queue) {
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = @"IndagoRev could not start Metal.";
    [alert runModal];
    [NSApp terminate:nil];
    return;
  }

  // Window sizes use logical points. Retina screens may use multiple physical
  // pixels per point; the frame loop supplies that scale to ImGui below.
  NSRect bounds = NSMakeRect(0, 0, 1400, 850);
  self.window = [[NSWindow alloc] initWithContentRect:bounds
      styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                NSWindowStyleMaskResizable | NSWindowStyleMaskMiniaturizable
      backing:NSBackingStoreBuffered defer:NO];
  self.window.title = @"IndagoRev - Mock Workbench";
#ifdef INDAGO_MAC_LIVE
  self.window.title = @"IndagoRev - macOS ARM64";
  InitializeMacWorkbench();
#endif
  self.window.contentMinSize = NSMakeSize(1000, 680);
  self.window.releasedWhenClosed = NO;
  self.window.delegate = self;
  // NSWindow supplies the title bar and resizing. MTKView is the drawable area
  // inside it, where Metal displays the GUI.
  self.view = [[MTKView alloc] initWithFrame:bounds device:device];
  self.view.clearColor = MTLClearColorMake(0.08, 0.10, 0.13, 1);
  self.view.preferredFramesPerSecond = 60;
  self.window.contentView = self.view;

  // The context owns ImGui's state. We disable automatic imgui.ini files for
  // now, so launching this mock does not write layout settings beside the app.
  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGui::GetIO().IniFilename = nullptr;
  ImGui::GetIO().ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
  SetWorkbenchStyle();
  // The Metal backend draws; the OSX backend supplies mouse/keyboard input.
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
  // The pass describes the render target; the drawable is the image that will
  // reach the screen. They may be unavailable while the window is minimized.
  MTLRenderPassDescriptor* pass = view.currentRenderPassDescriptor;
  id<CAMetalDrawable> drawable = view.currentDrawable;
  if (!pass || !drawable)
    return;
  // io is a reference to ImGui's input/display settings, not a separate copy.
  ImGuiIO& io = ImGui::GetIO();
  io.DisplaySize = ImVec2(view.bounds.size.width, view.bounds.size.height);
  const CGFloat scale = view.window.backingScaleFactor;
  io.DisplayFramebufferScale = ImVec2(scale, scale);
  // Prepare the backends, begin the UI frame, describe the widgets, then turn
  // those descriptions into drawing commands. Render() does not display them.
  ImGui_ImplMetal_NewFrame(pass);
  ImGui_ImplOSX_NewFrame(view);
  ImGui::NewFrame();
  DrawWorkbench();
  ImGui::Render();

  // The encoder records GPU work into a command buffer. Present schedules the
  // finished image for display; commit submits the recorded work to the GPU.
  id<MTLCommandBuffer> commands = [self.queue commandBuffer];
  id<MTLRenderCommandEncoder> encoder = [commands renderCommandEncoderWithDescriptor:pass];
  ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), commands, encoder);
  [encoder endEncoding];
  [commands presentDrawable:drawable];
  [commands commit];
#ifdef INDAGO_MAC_LIVE
  if (MacWorkbenchSmokeTesting()) {
    // Only diagnostic runs wait here; normal interactive frames stay asynchronous.
    [commands waitUntilCompleted];
    MacWorkbenchRendered(commands.status == MTLCommandBufferStatusCompleted);
  }
#endif
}

- (void)mtkView:(MTKView*)view drawableSizeWillChange:(CGSize)size {
  // The next frame reads the new window size in drawInMTKView.
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)app {
  return YES;
}

// Both the red close button and Command-Q use this check. Cancelling the alert
// must leave the window visible, so windowShouldClose checks before it closes.
- (BOOL)confirmDiscardNotes {
  if (!WorkbenchHasUnsavedNotes())
    return YES;
  NSAlert* alert = [[NSAlert alloc] init];
  alert.messageText = @"Discard unsaved mock notes?";
  alert.informativeText = @"Notes are kept only for this session. Cancel to copy them before quitting.";
#ifdef INDAGO_MAC_LIVE
  alert.messageText = @"Discard unsaved notes?";
  alert.informativeText = @"Saved notes remain on disk. Cancel to save your changes before quitting.";
#endif
  [alert addButtonWithTitle:@"Cancel"];
  [alert addButtonWithTitle:@"Discard and quit"];
  if ([alert runModal] != NSAlertSecondButtonReturn)
    return NO;
  DiscardWorkbenchNotes();
  return YES;
}

- (BOOL)windowShouldClose:(NSWindow*)sender {
  return [self confirmDiscardNotes];
}

- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication*)sender {
  return [self confirmDiscardNotes] ? NSTerminateNow : NSTerminateCancel;
}

- (void)applicationWillTerminate:(NSNotification*)notification {
#ifdef INDAGO_MAC_LIVE
  ShutdownMacWorkbench();
#endif
  // Startup can fail before creating the context, so only clean it up if it exists.
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
  // Apple uses this pool to release temporary Objective-C objects. [NSApp run]
  // runs the event loop until quit, delivering input and the callbacks above.
  @autoreleasepool {
    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    WorkbenchApp* app = [[WorkbenchApp alloc] init];
    NSApp.delegate = app;
    [NSApp run];
  }
  return 0;
}
