// Compile the real panel implementation once in this test executable. This
// gives assertions read access to its private state without adding test-only
// functions to the shipped GUI. User actions below still go through ImGui input.
#include "../workbench.cpp"
#include "imgui_internal.h"
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <map>
#include <stdexcept>

namespace test {
struct Item {
  ImRect bounds;
  ImRect clip;
  std::string label, window;
  bool disabled = false;
};
std::map<ImGuiID, Item> items;
int checks = 0;

void Check(bool passed, const char* expression, int line) {
  ++checks;
  if (!passed)
    throw std::runtime_error("Line " + std::to_string(line) + ": " + expression);
}
#define CHECK(expression) test::Check(bool(expression), #expression, __LINE__)

// This small driver advances real ImGui frames with a predictable clock. It
// produces drawing commands, but needs no Cocoa, Win32, Metal, or D3D renderer.
class Gui {
public:
  Gui() {
    ImGui::CreateContext();
    auto& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    io.DisplaySize = ImVec2(1400, 850);
    io.ConfigMacOSXBehaviors = false; // Ctrl+A means select-all on every test host.
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    SetWorkbenchStyle();
    unsigned char* pixels = nullptr;
    int width = 0, height = 0;
    io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
    CHECK(pixels && width > 0 && height > 0);
    ImGui::GetCurrentContext()->TestEngineHookItems = true;
    Frame(3); // Give auto-sized windows and tables time to settle.
  }
  ~Gui() { ImGui::DestroyContext(); }

  void Frame(int count = 1) {
    for (int i = 0; i < count; ++i) {
      items.clear();
      ImGui::GetIO().DeltaTime = 1.0f / 60.0f;
      ImGui::NewFrame();
      DrawWorkbench();
      ImGui::Render();
      const auto* draw = ImGui::GetDrawData();
      CHECK(draw && draw->Valid && draw->TotalVtxCount > 0);
    }
  }

  Item Find(const std::string& label, const std::string& window = "", int occurrence = -1) const {
    std::vector<Item> matches;
    for (const auto& [id, item] : items) {
      // '=' requests an exact window name, distinguishing a header button from
      // an identically named tab in a descendant window.
      const bool inWindow = window.starts_with('=') ? item.window == window.substr(1) :
                                                    item.window.find(window) != std::string::npos;
      bool matchesLabel = item.label == label;
      // BeginCombo records a rectangle but no label hook in this ImGui version.
      // Resolve an unlabeled top-level control using its window's normal ID hash.
      if (item.label.empty()) {
        const auto* owner = ImGui::FindWindowByName(item.window.c_str());
        matchesLabel = owner && id == ImHashStr(label.c_str(), 0, owner->ID);
      }
      if (matchesLabel && inWindow) matches.push_back(item);
    }
    if (matches.empty()) throw std::runtime_error("Missing control: " + label);
    if (occurrence < 0 && matches.size() != 1)
      throw std::runtime_error("Ambiguous control: " + label);
    return matches.at(occurrence < 0 ? 0 : occurrence);
  }

  void Click(const std::string& label, const std::string& window = "", int occurrence = -1) {
    const auto item = Find(label, window, occurrence);
    // Intersect with the visible region: a wide code row may scroll horizontally.
    ImRect visible = item.bounds;
    visible.ClipWith(item.clip);
    CHECK(visible.GetWidth() > 0 && visible.GetHeight() > 0);
    const auto point = visible.GetCenter();
    auto& io = ImGui::GetIO();
    io.AddMousePosEvent(point.x, point.y);
    Frame();
    io.AddMouseButtonEvent(0, true);
    Frame();
    io.AddMouseButtonEvent(0, false);
    // A tab change reveals its input next frame, then keyboard focus is applied
    // on the following frame. Settle both before sending typed characters.
    Frame(3);
  }

  void Key(ImGuiKey key) {
    ImGui::GetIO().AddKeyEvent(key, true);
    Frame();
    ImGui::GetIO().AddKeyEvent(key, false);
    Frame(2); // Enter can submit a command and request focus for the next one.
  }

  void Type(const std::string& text) {
    ImGui::GetIO().AddInputCharactersUTF8(text.c_str());
    Frame(2);
  }

  void Fill(const std::string& label, const std::string& text) {
    Click(label);
    ImGui::GetIO().AddKeyEvent(ImGuiMod_Ctrl, true);
    Key(ImGuiKey_A);
    ImGui::GetIO().AddKeyEvent(ImGuiMod_Ctrl, false);
    Frame();
    Key(ImGuiKey_Backspace);
    Type(text);
  }

  ImRect Pane(const std::string& name) const {
    // Child window names include a generated suffix, so match the panel segment.
    const auto segment = "/" + name + "_";
    const ImGuiWindow* result = nullptr;
    for (const auto* window : ImGui::GetCurrentContext()->Windows) {
      if (window->Active && std::string(window->Name).find(segment) != std::string::npos) {
        // Descendants also contain the segment; select the pane itself.
        if (std::string(window->Name).find('/', std::string(window->Name).find(segment) + 1) == std::string::npos)
          result = window;
      }
    }
    if (!result) throw std::runtime_error("Missing pane: " + name);
    return result->Rect();
  }

  void Resize(float width, float height) {
    ImGui::GetIO().DisplaySize = ImVec2(width, height);
    Frame(3);
  }

  void Drag(ImVec2 from, ImVec2 to) {
    auto& io = ImGui::GetIO();
    io.AddMousePosEvent(from.x, from.y);
    Frame(3);
    io.AddMouseButtonEvent(0, true);
    Frame(2);
    // Intermediate frames let the table resize code process a held mouse drag.
    for (int step = 1; step <= 5; ++step) {
      io.AddMousePosEvent(from.x + (to.x - from.x) * step / 5,
                          from.y + (to.y - from.y) * step / 5);
      Frame();
    }
    io.AddMouseButtonEvent(0, false);
    Frame(3);
  }
};

bool Near(float a, float b) { return std::abs(a - b) < 3.0f; }

void Layouts() {
  Gui gui;
  auto source = gui.Pane("Pseudocode");
  auto assembly = gui.Pane("Assembly");
  CHECK(source.Max.y <= assembly.Min.y);
  CHECK(Near(source.Min.x, assembly.Min.x));
  CHECK(Near(source.GetWidth(), assembly.GetWidth()));
  gui.Click("decode_buffer", "Project panel");
  gui.Click("4          buf[i] ^= 0x5A;", "Code rows");
  CHECK(model.selected == 2 && model.line == 3);
  gui.Click("Add reference");
  gui.Fill("##Prompt", "Explain this selection");
  gui.Click("Console", "=IndagoRev mock workspace");
  gui.Type("status");
  gui.Key(ImGuiKey_Enter);
  CHECK(!model.history.empty());
  CHECK(model.history.back() == "status");
  const auto project = gui.Pane("Project panel");
  const auto agent = gui.Pane("Agent panel");
  gui.Click("Compare layout");
  source = gui.Pane("Pseudocode");
  assembly = gui.Pane("Assembly");
  const auto inspector = gui.Pane("Inspector");
  CHECK(source.Max.x <= assembly.Min.x);
  CHECK(Near(source.Min.y, assembly.Min.y));
  CHECK(Near(source.GetHeight(), assembly.GetHeight()));
  CHECK(inspector.Min.y >= source.Max.y);
  CHECK(inspector.Min.x <= source.Min.x && inspector.Max.x >= assembly.Max.x);
  CHECK(Near(project.GetWidth(), gui.Pane("Project panel").GetWidth()));
  CHECK(Near(agent.Min.x, gui.Pane("Agent panel").Min.x));
  CHECK(model.selected == 2 && model.line == 3);
  CHECK(model.references.size() == 1 && prompt == "Explain this selection");
  CHECK(!gui.Find("##Command").disabled); // Console tab remains active.
  const float divider = (source.Max.x + assembly.Min.x) * 0.5f;
  gui.Drag(ImVec2(divider, source.Min.y + 20), ImVec2(divider + 70, source.Min.y + 20));
  CHECK(gui.Pane("Pseudocode").GetWidth() > source.GetWidth() + 40);
  gui.Click("Stacked layout");
  CHECK(gui.Pane("Pseudocode").Max.y <= gui.Pane("Assembly").Min.y);
  CHECK(model.references.front().text.find("0x5A") != std::string::npos);
  CHECK(model.history.back() == "status");
  for (const auto size : {ImVec2(1000, 680), ImVec2(1800, 1000)}) {
    gui.Resize(size.x, size.y);
    gui.Click("Compare layout");
    CHECK(gui.Pane("Inspector").GetHeight() > 100);
    CHECK(gui.Pane("Assembly").GetWidth() > 100);
    CHECK(gui.Find("Add reference").clip.Overlaps(gui.Find("Add reference").bounds));
    gui.Click("Stacked layout");
  }
}

void Navigation() {
  Gui gui;
  gui.Click("decode_buffer", "Project panel");
  gui.Click("4          buf[i] ^= 0x5A;", "Code rows");
  CHECK(model.line == 3 && model.instruction == 1);
  ImGui::GetIO().AddKeyEvent(ImGuiMod_Shift, true);
  gui.Frame();
  gui.Click("2      for (size_t i = 0; i < n; ++i) {", "Code rows");
  ImGui::GetIO().AddKeyEvent(ImGuiMod_Shift, false);
  gui.Frame();
  CHECK(model.anchor == 3 && model.line == 1);
  gui.Click("Add reference");
  CHECK(model.references.front().firstLine == 1);
  CHECK(model.references.front().lastLine == 3);
  gui.Click("Compare layout");
  gui.Click("0x140001128\nxor byte ptr [rcx+rax], 5Ah", "Assembly rows");
  CHECK(model.line == 3 && model.anchor == 3 && model.instruction == 1);
  gui.Fill("##Address", "0x140001183");
  gui.Key(ImGuiKey_Enter);
  CHECK(model.selected == 3 && model.line == 1);
  gui.Fill("##Address", "unknown");
  gui.Click("Go");
  CHECK(model.selected == 3 && model.status.starts_with("Error:"));
  gui.Fill("##Function filter", "decode");
  CHECK(!gui.Find("decode_buffer", "Project panel").disabled);
  bool sawMain = false;
  for (const auto& [id, item] : items) sawMain |= item.label == "main";
  CHECK(!sawMain);
  gui.Fill("##Function filter", "");
  gui.Click("entry", "Project panel");
  gui.Click("0x14000100e\nret", "Assembly rows");
  CHECK(model.line == 0 && model.instruction == 3);
  CHECK(model.status.find("No exact mapping") != std::string::npos);
}

void Notes() {
  Gui gui;
  const auto original = model.notes;
  gui.Click("notes.md", "Project panel");
  // Spell UTF-8 bytes explicitly so this test also works with MSVC code pages.
  const std::string unicodeNote = "Unsaved UTF-8 note: caf\xC3\xA9\n100% retained";
  gui.Fill("##Notes", unicodeNote);
  CHECK(model.notes == unicodeNote);
  CHECK(WorkbenchHasUnsavedNotes());
  const auto draft = model.notes;
  gui.Click("Compare layout");
  CHECK(model.notes == draft && model.showNotes);
  CHECK(gui.Find("Replay analysis").disabled);
  CHECK(gui.Find("Send").disabled);
  gui.Click("main", "Project panel");
  CHECK(model.showNotes && model.selected == 0);
  CHECK(model.notes == draft);
  gui.Click("Save notes");
  CHECK(!WorkbenchHasUnsavedNotes() && model.savedNotes == draft);
  gui.Fill("##Notes", "Discard this replacement");
  gui.Click("Stacked layout");
  CHECK(WorkbenchHasUnsavedNotes());
  gui.Click("Discard changes");
  CHECK(model.notes == draft && model.notes != original);
  CHECK(!WorkbenchHasUnsavedNotes());
  gui.Click("main", "Project panel");
  CHECK(!model.showNotes && model.selected == 1);
}

void Chat() {
  Gui gui;
  CHECK(gui.Find("Send").disabled);
  gui.Click("decode_buffer", "Project panel");
  gui.Click("Add reference");
  gui.Fill("##Prompt", "Explain the loop");
  gui.Click("Send");
  CHECK(model.operation == mock::Operation::Chat && prompt.empty());
  CHECK(gui.Find("Send").disabled && gui.Find("Add reference").disabled);
  gui.Click("Compare layout");
  gui.Click("main", "Project panel");
  gui.Frame(170); // Advance the mock clock, not wall-clock time.
  CHECK(!model.Busy() && model.references.empty());
  CHECK(model.messages.back().text.find("decode_buffer") != std::string::npos);
  CHECK(model.messages.back().references.front().function == 2);
  // Both the question and answer show this captured citation; either must navigate.
  gui.Click("decode_buffer : 1-1", "Conversation", 0);
  CHECK(model.selected == 2);
  gui.Fill("##Prompt", "Stop this reply");
  gui.Click("Send");
  gui.Click("Stop reply");
  CHECK(!model.Busy() && model.messages.back().role == "Agent (cancelled)");
}

void Console() {
  Gui gui;
  gui.Click("Console", "=IndagoRev mock workspace");
  gui.Type("hel");
  gui.Key(ImGuiKey_Tab);
  CHECK(command == "help ");
  gui.Key(ImGuiKey_Enter);
  CHECK(command.empty() && model.history.back() == "help");
  gui.Type("goto 0x140001128");
  gui.Key(ImGuiKey_Enter);
  CHECK(model.selected == 2 && model.line == 3);
  gui.Type("unfinished draft");
  gui.Key(ImGuiKey_UpArrow);
  CHECK(command == "goto 0x140001128");
  gui.Key(ImGuiKey_DownArrow);
  CHECK(command == "unfinished draft");
  gui.Fill("##Command", "analyze");
  gui.Key(ImGuiKey_Enter);
  CHECK(model.operation == mock::Operation::Analysis);
  gui.Type("cancel");
  gui.Key(ImGuiKey_Enter);
  CHECK(!model.Busy());
  gui.Type("not-a-command");
  gui.Key(ImGuiKey_Enter);
  CHECK(model.status.find("Unknown command") != std::string::npos);
  const auto count = model.history.size();
  gui.Click("Clear", "Inspector");
  CHECK(model.console.empty() && model.history.size() == count);
}

void Annotations() {
  Gui gui;
  gui.Click("Add reference");
  gui.Click("Edits", "Inspector");
  gui.Click("Review change...");
  gui.Fill("After", "bad name");
  gui.Click("Apply annotation");
  CHECK(model.revision == 7 && model.functions[0].name == "entry");
  CHECK(model.references.size() == 1);
  CHECK(model.status.starts_with("Error:"));
  gui.Fill("After", "start_here");
  gui.Click("Apply annotation");
  CHECK(model.revision == 8 && model.functions[0].name == "start_here");
  CHECK(model.functions[0].code[0] == "int start_here(void) {");
  CHECK(model.references.empty());
  gui.Click("Review change...");
  gui.Fill("After", "cancelled_name");
  gui.Click("Cancel", "Review annotation");
  CHECK(model.functions[0].name == "start_here" && model.revision == 8);
}

void SettingsAndFailures() {
  Gui gui;
  gui.Click("Settings");
  gui.Click("Light theme");
  CHECK(ImGui::GetStyleColorVec4(ImGuiCol_WindowBg).x > 0.5f);
  gui.Click("Light theme");
  CHECK(ImGui::GetStyleColorVec4(ImGuiCol_WindowBg).x < 0.2f);
  gui.Click("Next operation");
  gui.Click("Partial analysis");
  gui.Click("Close settings");
  gui.Click("Replay analysis");
  CHECK(model.operation == mock::Operation::Analysis);
  CHECK(model.progress > 0 && model.progress < 1);
  gui.Click("Compare layout");
  CHECK(model.Busy()); // Changing the layout must not cancel an operation.
  gui.Frame(170);
  CHECK(model.partial && !model.Busy());
  CHECK(model.functions.size() == 4); // Partial replay retains saved listings.
  gui.Click("Replay analysis");
  gui.Click("Cancel operation");
  CHECK(!model.Busy() && model.partial);

  gui.Click("Settings");
  gui.Click("Next operation");
  gui.Click("Chat provider failure");
  gui.Click("Close settings");
  gui.Click("Add reference");
  gui.Fill("##Prompt", "Simulate a failure");
  gui.Click("Send");
  gui.Frame(170);
  CHECK(model.messages.back().role == "Agent (error)");
  CHECK(model.references.size() == 1);
  CHECK(!model.Busy());

  // A retry through the same controls should recover and consume the reference.
  gui.Click("Settings");
  gui.Click("Next operation");
  gui.Click("Normal demo");
  gui.Click("Close settings");
  gui.Fill("##Prompt", "Retry with the retained reference");
  gui.Click("Send");
  gui.Frame(170);
  CHECK(model.messages.back().role == "Agent (scripted)");
  CHECK(model.references.empty());
  CHECK(model.messages.back().references.size() == 1);
}
} // namespace test

// The vendored ImGui exposes item hooks when IMGUI_ENABLE_TEST_ENGINE is set.
// Record labels and geometry for robust targeting instead of hard-coded pixels.
// These hooks are compiled only into this test target, not the application.
void ImGuiTestEngineHook_ItemAdd(ImGuiContext* ctx, ImGuiID id, const ImRect& box,
                                const ImGuiLastItemData* data) {
  auto& item = test::items[id];
  item.bounds = box;
  item.clip = ctx->CurrentWindow->ClipRect;
  item.window = ctx->CurrentWindow->Name;
  item.disabled = data && (data->ItemFlags & ImGuiItemFlags_Disabled);
}
void ImGuiTestEngineHook_ItemInfo(ImGuiContext*, ImGuiID id, const char* label,
                                 ImGuiItemStatusFlags) {
  test::items[id].label = label ? label : "";
}
void ImGuiTestEngineHook_Log(ImGuiContext*, const char*, ...) {}
const char* ImGuiTestEngine_FindItemDebugLabel(ImGuiContext*, ImGuiID id) {
  const auto found = test::items.find(id);
  return found == test::items.end() ? nullptr : found->second.label.c_str();
}

int main(int argc, char** argv) {
  const std::map<std::string, void(*)()> cases = {
      {"layouts", test::Layouts}, {"navigation", test::Navigation},
      {"notes", test::Notes}, {"chat", test::Chat},
      {"console", test::Console}, {"annotations", test::Annotations},
      {"settings", test::SettingsAndFailures}};
  try {
    if (argc != 2 || !cases.contains(argv[1]))
      throw std::runtime_error("Supply a registered GUI test case name.");
    cases.at(argv[1])();
    std::cout << argv[1] << ": " << test::checks << " checks passed\n";
    return EXIT_SUCCESS;
  } catch (const std::exception& error) {
    std::cerr << "GUI test failed: " << error.what() << '\n';
    return EXIT_FAILURE;
  }
}
