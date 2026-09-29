#include "workbench.hpp"
#include "imgui.h"

// Dear ImGui uses "immediate mode": we describe the visible controls again on
// every frame. Values that must survive between frames are stored separately.
// Read DrawWorkbench() at the bottom first to see how the panels fit together.

// An unnamed namespace keeps these helper functions and variables private to
// this source file. Only the functions declared in workbench.hpp are shared.
namespace {
// All content is invented sample text. Selecting a row never runs a tool.
// A struct groups the four pieces of text that describe one sample function.
// Each const char* points to a string literal whose characters cannot be edited.
struct MockFunction {
  const char* name;
  const char* address;
  const char* pseudocode;
  const char* assembly;
};

// Each {...} is one function. Adjacent quoted strings are joined by C++, and
// \n inside a string starts a new line when ImGui displays it.
const MockFunction functions[] = {
    {"entry", "0x140001000",
     "int entry(void) {\n    initialize_runtime();\n    return main();\n}",
     "0x140001000   sub rsp, 28h\n0x140001004   call initialize_runtime\n"
     "0x140001009   call main\n0x14000100e   ret"},
    {"main", "0x140001060",
     "int main(void) {\n    decode_buffer(buf, size);\n    return check_result(buf);\n}",
     "0x140001060   sub rsp, 28h\n0x140001064   call decode_buffer\n"
     "0x140001069   call check_result\n0x14000106e   ret"},
    {"decode_buffer", "0x140001120",
     "void decode_buffer(byte *buf, size_t n) {\n    for (size_t i = 0; i < n; ++i) {\n"
     "        buf[i] ^= 0x5A;\n    }\n}",
     "0x140001120   xor eax, eax\n0x140001128   xor byte ptr [rcx+rax], 5Ah\n"
     "0x14000112c   inc rax\n0x14000112f   cmp rax, rdx\n0x140001132   jb 0x140001128"},
    {"check_result", "0x140001180",
     "bool check_result(const byte *buf) {\n    return buf[0] == 0x48;\n}",
     "0x140001180   cmp byte ptr [rcx], 48h\n0x140001183   sete al\n0x140001186   ret"},
};
// This is an array index: 0 selects entry. Keeping it outside the drawing
// functions preserves the selection instead of resetting it every frame.
int selectedFunction = 0;

void DrawHeader() {
  // TextUnformatted displays text literally. SameLine keeps the next item on
  // this row; otherwise ImGui normally moves down to the next row.
  ImGui::TextUnformatted("[i]  IndagoRev / Decoder study");
  ImGui::SameLine();
  ImGui::TextColored(ImVec4(0.93f, 0.76f, 0.46f, 1), "MOCK DATA");
  ImGui::Separator();
  ImGui::TextUnformatted("sample-decoder.exe");
  ImGui::SameLine();
  ImGui::TextDisabled("PE / x64   |   Synthetic sample");
  ImGui::Separator();
}

void DrawProject() {
  ImGui::SeparatorText("Project");
  ImGui::TextUnformatted("decoder-study");
  // Indent/Unindent visually nest the sample files under their project.
  ImGui::Indent();
  ImGui::TextUnformatted("sample-decoder.exe");
  ImGui::TextDisabled("notes.md");
  ImGui::Unindent();
  ImGui::Spacing();
  ImGui::SeparatorText("Functions");
  // IM_ARRAYSIZE gives the number of entries in this fixed-size C++ array.
  // The second Selectable argument decides which row gets the highlight.
  for (int i = 0; i < IM_ARRAYSIZE(functions); ++i) {
    // A selectable returns true only on the frame when it is clicked.
    if (ImGui::Selectable(functions[i].name, selectedFunction == i))
      selectedFunction = i;
    ImGui::TextDisabled("%s", functions[i].address);
    ImGui::Spacing();
  }
}

void DrawCode() {
  // & makes this a reference to the selected record, rather than a copy.
  // const prevents this function from changing the mock record through it.
  const MockFunction& function = functions[selectedFunction];
  const float height = ImGui::GetContentRegionAvail().y;
  // ImVec2 holds a width and height. The first two child panels receive 52%
  // and 25% of the available height; the inspector uses the rest after spacing.
  // Positive heights reserve space. Zero lets the last panel fill the rest.
  if (ImGui::BeginChild("Pseudocode", ImVec2(0, height * 0.52f),
                        ImGuiChildFlags_Borders)) {
    ImGui::SeparatorText("Pseudocode");
    ImGui::TextDisabled("%s / %s", function.name, function.address);
    ImGui::Separator();
    ImGui::TextUnformatted(function.pseudocode);
  }
  // Every BeginChild needs EndChild, including when its contents are clipped.
  ImGui::EndChild();
  if (ImGui::BeginChild("Assembly", ImVec2(0, height * 0.25f),
                        ImGuiChildFlags_Borders)) {
    ImGui::SeparatorText("Assembly");
    ImGui::TextUnformatted(function.assembly);
  }
  ImGui::EndChild();
  if (ImGui::BeginChild("Inspector", ImVec2(0, 0), ImGuiChildFlags_Borders)) {
    // BeginTabItem is true for the visible tab. EndTabItem and EndTabBar are
    // called only when their matching Begin call returns true.
    if (ImGui::BeginTabBar("Inspector tabs")) {
      if (ImGui::BeginTabItem("Evidence")) {
        ImGui::TextUnformatted("Synthetic example / no analysis performed");
        ImGui::Text("Function: %s", function.name);
        ImGui::Text("Address:  %s", function.address);
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Edits")) {
        ImGui::TextWrapped("Editing will be added in a later step.");
        ImGui::EndTabItem();
      }
      if (ImGui::BeginTabItem("Activity")) {
        ImGui::TextWrapped("Mock project opened. No tools are running.");
        ImGui::EndTabItem();
      }
      ImGui::EndTabBar();
    }
  }
  ImGui::EndChild();
}

void DrawAgent() {
  ImGui::SeparatorText("Agent");
  // Reserve room for the 100-pixel text box and the surrounding control rows.
  // A negative child height means "fill the space, leaving this much below".
  const float composerHeight = 100 + ImGui::GetFrameHeightWithSpacing() * 3;
  if (ImGui::BeginChild("Conversation", ImVec2(0, -composerHeight))) {
    ImGui::TextDisabled("Pair mode / placeholder");
    ImGui::Spacing();
    ImGui::TextWrapped("The agent conversation will appear here.");
    ImGui::TextWrapped("This first version only displays the layout and mock code.");
  }
  ImGui::EndChild();
  ImGui::TextUnformatted("Ask about the selected code");
  // Disabled controls show their future position without suggesting they work.
  ImGui::BeginDisabled();
  // This one-character buffer holds only the terminating '\0' of an empty
  // C string. A working editor will need a larger buffer that survives frames.
  char prompt[1] = {};
  // "##Prompt" is an internal widget ID with no visible label. -1 uses almost
  // all available width, while 100 is the requested text-box height.
  ImGui::InputTextMultiline("##Prompt", prompt, sizeof(prompt), ImVec2(-1, 100));
  ImGui::Button("Send");
  ImGui::EndDisabled();
  ImGui::TextDisabled("No provider connected");
}
} // namespace

void SetWorkbenchStyle() {
  ImGui::StyleColorsDark();
  // GetStyle returns a reference to ImGui's shared style, so assignments below
  // change the actual interface. This setup runs once, when the app starts.
  ImGuiStyle& style = ImGui::GetStyle();
  style.FontSizeBase = 16.0f;
  style.WindowPadding = ImVec2(10, 10);
  style.FramePadding = ImVec2(8, 5);
  style.ItemSpacing = ImVec2(8, 8);
  style.ChildRounding = 0;
  style.FrameRounding = 3;
  // ImVec4 color values are red, green, blue, and opacity, each from 0 to 1.
  style.Colors[ImGuiCol_WindowBg] = ImVec4(0.08f, 0.10f, 0.13f, 1);
  style.Colors[ImGuiCol_ChildBg] = ImVec4(0.10f, 0.13f, 0.17f, 1);
  style.Colors[ImGuiCol_Text] = ImVec4(0.85f, 0.89f, 0.93f, 1);
  style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.60f, 0.67f, 0.75f, 1);
  style.Colors[ImGuiCol_Border] = ImVec4(0.21f, 0.26f, 0.32f, 1);
  style.Colors[ImGuiCol_Header] = ImVec4(0.14f, 0.24f, 0.36f, 1);
}

void DrawWorkbench() {
  // The viewport describes the app's drawing area. These "SetNext" calls apply
  // to the next Begin call, making this ImGui container fill the native window.
  const ImGuiViewport* viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(viewport->WorkSize);
  // | combines options: no extra ImGui title bar, no dragging this container,
  // and no saved position. The surrounding macOS window still moves/resizes.
  const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration |
                                ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings;
  if (ImGui::Begin("IndagoRev mock workspace", nullptr, flags)) {
    DrawHeader();
    // Leave one row below the workspace for the status text.
    const float statusHeight = ImGui::GetFrameHeightWithSpacing();
    if (ImGui::BeginChild("Workspace", ImVec2(0, -statusHeight))) {
      // A single table row provides three resizable layout columns. Project
      // and Agent have starting widths; Code stretches into the remaining room.
      if (ImGui::BeginTable("Columns", 3, ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Project", ImGuiTableColumnFlags_WidthFixed, 210);
        ImGui::TableSetupColumn("Code", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Agent", ImGuiTableColumnFlags_WidthFixed, 280);
        ImGui::TableNextRow();
        // Each TableNextColumn moves the drawing position into the next column.
        // Child containers give the panels their own boundaries and scrolling.
        ImGui::TableNextColumn();
        if (ImGui::BeginChild("Project panel", ImVec2(0, 0), ImGuiChildFlags_Borders))
          DrawProject();
        ImGui::EndChild();
        ImGui::TableNextColumn();
        if (ImGui::BeginChild("Code panels", ImVec2(0, 0)))
          DrawCode();
        ImGui::EndChild();
        ImGui::TableNextColumn();
        if (ImGui::BeginChild("Agent panel", ImVec2(0, 0), ImGuiChildFlags_Borders))
          DrawAgent();
        ImGui::EndChild();
        ImGui::EndTable();
      }
    }
    ImGui::EndChild();
    ImGui::TextDisabled("Mock data / select a function to explore the layout");
  }
  // Like BeginChild/EndChild, Begin/End must be paired even if Begin is false.
  ImGui::End();
}
