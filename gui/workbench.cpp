#include "workbench.hpp"
#include "mock_workbench.hpp"
#include "imgui.h"
#include "imgui_stdlib.h"
#include <algorithm>
#include <string>

// Dear ImGui redraws controls every frame. The model owns project data and
// actions; this file owns presentation details such as text fields and tabs.
// Start reading at DrawWorkbench() to see how the panels fit together.
namespace {
mock::Workbench model;
WorkbenchIntegration* live = nullptr;
// Layout is presentation state, not project data. Both views draw the same
// model, so changing views cannot reset a selection, draft, or running reply.
enum class Layout { Stacked, Compare };
Layout layout = Layout::Stacked;
ImGuiTextFilter functionFilter, consoleFilter;
std::string address, prompt, command;
bool selectConsole = false, focusConsole = false;
bool scrollChat = true, scrollConsole = true;
int editKind = 0, editFunction = -1, editRevision = 0;
std::string editValue, editBefore;
const char* editKinds[] = {"rename", "signature", "type"};

// Display external strings literally. Passing them as printf format strings
// would interpret any percent signs in notes, commands, or future tool output.
void Wrapped(const std::string& text) {
  ImGui::PushTextWrapPos(0);
  ImGui::TextUnformatted(text.c_str());
  ImGui::PopTextWrapPos();
}
void Heading(const char* text) { ImGui::SeparatorText(text); }

// Keep related controls together when they fit; otherwise let ImGui start a
// new row. Compare panes can be much narrower than the original stacked pane.
void SameLineIfFits(const char* label) {
  const auto& style = ImGui::GetStyle();
  const float width = ImGui::CalcTextSize(label).x + style.FramePadding.x * 2;
  const float right = ImGui::GetItemRectMax().x + style.ItemSpacing.x + width;
  const float edge = ImGui::GetWindowPos().x + ImGui::GetWindowContentRegionMax().x;
  if (right <= edge) ImGui::SameLine();
}

void DrawLayoutButton() {
  const bool compare = layout == Layout::Compare;
  const char* label = compare ? "Stacked layout" : "Compare layout";
  if (ImGui::Button(label))
    layout = compare ? Layout::Stacked : Layout::Compare;
  if (ImGui::IsItemHovered()) {
    ImGui::SetTooltip("%s", compare ? "Place pseudocode above assembly" :
                                     "Place pseudocode beside assembly");
  }
}

void DrawSettings() {
  if (!ImGui::BeginPopupModal("Settings", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) return;
  static bool light = false;
  if (ImGui::Checkbox("Light theme", &light)) {
    if (light) ImGui::StyleColorsLight();
    else SetWorkbenchStyle();
  }
  ImGui::SliderFloat("Text size", &ImGui::GetStyle().FontSizeBase, 13, 20, "%.0f");
  if (live) {
    Wrapped("Native macOS ARM64 / Ghidra static analysis. Notes and evidence are saved in the workspace. AI and live annotations are not connected.");
    if (ImGui::Button("Close settings")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
    return;
  }
  int scenario = static_cast<int>(model.scenario);
  ImGui::BeginDisabled(model.Busy());
  if (ImGui::Combo("Next operation", &scenario,
                   "Normal demo\0Partial analysis\0Chat provider failure\0"))
    model.scenario = static_cast<mock::Scenario>(scenario);
  ImGui::EndDisabled();
  ImGui::TextUnformatted("Provider: offline scripted replies\nContext budget: unknown\nSettings and edits last for this session only.");
  if (ImGui::Button("Close settings")) ImGui::CloseCurrentPopup();
  ImGui::EndPopup();
}

void DrawHeader() {
  if (live) {
    ImGui::TextUnformatted("[i]  IndagoRev / macOS ARM64");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.45f, 0.8f, 0.55f, 1), "REAL STATIC ANALYSIS");
    ImGui::SameLine();
    DrawLayoutButton();
    ImGui::SameLine();
    if (ImGui::Button("Console")) selectConsole = focusConsole = true;
    ImGui::SameLine();
    if (ImGui::Button("Settings")) ImGui::OpenPopup("Settings");
    DrawSettings();
    ImGui::Separator();
    Wrapped(live->target + " | Mach-O / ARM64 | " + live->producer);
    ImGui::BeginDisabled(live->busy || model.Dirty());
    if (ImGui::Button("Open app or ARM64 file...")) live->open();
    ImGui::SameLine();
    ImGui::BeginDisabled(!live->loaded);
    if (ImGui::Button("Analyze again")) live->analyze();
    ImGui::EndDisabled();
    ImGui::EndDisabled();
    if (live->busy) {
      ImGui::SameLine();
      if (ImGui::Button("Cancel analysis")) live->cancel();
      ImGui::SameLine();
      ImGui::TextUnformatted("Analyzing saved bytes; target is not running...");
    }
    ImGui::Separator();
    return;
  }
  ImGui::TextUnformatted("[i]  IndagoRev / Decoder study");
  ImGui::SameLine();
  ImGui::TextColored(ImVec4(0.85f, 0.60f, 0.20f, 1), "MOCK DATA");
  ImGui::SameLine();
  DrawLayoutButton();
  ImGui::SameLine();
  if (ImGui::Button("Console")) selectConsole = focusConsole = true;
  ImGui::SameLine();
  if (ImGui::Button("Settings")) ImGui::OpenPopup("Settings");
  DrawSettings();
  ImGui::Separator();
  ImGui::Text("sample-decoder.exe   |   PE / x64   |   Synthetic fixture   |   rev %d", model.revision);
  ImGui::SameLine();
  if (model.Busy()) {
    if (ImGui::Button("Cancel operation")) model.Cancel();
    ImGui::SameLine();
    ImGui::ProgressBar(model.progress, ImVec2(120, 0),
        model.operation == mock::Operation::Analysis ? "Analysis" : "Reply");
  } else {
    ImGui::BeginDisabled(model.Dirty());
    if (ImGui::Button("Replay analysis")) model.StartAnalysis();
    ImGui::EndDisabled();
  }
  ImGui::Separator();
}

void DrawProject() {
  Heading("Project");
  if (ImGui::TreeNodeEx(live ? "ARM64 project" : "decoder-study", ImGuiTreeNodeFlags_DefaultOpen)) {
    Wrapped(live ? live->target : "sample-decoder.exe");
    if (ImGui::Selectable(model.Dirty() ? "notes.md *" : "notes.md", model.showNotes))
      model.OpenNotes();
    ImGui::TreePop();
  }
  Heading("Functions");
  ImGui::TextDisabled("Filter name or address");
  functionFilter.Draw("##Function filter", -1);
  ImGui::SetNextItemWidth(-1);
  const bool go = ImGui::InputTextWithHint("##Address", "Go to address or name", &address,
                                          ImGuiInputTextFlags_EnterReturnsTrue);
  if (ImGui::Button("Go") || go) model.Navigate(address);
  ImGui::Separator();
  int visible = 0;
  for (int i = 0; i < static_cast<int>(model.functions.size()); ++i) {
    const auto& f = model.functions[i];
    const auto searchable = f.name + " " + f.address;
    if (!functionFilter.PassFilter(searchable.c_str())) continue;
    ++visible;
    // Stable IDs avoid collisions if two visible labels happen to match.
    ImGui::PushID(i);
    if (ImGui::Selectable(f.name.c_str(), !model.showNotes && model.selected == i))
      model.SelectFunction(i);
    ImGui::TextDisabled("%s", f.address.c_str());
    ImGui::Spacing();
    ImGui::PopID();
  }
  if (!visible) Wrapped(live ? "No matching functions. Open and analyze a file, or clear the filter." :
                               "No matching functions. Clear the filter to show all four.");
  if (model.Dirty()) Wrapped("Save or discard notes before navigating.");
}

void DrawNotes() {
  Heading("notes.md");
  Wrapped(live ? "Notes are saved alongside this project's immutable analysis evidence." :
                 "Session-only notes. Copy the text to keep it after closing the app.");
  ImGui::BeginDisabled(live && !live->loaded);
  if (ImGui::Button("Save notes")) { if (live) live->saveNotes(); else model.SaveNotes(); }
  ImGui::EndDisabled();
  SameLineIfFits("Discard changes");
  if (ImGui::Button("Discard changes")) model.DiscardNotes();
  SameLineIfFits("Copy notes");
  if (ImGui::Button("Copy notes")) ImGui::SetClipboardText(model.notes.c_str());
  ImGui::TextDisabled("%s", model.Dirty() ? "Unsaved changes" : live ? "Saved to project" : "Saved in this session");
  ImGui::BeginDisabled(live && !live->loaded);
  ImGui::InputTextMultiline("##Notes", &model.notes, ImVec2(-1, -1));
  ImGui::EndDisabled();
}

void DrawPseudocode() {
  if (model.functions.empty()) { Heading("Pseudocode"); Wrapped("Open an ARM64 Mach-O file to begin."); return; }
  const auto& f = model.functions[model.selected];
  Heading("Pseudocode");
  ImGui::TextDisabled("%s", f.name.c_str());
  SameLineIfFits(f.address.c_str());
  ImGui::TextDisabled("%s", f.address.c_str());
  ImGui::BeginDisabled(model.Busy() || model.Dirty());
  if (ImGui::Button("Add reference")) model.AddReference();
  ImGui::EndDisabled();
  SameLineIfFits("Shift-click for a range");
  ImGui::TextDisabled("Shift-click for a range");
  ImGui::Separator();
  // The inner child permits horizontal scrolling for long declarations.
  if (ImGui::BeginChild("Code rows", ImVec2(0, 0), 0, ImGuiWindowFlags_HorizontalScrollbar)) {
    for (int i = 0; i < static_cast<int>(f.code.size()); ++i) {
      ImGui::PushID(i);
      const auto label = std::to_string(i + 1) + "  " + f.code[i];
      const bool selected = i >= std::min(model.line, model.anchor) &&
                            i <= std::max(model.line, model.anchor);
      if (ImGui::Selectable(label.c_str(), selected, 0,
                            ImVec2(std::max(ImGui::GetContentRegionAvail().x,
                                           ImGui::CalcTextSize(label.c_str()).x), 0)))
        model.SelectLine(i, ImGui::GetIO().KeyShift);
      ImGui::PopID();
    }
  }
  ImGui::EndChild();
}

void DrawAssembly() {
  Heading("Assembly");
  if (model.functions.empty()) { Wrapped("No analyzed instructions yet."); return; }
  const auto& rows = model.functions[model.selected].assembly;
  const bool exact = model.instruction >= 0 && rows[model.instruction].codeLine >= 0;
  ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled));
  Wrapped(exact ? "Mapped to selected code" : "No exact mapping / containing function");
  ImGui::PopStyleColor();
  if (model.partial) Wrapped(live ? "Partial analysis: inspect the evidence diagnostics." :
                                   "Partial replay: showing the last saved fixture listing.");
  if (ImGui::BeginChild("Assembly rows", ImVec2(0, 0), 0, ImGuiWindowFlags_HorizontalScrollbar)) {
    for (int i = 0; i < static_cast<int>(rows.size()); ++i) {
      const auto& row = rows[i];
      // The reference design places the address above its instruction in the
      // narrower compare pane. The selectable still represents one instruction.
      const bool compare = layout == Layout::Compare;
      const auto label = row.address + (compare ? "\n" : "   ") + row.text;
      const float rowHeight = compare ? ImGui::GetTextLineHeight() * 2 : 0;
      const bool mapped = row.codeLine >= std::min(model.line, model.anchor) &&
                          row.codeLine <= std::max(model.line, model.anchor);
      ImGui::PushID(i);
      if (ImGui::Selectable(label.c_str(), i == model.instruction || mapped, 0,
                            ImVec2(std::max(ImGui::GetContentRegionAvail().x,
                                           ImGui::CalcTextSize(label.c_str()).x), rowHeight)))
        model.SelectInstruction(i);
      ImGui::PopID();
    }
  }
  ImGui::EndChild();
}

void DrawEvidence() {
  if (live) {
    Wrapped(live->evidence.empty() ? "No analysis evidence yet." : live->evidence);
    if (!model.functions.empty()) {
      const auto& f = model.functions[model.selected];
      Wrapped("Function: " + f.name + " / " + f.address);
      Wrapped(f.explanation);
    }
    return;
  }
  const auto& f = model.functions[model.selected];
  Wrapped("Backend evidence / synthetic fixture");
  ImGui::Text("Location: %s / lines %d-%d", f.name.c_str(),
      std::min(model.line, model.anchor) + 1, std::max(model.line, model.anchor) + 1);
  ImGui::Text("Producer: mock fixture / revision %d", model.revision);
  ImGui::Text("Evidence ID: demo-function-%d", model.selected);
  ImGui::Text("Completeness: %s", model.partial ? "Partial replay; saved listing" : "Complete fixture listing");
  if (ImGui::TreeNode("Selected evidence text")) {
    for (int i = std::min(model.line, model.anchor); i <= std::max(model.line, model.anchor); ++i)
      Wrapped(f.code[i]);
    ImGui::TreePop();
  }
}

void BeginEdit() {
  // Capture both identity and revision for the preview. A later selection must
  // not redirect the pending edit to a different function.
  editFunction = model.selected;
  editRevision = model.revision;
  const auto& f = model.functions[editFunction];
  editBefore = editKind == 0 ? f.name : editKind == 1 ? f.signature : f.variableType;
  editValue = editBefore;
  ImGui::OpenPopup("Review annotation");
}

void DrawEdits() {
  if (live) { Wrapped("Decompiler annotations are not connected in this milestone. Use project notes to retain your observations."); return; }
  Wrapped("Annotations are session-only user assertions. They do not patch a binary.");
  ImGui::SetNextItemWidth(160);
  ImGui::Combo("Annotation", &editKind, "Function name\0Signature\0Variable type\0");
  ImGui::BeginDisabled(model.Busy() || model.Dirty() || model.showNotes);
  if (ImGui::Button("Review change...")) BeginEdit();
  ImGui::EndDisabled();
  Wrapped("A rename updates this declaration; captured call-site text stays as supplied. Type changes update metadata only.");
  if (ImGui::BeginPopupModal("Review annotation", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
    ImGui::Text("Function: %s / revision %d", model.functions[editFunction].name.c_str(), editRevision);
    Wrapped("Before: " + editBefore);
    ImGui::SetNextItemWidth(480);
    if (editKind == 2) {
      if (ImGui::BeginCombo("After", editValue.c_str())) {
        for (const char* type : {"int", "unsigned int", "byte*", "const byte*", "size_t"})
          if (ImGui::Selectable(type, editValue == type)) editValue = type;
        ImGui::EndCombo();
      }
    } else ImGui::InputText("After", &editValue);
    Wrapped("Applying expires old citations and clears pending references.");
    if (ImGui::Button("Apply annotation")) {
      if (model.ApplyEdit(editFunction, editRevision, editKinds[editKind], editValue))
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
    Wrapped(model.status);
    ImGui::EndPopup();
  }
}

// ImGui calls this while the command input has focus. Its buffer-edit methods
// also keep the cursor and std::string adapter in sync; do not replace Buf.
int ConsoleCallback(ImGuiInputTextCallbackData* data) {
  std::string replacement;
  if (data->EventFlag == ImGuiInputTextFlags_CallbackHistory) {
    replacement = model.RecallHistory(data->EventKey == ImGuiKey_UpArrow ? -1 : 1, data->Buf);
  } else if (data->EventFlag == ImGuiInputTextFlags_CallbackCompletion) {
    auto matches = mock::Workbench::Completions(data->Buf);
    if (live) {
      matches.clear();
      for (const std::string item : {"help", "functions", "goto", "analyze", "cancel", "notes", "save", "status", "clear", "history"})
        if (item.starts_with(data->Buf)) matches.push_back(item);
    }
    if (matches.size() == 1) replacement = matches.front() + " ";
    else {
      std::string list = matches.empty() ? "No command matches." : "Commands:";
      for (const auto& match : matches) list += " " + match;
      model.Log(list);
      scrollConsole = true;
      return 0;
    }
  }
  data->DeleteChars(0, data->BufTextLen);
  data->InsertChars(0, replacement.c_str());
  return 0;
}

void DrawConsole() {
  if (ImGui::SmallButton("Clear")) model.console.clear();
  ImGui::SameLine();
  if (ImGui::SmallButton("Copy log")) {
    std::string text;
    for (const auto& row : model.console) text += row + "\n";
    ImGui::SetClipboardText(text.c_str());
  }
  ImGui::SameLine();
  consoleFilter.Draw("Filter", 130);
  const float inputHeight = ImGui::GetFrameHeightWithSpacing();
  if (ImGui::BeginChild("Console output", ImVec2(0, -inputHeight))) {
    for (const auto& row : model.console)
      if (consoleFilter.PassFilter(row.c_str())) Wrapped(row);
    if (scrollConsole) { ImGui::SetScrollHereY(1); scrollConsole = false; }
  }
  ImGui::EndChild();
  if (focusConsole) { ImGui::SetKeyboardFocusHere(); focusConsole = false; }
  ImGui::SetNextItemWidth(-1);
  const auto flags = ImGuiInputTextFlags_EnterReturnsTrue |
                     ImGuiInputTextFlags_CallbackHistory | ImGuiInputTextFlags_CallbackCompletion;
  if (ImGui::InputTextWithHint("##Command", "help / Up-Down history / Tab complete", &command, flags, ConsoleCallback)) {
    if (live) live->execute(command); else model.Execute(command);
    command.clear();
    scrollConsole = focusConsole = true;
  }
}

void DrawInspector() {
  if (!ImGui::BeginTabBar("Inspector tabs")) return;
  if (ImGui::BeginTabItem("Evidence")) { DrawEvidence(); ImGui::EndTabItem(); }
  if (ImGui::BeginTabItem("Edits")) { DrawEdits(); ImGui::EndTabItem(); }
  if (ImGui::BeginTabItem("Activity")) {
    for (auto it = model.activity.rbegin(); it != model.activity.rend(); ++it) Wrapped(*it);
    ImGui::EndTabItem();
  }
  if (ImGui::BeginTabItem("Console", nullptr, selectConsole ? ImGuiTabItemFlags_SetSelected : 0)) {
    DrawConsole(); ImGui::EndTabItem();
  }
  selectConsole = false;
  ImGui::EndTabBar();
}

void DrawSourcePane(float height) {
  if (ImGui::BeginChild("Pseudocode", ImVec2(0, height), ImGuiChildFlags_Borders)) {
    if (model.showNotes) DrawNotes(); else DrawPseudocode();
  }
  ImGui::EndChild();
}

void DrawAssemblyPane(float height) {
  if (ImGui::BeginChild("Assembly", ImVec2(0, height), ImGuiChildFlags_Borders))
    DrawAssembly();
  ImGui::EndChild();
}

void DrawStackedCode(float available) {
  // Preserve the original layout's proportions and independently scrolling panes.
  DrawSourcePane(available * 0.40f);
  DrawAssemblyPane(available * 0.25f);
}

void DrawCompareCode(float available) {
  // One table row places the existing panes beside each other. Equal starting
  // widths match GUI_Layout2; dragging their divider adjusts the comparison.
  // Explicit child heights bound the table so the inspector fits underneath.
  const auto flags = ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingStretchSame;
  if (ImGui::BeginTable("Compare code columns", 2, flags)) {
    ImGui::TableSetupColumn("Pseudocode", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn("Assembly", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableNextRow();
    ImGui::TableNextColumn();
    DrawSourcePane(available * 0.50f);
    ImGui::TableNextColumn();
    DrawAssemblyPane(available * 0.50f);
    ImGui::EndTable();
  }
}

void DrawCode() {
  const float available = ImGui::GetContentRegionAvail().y;
  if (layout == Layout::Compare)
    DrawCompareCode(available);
  else
    DrawStackedCode(available);
  // The inspector stays outside the compare table and spans both code panes.
  // Keeping its parent and ID unchanged also preserves the active inspector tab.
  if (ImGui::BeginChild("Inspector", ImVec2(0, 0), ImGuiChildFlags_Borders)) DrawInspector();
  ImGui::EndChild();
}

void DrawCitation(const mock::Reference& ref) {
  const bool stale = ref.revision != model.revision;
  const auto label = ref.name + " : " + std::to_string(ref.firstLine + 1) + "-" +
      std::to_string(ref.lastLine + 1) + (stale ? " (expired)" : "");
  ImGui::BeginDisabled(stale || model.Dirty());
  if (ImGui::SmallButton(label.c_str())) model.FollowReference(ref);
  ImGui::EndDisabled();
  if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
    ImGui::BeginTooltip();
    ImGui::PushTextWrapPos(ImGui::GetFontSize() * 32);
    ImGui::Text("Captured revision %d", ref.revision);
    ImGui::TextUnformatted(ref.text.c_str());
    ImGui::PopTextWrapPos();
    ImGui::EndTooltip();
  }
}

void DrawAgent() {
  if (live) {
    Heading("References");
    Wrapped("AI chat is not connected. These references quote the real decompiled listing; no scripted answer is presented as analysis.");
    for (const auto& ref : model.references) {
      ImGui::PushID(ref.id); DrawCitation(ref); ImGui::PopID();
    }
    return;
  }
  Heading("Agent / scripted preview");
  const float composerHeight = 100 + ImGui::GetFrameHeightWithSpacing() * 3 +
                               (model.references.empty() ? 0 : 86);
  if (ImGui::BeginChild("Conversation", ImVec2(0, -composerHeight))) {
    const bool atBottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 8;
    for (int i = 0; i < static_cast<int>(model.messages.size()); ++i) {
      ImGui::PushID(i);
      const auto& message = model.messages[i];
      ImGui::TextDisabled("%s", message.role.c_str());
      Wrapped(message.text);
      for (int j = 0; j < static_cast<int>(message.references.size()); ++j) {
        ImGui::PushID(j); DrawCitation(message.references[j]); ImGui::PopID();
      }
      ImGui::Separator();
      ImGui::PopID();
    }
    if (model.operation == mock::Operation::Chat) {
      ImGui::TextDisabled("Agent (streaming mock reply)");
      Wrapped(model.streaming);
    }
    if (scrollChat || atBottom) { ImGui::SetScrollHereY(1); scrollChat = false; }
  }
  ImGui::EndChild();
  if (!model.references.empty()) {
    int remove = -1;
    if (ImGui::BeginChild("Pending references", ImVec2(0, 78), ImGuiChildFlags_Borders)) {
      for (const auto& ref : model.references) {
        ImGui::PushID(ref.id);
        DrawCitation(ref);
        ImGui::SameLine();
        ImGui::BeginDisabled(model.Busy());
        if (ImGui::SmallButton("x")) remove = ref.id;
        ImGui::EndDisabled();
        ImGui::PopID();
      }
    }
    ImGui::EndChild();
    // Erase after iterating: changing the vector inside the loop invalidates refs.
    if (remove >= 0) model.RemoveReference(remove);
  }
  ImGui::TextUnformatted("Ask about the selected code");
  ImGui::InputTextMultiline("##Prompt", &prompt, ImVec2(-1, 100));
  ImGui::BeginDisabled(model.Busy() || model.Dirty() || model.showNotes || prompt.empty());
  if (ImGui::Button("Send")) {
    if (model.Send(prompt)) { prompt.clear(); scrollChat = true; }
  }
  ImGui::EndDisabled();
  if (model.operation == mock::Operation::Chat) {
    ImGui::SameLine();
    if (ImGui::Button("Stop reply")) model.Cancel();
  }
  ImGui::TextDisabled("Context unknown / offline mock");
}
} // namespace

void SetWorkbenchStyle() {
  ImGui::StyleColorsDark();
  ImGuiStyle& style = ImGui::GetStyle();
  style.FontSizeBase = 16;
  style.WindowPadding = ImVec2(10, 10);
  style.FramePadding = ImVec2(8, 5);
  style.ItemSpacing = ImVec2(8, 8);
  style.ChildRounding = 0;
  style.FrameRounding = 3;
  // Color components are red, green, blue and opacity, each between 0 and 1.
  style.Colors[ImGuiCol_WindowBg] = ImVec4(0.08f, 0.10f, 0.13f, 1);
  style.Colors[ImGuiCol_ChildBg] = ImVec4(0.10f, 0.13f, 0.17f, 1);
  style.Colors[ImGuiCol_Text] = ImVec4(0.85f, 0.89f, 0.93f, 1);
  style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.60f, 0.67f, 0.75f, 1);
  style.Colors[ImGuiCol_Border] = ImVec4(0.21f, 0.26f, 0.32f, 1);
  style.Colors[ImGuiCol_Header] = ImVec4(0.14f, 0.24f, 0.36f, 1);
}

bool WorkbenchHasUnsavedNotes() { return model.Dirty(); }
void DiscardWorkbenchNotes() { model.DiscardNotes(); }
void ConfigureWorkbench(WorkbenchIntegration* integration) { live = integration; }
mock::Workbench& WorkbenchModel() { return model; }

void DrawWorkbench() {
  // Time advances only mock progress; no worker threads or x64 tools are needed.
  if (live) live->tick(); else model.Tick(ImGui::GetIO().DeltaTime);
  const ImGuiViewport* viewport = ImGui::GetMainViewport();
  ImGui::SetNextWindowPos(viewport->WorkPos);
  ImGui::SetNextWindowSize(viewport->WorkSize);
  const auto flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoSavedSettings;
  if (ImGui::Begin("IndagoRev mock workspace", nullptr, flags)) {
    DrawHeader();
    if (ImGui::BeginChild("Workspace", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()))) {
      // The outer columns are shared by both layouts. Only DrawCode changes the
      // arrangement in the middle; project and chat keep their state and widths.
      if (ImGui::BeginTable("Columns", 3, ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Project", ImGuiTableColumnFlags_WidthFixed, 210);
        ImGui::TableSetupColumn("Code", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Agent", ImGuiTableColumnFlags_WidthFixed, 300);
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        if (ImGui::BeginChild("Project panel", ImVec2(0, 0), ImGuiChildFlags_Borders)) DrawProject();
        ImGui::EndChild();
        ImGui::TableNextColumn();
        if (ImGui::BeginChild("Code panels", ImVec2(0, 0))) DrawCode();
        ImGui::EndChild();
        ImGui::TableNextColumn();
        if (ImGui::BeginChild("Agent panel", ImVec2(0, 0), ImGuiChildFlags_Borders)) DrawAgent();
        ImGui::EndChild();
        ImGui::EndTable();
      }
    }
    ImGui::EndChild();
    ImGui::TextDisabled("%s", model.status.c_str());
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", model.status.c_str());
  }
  // Begin/End and BeginChild/EndChild must pair even when Begin returns false.
  ImGui::End();
}
