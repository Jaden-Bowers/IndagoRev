// Include the actual panels, just as the existing GUI interaction tests do.
// This test supplies real Ghidra results rather than the synthetic fixture.
#include "../../gui/workbench.cpp"
#include "controller.hpp"
#include "imgui_internal.h"
#include <chrono>
#include <iostream>
#include <map>
#include <limits>
#include <thread>
#include <unistd.h>

namespace {
int checks = 0;
void Check(bool condition, const char* text, int line) {
  ++checks;
  if (!condition) throw std::runtime_error(std::string(text) + " at line " + std::to_string(line));
}
#define REQUIRE(c) Check(bool(c), #c, __LINE__)
template<class F> void Rejected(F action) {
  bool rejected = false;
  try { action(); } catch (const std::exception&) { rejected = true; }
  REQUIRE(rejected);
}
struct Control { ImRect rect; std::string label; };
std::map<ImGuiID, Control> controls;

void Frame() {
  controls.clear();
  ImGui::GetIO().DeltaTime = 1.0f / 60;
  ImGui::NewFrame(); DrawWorkbench(); ImGui::Render();
  REQUIRE(ImGui::GetDrawData()->Valid);
  REQUIRE(ImGui::GetDrawData()->TotalVtxCount > 0);
}
void Click(const std::string& label, bool textField = false) {
  auto found = std::find_if(controls.begin(), controls.end(), [&](const auto& item) {
    return item.second.label == label;
  });
  if (found == controls.end()) throw std::runtime_error("Missing GUI control: " + label);
  auto point = found->second.rect.GetCenter();
  if (textField) point.x = found->second.rect.Min.x + 15; // Avoid the field's label.
  auto& io = ImGui::GetIO();
  io.AddMousePosEvent(point.x, point.y); Frame();
  io.AddMouseButtonEvent(0, true); Frame();
  io.AddMouseButtonEvent(0, false); Frame(); Frame();
}
ImRect Pane(const std::string& name) {
  const std::string part = "/" + name + "_";
  for (const auto* window : ImGui::GetCurrentContext()->Windows) {
    const std::string path = window->Name;
    const auto position = path.find(part);
    if (window->Active && position != std::string::npos &&
        path.find('/', position + 1) == std::string::npos) return window->Rect();
  }
  throw std::runtime_error("Missing pane: " + name);
}
void Wait(macbuild::Controller& controller) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(200);
  while (controller.view.busy && std::chrono::steady_clock::now() < deadline) {
    controller.Tick();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  REQUIRE(!controller.view.busy);
}
void Put32(macbuild::Bytes& data, std::size_t at, std::uint32_t value) {
  for (int i = 0; i < 4; ++i) data[at + i] = (value >> (24 - 8 * i)) & 255;
}
void UniversalChecks(const macbuild::Bytes& thin) {
  macbuild::Bytes fat(4096 + thin.size());
  Put32(fat, 0, 0xcafebabe); Put32(fat, 4, 1);
  Put32(fat, 8, 0x0100000c); Put32(fat, 16, 4096);
  Put32(fat, 20, thin.size()); Put32(fat, 24, 12);
  std::copy(thin.begin(), thin.end(), fat.begin() + 4096);
  auto selected = macbuild::Arm64Slice(fat);
  REQUIRE(selected.universal && selected.offset == 4096 && selected.size == thin.size());
  auto bad = fat; Put32(bad, 16, 0xfffffff0);
  Rejected([&] { macbuild::Arm64Slice(bad); });
  bad = fat; Put32(bad, 24, 32);
  Rejected([&] { macbuild::Arm64Slice(bad); });
  bad = fat; Put32(bad, 8, 0x01000007);
  Rejected([&] { macbuild::Arm64Slice(bad); });
  bad = fat; Put32(bad, 4, 65);
  Rejected([&] { macbuild::Arm64Slice(bad); });
  bad = fat; Put32(bad, 4, 2);
  std::copy(fat.begin() + 8, fat.begin() + 28, bad.begin() + 28);
  Rejected([&] { macbuild::Arm64Slice(bad); });
}
} // namespace

void ImGuiTestEngineHook_ItemAdd(ImGuiContext*, ImGuiID id, const ImRect& bounds,
                                const ImGuiLastItemData*) { controls[id].rect = bounds; }
void ImGuiTestEngineHook_ItemInfo(ImGuiContext*, ImGuiID id, const char* label,
                                 ImGuiItemStatusFlags) { controls[id].label = label ? label : ""; }
void ImGuiTestEngineHook_Log(ImGuiContext*, const char*, ...) {}
const char* ImGuiTestEngine_FindItemDebugLabel(ImGuiContext*, ImGuiID id) {
  return controls.contains(id) ? controls.at(id).label.c_str() : nullptr;
}

int main(int argc, char** argv) {
  namespace fs = macbuild::fs;
  auto root = fs::temp_directory_path() / ("Indago ARM test ' $ " + std::to_string(getpid()));
  try {
    REQUIRE(argc == 3);
    const auto bytes = macbuild::ReadBytes(argv[1]);
    UniversalChecks(bytes);
    macbuild::WriteAtomic(root / "sample ' $.macho", std::string(bytes.begin(), bytes.end()));
    const auto p = macbuild::Import(root / "sample ' $.macho", root / "workspace");
    REQUIRE(p.metadata.at("target_executed") == false);
    REQUIRE(p.metadata.at("slice_sha256") == macbuild::Sha256(bytes));
    const auto app = root / "Decoder Demo.app";
    macbuild::WriteAtomic(app / "Contents/MacOS/Decoder", std::string(bytes.begin(), bytes.end()));
    macbuild::WriteAtomic(app / "Contents/Info.plist",
        "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>"
        "<key>CFBundleExecutable</key><string>Decoder</string></dict></plist>");
    {
      macbuild::Controller controller(model, root / "workspace");
      ConfigureWorkbench(&controller.view);
      REQUIRE(model.functions.empty() && model.messages.empty());
      controller.Open(app);
      REQUIRE(controller.view.busy);
      Wait(controller);
      REQUIRE(model.functions.size() >= 3);
      REQUIRE(!model.partial && !model.Busy());
      REQUIRE(controller.view.target == "Decoder Demo.app");
      REQUIRE(controller.view.evidence.find("Contents/MacOS/Decoder") != std::string::npos);
      const auto report = macbuild::LoadAnalysis(p);
      REQUIRE(report.at("target_executed") == false);
      REQUIRE(report.at("architecture") == "AARCH64");
      REQUIRE(report.at("java_heap_gib") == 2);
      auto function = std::find_if(model.functions.begin(), model.functions.end(), [](const auto& f) {
        return f.name == "_decode_buffer";
      });
      REQUIRE(function != model.functions.end());
      REQUIRE(std::any_of(function->code.begin(), function->code.end(), [](const auto& line) {
        return line.find("0x5a") != std::string::npos;
      }));
      REQUIRE(std::any_of(function->assembly.begin(), function->assembly.end(), [](const auto& row) {
        return row.text.find("eor") != std::string::npos;
      }));
      for (const auto& row : function->assembly) REQUIRE(row.codeLine == -1);

      ImGui::CreateContext();
      auto& io = ImGui::GetIO();
      io.IniFilename = nullptr; io.LogFilename = nullptr;
      io.DisplaySize = ImVec2(1400, 850);
      SetWorkbenchStyle();
      unsigned char* pixels; int width, height;
      io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
      ImGui::GetCurrentContext()->TestEngineHookItems = true;
      Frame(); Frame(); Frame();
      REQUIRE(Pane("Pseudocode").Max.y <= Pane("Assembly").Min.y);
      Click("_decode_buffer");
      REQUIRE(model.functions[model.selected].name == "_decode_buffer");
      const auto selected = model.selected;
      Click("Add reference");
      REQUIRE(model.references.size() == 1);
      Click("Compare layout");
      REQUIRE(Pane("Pseudocode").Max.x <= Pane("Assembly").Min.x);
      REQUIRE(model.selected == selected && model.references.size() == 1);
      Click("Stacked layout");
      REQUIRE(Pane("Pseudocode").Max.y <= Pane("Assembly").Min.y);
      Click("notes.md");
      model.notes = "Persistent note about a real ARM64 function.\n";
      Frame(); Click("Save notes");
      REQUIRE(!model.Dirty());
      controller.Execute("goto _check_result");
      REQUIRE(model.functions[model.selected].name == "_check_result");
      controller.Execute("explain");
      REQUIRE(model.messages.empty());
      REQUIRE(model.status.find("Unsupported live command") != std::string::npos);
      REQUIRE(model.RecallHistory(-1, "draft") == "explain");
      REQUIRE(model.RecallHistory(-1, "") == "goto _check_result");
      REQUIRE(model.RecallHistory(1, "") == "explain");
      REQUIRE(model.RecallHistory(1, "") == "draft");
      // Exercise the real settings control, then verify the next Ghidra run
      // saves the chosen deadline and extends the outer worker deadline too.
      controller.view.analysisSeconds = 299;
      Click("Settings");
      Click("+");
      REQUIRE(controller.view.analysisSeconds == 300);
      // Enter the memory value through the actual GUI, not just the view model.
      Click("Analysis memory (GiB)", true);
      io.AddInputCharactersUTF8("4"); Frame();
      io.AddKeyEvent(ImGuiKey_Enter, true); Frame();
      io.AddKeyEvent(ImGuiKey_Enter, false); Frame();
      REQUIRE(controller.view.analysisMemoryGiB == 4);
      Click("Close settings");
      Click("Analyze again");
      REQUIRE(controller.view.busy);
      // The in-flight worker owns a snapshot of its settings.
      controller.view.analysisMemoryGiB = 8;
      Wait(controller);
      const auto longer = macbuild::LoadAnalysis(p);
      REQUIRE(longer.at("analysis_timeout_seconds") == 300);
      REQUIRE(longer.at("worker_timeout_seconds") == 420);
      REQUIRE(longer.at("java_heap_gib") == 4);
      // Verify Java actually received the increased heap ceiling, rather than
      // merely echoing a setting into the saved JSON. Allow JVM alignment.
      const auto heapBytes = longer.at("java_max_heap_bytes").get<std::uint64_t>();
      REQUIRE(heapBytes > 3ULL * 1024 * 1024 * 1024);
      REQUIRE(heapBytes <= 4ULL * 1024 * 1024 * 1024);
      REQUIRE(controller.view.evidence.find("Java heap limit: 4 GiB") != std::string::npos);
      REQUIRE(!model.functions.empty());
      REQUIRE(controller.view.evidence.find("300 seconds") != std::string::npos);
      // Invalid settings fail before a worker starts and preserve prior results.
      controller.view.analysisSeconds = 0;
      controller.StartAnalysis();
      REQUIRE(!controller.view.busy);
      REQUIRE(model.status.find("at least 1 second") != std::string::npos);
      REQUIRE(macbuild::LoadAnalysis(p) == longer);
      controller.view.analysisSeconds = 300;
      for (const auto invalidMemory : {0, -1}) {
        controller.view.analysisMemoryGiB = invalidMemory;
        controller.StartAnalysis();
        REQUIRE(!controller.view.busy);
        REQUIRE(model.status.find("at least 1 GiB") != std::string::npos);
        REQUIRE(macbuild::LoadAnalysis(p) == longer);
        Rejected([&] { macbuild::SettingsForAnalysis(60, invalidMemory); });
        std::atomic_bool unusedCancel{false};
        Rejected([&] { macbuild::Analyze(p, macbuild::DefaultTools(), unusedCancel, {60, 180, invalidMemory}); });
      }
      controller.view.analysisMemoryGiB = 4;
      REQUIRE(macbuild::SettingsForAnalysis(60, 1).memoryGiB == 1);
      Rejected([] { macbuild::SettingsForAnalysis(-1); });
      REQUIRE(macbuild::SettingsForAnalysis(60).workerSeconds == 180);
      REQUIRE(macbuild::SettingsForAnalysis(std::numeric_limits<int>::max()).workerSeconds >
              static_cast<unsigned>(std::numeric_limits<int>::max()));
      ImGui::DestroyContext();

      // Both timeout and cancellation must leave the last successful evidence.
      const auto previous = macbuild::LoadAnalysis(p);
      std::atomic_bool cancel{false};
      Rejected([&] { macbuild::Analyze(p, macbuild::DefaultTools(), cancel, {60, 0}); });
      REQUIRE(macbuild::LoadAnalysis(p) == previous);
      controller.StartAnalysis();
      REQUIRE(controller.view.busy);
      controller.view.cancel();
      Wait(controller);
      REQUIRE(model.status.find("cancelled") != std::string::npos);
      REQUIRE(macbuild::LoadAnalysis(p) == previous);
      auto wrong = macbuild::DefaultTools(); wrong.java = root / "missing-java";
      Rejected([&] { macbuild::Analyze(p, wrong, cancel); });
      REQUIRE(macbuild::LoadAnalysis(p) == previous);
      ConfigureWorkbench(nullptr);
    }
    {
      macbuild::Controller reopened(model, root / "workspace");
      reopened.ResumeLastProject();
      REQUIRE(reopened.view.loaded && !reopened.view.busy);
      REQUIRE(model.notes == "Persistent note about a real ARM64 function.\n");
      REQUIRE(model.functions.size() >= 3 && model.references.empty());
      REQUIRE(reopened.view.evidence.find("Original SHA-256") != std::string::npos);
      REQUIRE(reopened.view.analysisSeconds == 60); // Preferences are session-local.
      REQUIRE(reopened.view.analysisMemoryGiB == 2);
      REQUIRE(reopened.view.evidence.find("Java heap limit: 4 GiB") != std::string::npos);
      REQUIRE(reopened.view.evidence.find("300 seconds") != std::string::npos);
      macbuild::WriteAtomic(root / "not-a-program", "not Mach-O");
      const auto name = reopened.view.target;
      reopened.Open(root / "not-a-program");
      REQUIRE(reopened.view.target == name && !model.functions.empty());
      // Corrupted evidence is rejected rather than rendered as a valid analysis.
      auto pointerBytes = macbuild::ReadBytes(p.directory / "latest.json");
      auto pointer = macbuild::Json::parse(pointerBytes);
      macbuild::WriteAtomic(p.directory / ("analysis-" + pointer.at("sha256").get<std::string>() + ".json"), "{}");
      Rejected([&] { macbuild::LoadAnalysis(p); });
    }
    {
      // A real binary with more than 256 functions proves the index is complete
      // even though detailed decompilation is still bounded in this increment.
      macbuild::Controller indexed(model, root / "indexed-workspace");
      ConfigureWorkbench(&indexed.view);
      indexed.Open(argv[2]);
      Wait(indexed);
      REQUIRE(model.functions.size() > 320);
      const auto project = macbuild::Import(argv[2], root / "indexed-workspace");
      const auto report = macbuild::LoadAnalysis(project);
      const auto entries = macbuild::LoadFunctionIndex(project, report);
      REQUIRE(entries.size() == model.functions.size());
      REQUIRE(report.at("function_index_complete") == true);
      REQUIRE(report.at("functions_truncated") == false);
      REQUIRE(report.at("details_truncated") == true);
      REQUIRE(report.at("functions").size() == 256);
      for (int i = 0; i < 320; ++i) {
        const auto name = "_indexed_" + std::to_string(i);
        REQUIRE(std::count_if(model.functions.begin(), model.functions.end(),
            [&](const auto& f) { return f.name == name; }) == 1);
      }
      REQUIRE(std::any_of(model.functions.begin(), model.functions.end(),
          [](const auto& f) { return f.external && f.address.starts_with("EXTERNAL:"); }));
      auto late = std::find_if(model.functions.begin(), model.functions.end(),
          [](const auto& f) { return !f.external && !f.detailsAvailable; });
      REQUIRE(late != model.functions.end());
      const auto name = late->name, location = late->address;
      REQUIRE(std::distance(model.functions.begin(), late) >= 256);
      REQUIRE(model.Navigate(location));
      REQUIRE(model.instruction == -1 && model.line == 0);
      REQUIRE(model.functions[model.selected].code.empty());
      REQUIRE(!model.AddReference());
      REQUIRE(model.references.empty());
      REQUIRE(indexed.view.evidence.find("discovered functions are listed") != std::string::npos);

      ImGui::CreateContext();
      auto& io = ImGui::GetIO();
      io.IniFilename = nullptr; io.LogFilename = nullptr;
      io.DisplaySize = ImVec2(1400, 850);
      SetWorkbenchStyle();
      unsigned char* pixels; int width, height;
      io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
      ImGui::GetCurrentContext()->TestEngineHookItems = true;
      functionFilter.Clear();
      Frame(); Frame();
      // Clipping renders a small visible subset, while filtering can still
      // reach a function beyond the initial batch of detailed code.
      REQUIRE(controls.size() < model.functions.size());
      std::snprintf(functionFilter.InputBuf, sizeof(functionFilter.InputBuf), "%s", name.c_str());
      functionFilter.Build();
      Frame(); Frame(); Click(name);
      REQUIRE(model.functions[model.selected].address == location);
      layout = Layout::Stacked; Frame();
      layout = Layout::Compare; Frame();
      REQUIRE(Pane("Pseudocode").Max.x <= Pane("Assembly").Min.x);
      functionFilter.Clear();
      ImGui::DestroyContext();
      ConfigureWorkbench(nullptr);

      // Old reports remain readable and advertise only the list they contain.
      auto legacy = report;
      legacy.erase("function_index_sha256");
      REQUIRE(macbuild::LoadFunctionIndex(project, legacy) == report.at("functions"));
      auto wrongCount = report; wrongCount["function_index_count"] = entries.size() + 1;
      Rejected([&] { macbuild::LoadFunctionIndex(project, wrongCount); });
      auto badPath = report; badPath["function_index_sha256"] = "../outside";
      Rejected([&] { macbuild::LoadFunctionIndex(project, badPath); });
      macbuild::Controller reopened(model, root / "indexed-workspace");
      reopened.ResumeLastProject();
      REQUIRE(reopened.view.loaded && model.functions.size() == entries.size());
      REQUIRE(model.Navigate(location));
      REQUIRE(!model.functions[model.selected].detailsAvailable);
      const auto indexFile = project.directory / ("functions-" + report.at("function_index_sha256").get<std::string>() + ".json");
      macbuild::WriteAtomic(indexFile, "[]");
      Rejected([&] { macbuild::LoadFunctionIndex(project, report); });
    }
    fs::remove_all(root);
    std::cout << checks << " live ARM analysis and GUI checks passed\n";
  } catch (const std::exception& error) {
    ConfigureWorkbench(nullptr);
    if (ImGui::GetCurrentContext()) ImGui::DestroyContext();
    std::cerr << error.what() << "\nDiagnostic workspace: " << root << '\n';
    return 1;
  }
}
