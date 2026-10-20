#include "controller.hpp"
#include <sstream>

namespace macbuild {
namespace {
std::string ReadText(const fs::path& file, std::size_t limit = 1024 * 1024) {
  const auto bytes = ReadBytes(file, limit);
  return {bytes.begin(), bytes.end()};
}
}
Controller::Controller(mock::Workbench& model, fs::path folder, Tools settings)
    : state(model), workspace(fs::absolute(folder)), tools(std::move(settings)) {
  // Remove every synthetic fixture before the real window is displayed.
  state.functions.clear(); state.messages.clear(); state.references.clear();
  state.activity.clear(); state.console.clear(); state.history.clear();
  state.notes.clear(); state.savedNotes.clear(); state.partial = false;
  state.selected = state.line = state.anchor = 0; state.instruction = -1;
  state.operation = mock::Operation::Idle; state.revision = 0;
  view.producer = "Ghidra 12.0.3";
  view.tick = [this] { Tick(); };
  view.analyze = [this] { StartAnalysis(); };
  view.cancel = [this] { cancelled = true; state.Log("Cancelling analysis..."); };
  view.saveNotes = [this] { SaveNotes(); };
  view.execute = [this](const std::string& command) { Execute(command); };
  state.Log("Open an ARM64 Mach-O file. Analysis never executes the selected program.");
}

Controller::~Controller() {
  cancelled = true;
  // The runner polls cancellation, kills its process group and reaps Java.
  // Wait before destroying fields referenced by the background task.
  if (pending.valid()) pending.wait();
}

void Controller::ShowProject(Project next) {
  std::string notes = ReadText(next.directory / "notes.md");
  project = std::move(next);
  state.notes = state.savedNotes = std::move(notes);
  state.functions.clear(); state.references.clear(); state.showNotes = false;
  state.selected = state.line = state.anchor = 0; state.instruction = -1;
  state.partial = false; ++state.revision;
  view.loaded = true;
  view.target = project->metadata.at("name").get<std::string>();
  view.evidence = "Input SHA-256: " + project->metadata.at("sha256").get<std::string>() +
                  "\nNo analysis yet. Target has not been executed.";
  WriteAtomic(workspace / "last-project.json", Json{{"sha256", project->metadata.at("sha256")}}.dump());
  if (fs::exists(project->directory / "latest.json")) ShowReport(LoadAnalysis(*project));
}

void Controller::Open(const fs::path& file) {
  if (view.busy || state.Dirty()) { state.Log("Save/discard notes and finish analysis before opening another file."); return; }
  try {
    ShowProject(Import(file, workspace));
    state.Log("Opened " + view.target + "; saved notes and evidence restored.");
    if (!fs::exists(project->directory / "latest.json")) StartAnalysis();
  } catch (const std::exception& error) { state.Log(std::string("Open failed: ") + error.what()); }
}

void Controller::ResumeLastProject() {
  if (!fs::exists(workspace / "last-project.json")) return;
  try {
    auto hash = Json::parse(ReadText(workspace / "last-project.json", 1024)).at("sha256").get<std::string>();
    if (hash.size() != 64 || hash.find_first_not_of("0123456789abcdef") != std::string::npos)
      throw std::runtime_error("Invalid saved project identifier.");
    ShowProject(LoadProject(workspace / hash));
    state.Log("Reopened " + view.target + ". Notes and evidence restored from disk.");
  } catch (const std::exception& error) { state.Log(std::string("Reopen failed: ") + error.what()); }
}

void Controller::StartAnalysis() {
  if (!project || view.busy || state.Dirty()) { state.Log("Open a file and save/discard notes before analyzing."); return; }
  cancelled = false;
  const Project snapshot = *project;
  try {
    pending = std::async(std::launch::async, [this, snapshot] { return Analyze(snapshot, tools, cancelled); });
    view.busy = true;
    state.Log("Ghidra is analyzing the saved ARM64 slice. Previous evidence remains readable.");
  } catch (const std::exception& error) { state.Log(std::string("Could not start analysis: ") + error.what()); }
}

void Controller::Tick() {
  if (!view.busy || pending.wait_for(std::chrono::seconds(0)) != std::future_status::ready) return;
  view.busy = false;
  try {
    ShowReport(pending.get());
    state.Log(std::string(state.partial ? "Partial analysis: " : "Analysis complete: ") +
              std::to_string(state.functions.size()) + " functions. Target was not executed.");
  } catch (const std::exception& error) { state.Log(std::string("Analysis stopped: ") + error.what()); }
}

void Controller::ShowReport(const Json& report) {
  std::vector<mock::Function> functions;
  for (const auto& item : report.at("functions")) {
    mock::Function f;
    f.name = item.at("name").get<std::string>();
    f.address = item.at("address").get<std::string>();
    f.signature = item.at("signature").get<std::string>();
    f.explanation = item.at("decompile_ok").get<bool>() ? "Ghidra decompilation completed." : "Ghidra decompilation failed.";
    const auto diagnostic = item.value("diagnostic", std::string{});
    if (!diagnostic.empty()) f.explanation += "\n" + diagnostic;
    if (item.at("code_truncated").get<bool>()) f.explanation += "\nPseudocode truncated at the export limit.";
    if (item.at("assembly_truncated").get<bool>()) f.explanation += "\nAssembly truncated at the export limit.";
    std::istringstream lines(item.at("code").get<std::string>());
    std::string line;
    while (std::getline(lines, line)) f.code.push_back(line);
    if (f.code.empty()) f.code.push_back("// No pseudocode available. See evidence diagnostics.");
    for (const auto& row : item.at("assembly"))
      f.assembly.push_back({row.at("address").get<std::string>(), row.at("text").get<std::string>(), -1});
    functions.push_back(std::move(f));
  }
  const auto previous = state.functions.empty() ? "" : state.functions[state.selected].address;
  state.functions = std::move(functions);
  state.selected = state.line = state.anchor = 0; state.instruction = -1;
  for (int i = 0; i < static_cast<int>(state.functions.size()); ++i)
    if (state.functions[i].address == previous) state.selected = i;
  if (!state.functions.empty()) state.SelectLine(0);
  state.references.clear(); ++state.revision;
  state.partial = report.at("partial").get<bool>();
  view.producer = "Ghidra " + report.at("ghidra_version").get<std::string>();
  view.evidence = view.producer + " / static analysis\nOriginal SHA-256: " +
      report.at("original_sha256").get<std::string>() + "\nARM64 slice SHA-256: " +
      report.at("input_sha256").get<std::string>() + "\nLanguage: " + report.at("language").get<std::string>() +
      "\nImage base: " + report.at("image_base").get<std::string>() +
      "\n" + (state.partial ? "Partial export; inspect function diagnostics." : "Export completed within configured limits.") +
      "\nNo target execution. Mapping is by containing function, not exact source line.\nSaved evidence: " + project->directory.string();
}

void Controller::SaveNotes() {
  if (!project) return;
  try {
    if (state.notes.size() > 1024 * 1024) throw std::runtime_error("Notes exceed 1 MiB.");
    WriteAtomic(project->directory / "notes.md", state.notes);
    state.savedNotes = state.notes;
    state.Log("Notes saved to disk.");
  } catch (const std::exception& error) { state.Log(std::string("Save failed: ") + error.what()); }
}

void Controller::Execute(const std::string& text) {
  if (text.empty() || text.size() > 4096) return;
  state.history.push_back(text);
  if (state.history.size() > 100) state.history.erase(state.history.begin());
  state.Log("> " + text);
  std::istringstream in(text);
  std::string command, value; in >> command; std::getline(in >> std::ws, value);
  if (command == "help") state.Log("Live commands: help, functions, goto NAME/ADDRESS, analyze, cancel, notes, save, status, clear, history. Use Open ARM64 file to select a binary.");
  else if (command == "functions") for (const auto& f : state.functions) state.Log(f.address + " " + f.name);
  else if (command == "goto" || command == "open") state.Navigate(value);
  else if (command == "analyze") StartAnalysis();
  else if (command == "cancel") view.cancel();
  else if (command == "notes") state.OpenNotes();
  else if (command == "save") SaveNotes();
  else if (command == "status") state.Log(view.target + (view.busy ? " / analyzing" : " / idle"));
  else if (command == "clear") state.console.clear();
  else if (command == "history") for (const auto& entry : state.history) state.Log(entry);
  else state.Log("Unsupported live command. Type help. No shell commands are executed.");
}
} // namespace macbuild
