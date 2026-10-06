#include "mock_workbench.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <utility>

namespace mock {
namespace {
std::string Trim(const std::string& text) {
  const auto first = text.find_first_not_of(" \t\r\n");
  return first == std::string::npos ? "" :
      text.substr(first, text.find_last_not_of(" \t\r\n") - first + 1);
}
std::string Lower(std::string value) {
  for (char& c : value)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return value;
}
// Bounded logs keep long demo sessions from growing memory without limit.
template<class T> void Append(std::vector<T>& items, T item, size_t limit) {
  items.push_back(std::move(item));
  if (items.size() > limit)
    items.erase(items.begin());
}
const std::vector<std::string> commands = {
    "help", "clear", "status", "functions", "open", "goto", "analyze",
    "cancel", "refs", "explain", "rename", "history"};
} // namespace

Workbench::Workbench() {
  // These strings are illustrative, not results from a real executable.
  functions = {
    {"entry", "0x140001000", "int entry(void)", "int",
     "The entry function initializes the runtime and transfers control to main.",
     {"int entry(void) {", "    initialize_runtime();", "    return main();", "}"},
     {{"0x140001000", "sub rsp, 28h", 0}, {"0x140001004", "call initialize_runtime", 1},
      {"0x140001009", "call main", 2}, {"0x14000100e", "ret", -1}}},
    {"main", "0x140001060", "int main(void)", "byte*",
     "Main passes a buffer to decode_buffer, then checks the transformed bytes.",
     {"int main(void) {", "    decode_buffer(buf, size);", "    return check_result(buf);", "}"},
     {{"0x140001060", "sub rsp, 28h", 0}, {"0x140001064", "call decode_buffer", 1},
      {"0x140001069", "call check_result", 2}, {"0x14000106e", "ret", -1}}},
    {"decode_buffer", "0x140001120", "void decode_buffer(byte *buf, size_t n)", "byte*",
     "Each byte is XORed with 0x5A in place. Applying the same operation twice restores the original byte.",
     {"void decode_buffer(byte *buf, size_t n) {", "    for (size_t i = 0; i < n; ++i) {",
      "        // Transform one byte", "        buf[i] ^= 0x5A;", "    }", "}"},
     {{"0x140001120", "xor eax, eax", 1}, {"0x140001128", "xor byte ptr [rcx+rax], 5Ah", 3},
      {"0x14000112c", "inc rax", 1}, {"0x14000112f", "cmp rax, rdx", 1},
      {"0x140001132", "jb 0x140001128", 1}}},
    {"check_result", "0x140001180", "bool check_result(const byte *buf)", "const byte*",
     "This function checks whether the first byte equals 0x48. This static condition is not a verified runtime result.",
     {"bool check_result(const byte *buf) {", "    return buf[0] == 0x48;", "}"},
     {{"0x140001180", "cmp byte ptr [rcx], 48h", 1}, {"0x140001183", "sete al", 1},
      {"0x140001186", "ret", -1}}}
  };
  notes = savedNotes = "# Decoder study\n\nThese are editable mock notes.\nNo target has been executed.\n";
  messages.push_back({"Agent (scripted)", "Select code, add a reference, and ask a question. Replies are offline demonstrations, not model inference.", {}});
  SelectLine(0);
  Log("Ready: synthetic project loaded. Console: type help.");
}

void Workbench::Log(const std::string& text) {
  status = text;
  Append(activity, text, 200);
  Append(console, text, 300);
}
bool Workbench::Fail(const std::string& reason) { Log("Error: " + reason); return false; }

bool Workbench::SelectFunction(int index) {
  if (Dirty()) return Fail("Save or discard notes before navigating.");
  if (index < 0 || index >= static_cast<int>(functions.size())) return Fail("Function not found.");
  selected = index;
  showNotes = false;
  SelectLine(0);
  Log("Selected " + functions[selected].name);
  return true;
}
bool Workbench::SelectLine(int index, bool extend) {
  const auto& f = functions[selected];
  if (index < 0 || index >= static_cast<int>(f.code.size())) return Fail("Invalid code line.");
  line = index;
  if (!extend) anchor = index;
  instruction = -1;
  for (int i = 0; i < static_cast<int>(f.assembly.size()); ++i)
    if (f.assembly[i].codeLine == line) { instruction = i; break; }
  return true;
}
bool Workbench::SelectInstruction(int index) {
  const auto& rows = functions[selected].assembly;
  if (index < 0 || index >= static_cast<int>(rows.size())) return Fail("Invalid instruction.");
  const int mapped = rows[index].codeLine;
  SelectLine(mapped >= 0 ? mapped : 0);
  instruction = index;
  if (mapped < 0) Log("No exact mapping; showing the containing function.");
  return true;
}
bool Workbench::Navigate(const std::string& query) {
  const auto key = Lower(Trim(query));
  for (int i = 0; i < static_cast<int>(functions.size()); ++i) {
    const auto& f = functions[i];
    if (Lower(f.name) == key || Lower(f.address) == key) return SelectFunction(i);
    for (int j = 0; j < static_cast<int>(f.assembly.size()); ++j)
      if (Lower(f.assembly[j].address) == key)
        return SelectFunction(i) && SelectInstruction(j);
  }
  return Fail("No mock function or instruction matches: " + query);
}
bool Workbench::OpenNotes() { showNotes = true; return true; }
void Workbench::SaveNotes() {
  savedNotes = notes;
  Log("Notes saved in this mock session only (no disk write).");
}
void Workbench::DiscardNotes() { notes = savedNotes; Log("Unsaved notes discarded."); }

bool Workbench::AddReference() {
  if (Busy() || Dirty() || showNotes) return Fail("Finish the operation or notes edit before quoting code.");
  if (references.size() >= 8) return Fail("At most eight references are allowed.");
  Reference ref{nextReference++, selected, std::min(line, anchor), std::max(line, anchor),
                revision, functions[selected].name, ""};
  for (int i = ref.firstLine; i <= ref.lastLine; ++i)
    ref.text += functions[selected].code[i] + "\n";
  if (ref.text.size() > 16384) return Fail("Reference exceeds 16 KiB.");
  references.push_back(ref);
  Log("Attached " + ref.name + " lines " + std::to_string(ref.firstLine + 1) + "-" + std::to_string(ref.lastLine + 1));
  return true;
}
void Workbench::RemoveReference(int id) {
  if (Busy()) { Fail("Wait for the current operation before changing references."); return; }
  std::erase_if(references, [id](const auto& r) { return r.id == id; });
}
bool Workbench::FollowReference(const Reference& ref) {
  if (ref.revision != revision) return Fail("Citation is stale; reselect code at the current revision.");
  if (!SelectFunction(ref.function)) return false;
  SelectLine(ref.firstLine);
  return SelectLine(ref.lastLine, true);
}
bool Workbench::StartAnalysis() {
  if (Busy() || Dirty()) return Fail("Finish the current operation or save/discard notes first.");
  operation = Operation::Analysis;
  runningScenario = scenario;
  elapsed = progress = 0;
  Log("Replaying static analysis fixture. No executable is launched.");
  return true;
}
bool Workbench::Send(const std::string& question) {
  if (Busy() || Dirty() || showNotes) return Fail("Select saved code and finish the current operation first.");
  const auto text = Trim(question);
  if (text.empty() || text.size() > 4096) return Fail("Enter a question of 1 to 4096 bytes.");
  for (const auto& ref : references)
    if (ref.revision != revision) return Fail("A reference is stale; reselect it.");
  // Capture the reply and citations now, so navigating during streaming cannot
  // silently change which function the answer discusses.
  replyReferences = references;
  const int target = references.empty() ? selected : references.front().function;
  if (replyReferences.empty())
    replyReferences.push_back({0, target, line, line, revision, functions[target].name, functions[target].code[line]});
  reply = "Scripted explanation of " + functions[target].name + ": " + functions[target].explanation +
          " This is synthetic evidence; no program execution or AI request occurred.";
  if (references.size() > 1) reply += " The first attached function drives this sample answer; all attached quotes are retained below.";
  Append(messages, Message{"You", text, replyReferences}, 60);
  runningScenario = scenario;
  operation = Operation::Chat;
  elapsed = progress = 0;
  streaming.clear();
  Log("Scripted reply started.");
  return true;
}
void Workbench::Cancel() {
  if (!Busy()) { Log("Nothing is running."); return; }
  if (operation == Operation::Chat)
    Append(messages, Message{"Agent (cancelled)", streaming + "\nReply cancelled; pending references retained.", replyReferences}, 60);
  operation = Operation::Idle;
  streaming.clear();
  Log("Mock operation cancelled; existing data retained.");
}
void Workbench::Tick(float seconds) {
  if (!Busy()) return;
  elapsed += std::max(0.0f, seconds);
  progress = std::min(1.0f, elapsed / 2.5f);
  if (operation == Operation::Chat)
    streaming = reply.substr(0, static_cast<size_t>(progress * reply.size()));
  if (progress < 1) return;
  const auto finished = operation;
  operation = Operation::Idle;
  if (finished == Operation::Analysis) {
    partial = runningScenario == Scenario::Partial;
    Log(partial ? "Replay partial: assembly scan stopped early. Saved listings remain readable." : "Replay complete: four mock functions available.");
  } else if (runningScenario == Scenario::ProviderError) {
    Append(messages, Message{"Agent (error)", "Simulated provider failure. References retained for retry.", {}}, 60);
    Log("Simulated provider failure. Change the scenario in Settings and retry.");
  } else {
    Append(messages, Message{"Agent (scripted)", reply, replyReferences}, 60);
    references.clear();
    Log("Scripted reply complete; interpretation is not a verified result.");
  }
  streaming.clear();
}

bool Workbench::ApplyEdit(int index, int expected, const std::string& kind, const std::string& input) {
  if (Busy() || Dirty()) return Fail("Finish the operation or notes edit first.");
  if (expected != revision) return Fail("Revision conflict: review this change again.");
  if (index < 0 || index >= static_cast<int>(functions.size())) return Fail("Function not found.");
  const auto value = Trim(input);
  if (value.empty() || value.size() > 256 || value.find_first_of("\r\n") != std::string::npos)
    return Fail("Enter a single-line value of 1 to 256 bytes.");
  auto& f = functions[index];
  if (kind == "rename") {
    if (!(std::isalpha(static_cast<unsigned char>(value[0])) || value[0] == '_') ||
        !std::all_of(value.begin(), value.end(), [](unsigned char c) { return std::isalnum(c) || c == '_'; }))
      return Fail("Use a C identifier: letters, digits and underscores, with no leading digit.");
    for (int i = 0; i < static_cast<int>(functions.size()); ++i)
      if (i != index && functions[i].name == value) return Fail("A function already has that name.");
    // Only update this function's displayed declaration. Mock call-site text is
    // captured fixture text, not a decompiler that can rewrite all references.
    const auto at = f.signature.find(f.name + "(");
    if (at != std::string::npos) f.signature.replace(at, f.name.size(), value);
    f.name = value;
    f.code[0] = f.signature + " {";
  } else if (kind == "signature") {
    if (value.find(f.name + "(") == std::string::npos || value.back() != ')')
      return Fail("Use a declaration with the current function name, ending in ).");
    f.signature = value;
    f.code[0] = value + " {";
  } else if (kind == "type") {
    const std::vector<std::string> types = {"int", "unsigned int", "byte*", "const byte*", "size_t"};
    if (std::find(types.begin(), types.end(), value) == types.end()) return Fail("Choose a listed mock type.");
    f.variableType = value;
  } else return Fail("Unknown annotation kind.");
  ++revision;
  references.clear();
  Log("User assertion: " + kind + " applied to " + f.name + "; revision " + std::to_string(revision) + ". Old quotes expired.");
  return true;
}

// This parser has an explicit command list. There is deliberately no system(),
// shell, subprocess, filesystem, or network call anywhere in the mock model.
void Workbench::Execute(const std::string& input) {
  const auto text = Trim(input);
  if (text.empty()) return;
  if (text.size() > 4096) { Fail("Command exceeds 4096 bytes."); return; }
  Append(history, text, 100);
  historyPosition = static_cast<int>(history.size());
  historyDraft.clear();
  Append(console, "> " + text, 300);
  std::istringstream words(text);
  std::string command, argument;
  words >> command;
  std::getline(words, argument);
  command = Lower(command);
  argument = Trim(argument);
  if (command == "help") {
    Log("help | clear | status | functions | open <name/address/notes> | goto <address>");
    Log("analyze | cancel | refs | explain <question> | rename <name> | history");
    Log("All commands use mock state. Rename applies a session-only user assertion.");
  } else if (command == "clear") console.clear();
  else if (command == "status") Log("Mock revision " + std::to_string(revision) +
      (Busy() ? " / operation running" : " / idle") + (partial ? " / partial" : " / complete fixture"));
  else if (command == "functions") {
    for (const auto& f : functions) Log(f.name + "  " + f.address);
  } else if (command == "open" || command == "goto") {
    if (command == "open" && (argument == "notes" || argument == "notes.md")) OpenNotes();
    else Navigate(argument);
  } else if (command == "analyze") StartAnalysis();
  else if (command == "cancel") Cancel();
  else if (command == "explain") Send(argument);
  else if (command == "rename") ApplyEdit(selected, revision, "rename", argument);
  else if (command == "refs") {
    Log(std::to_string(references.size()) + " pending references");
    for (const auto& r : references) Log(r.name + " / rev " + std::to_string(r.revision));
  } else if (command == "history") {
    for (const auto& h : history) Append(console, h, 300);
  } else Fail("Unknown command: " + command + ". Type help. Shell commands are not supported.");
}
std::string Workbench::RecallHistory(int direction, const std::string& draft) {
  if (historyPosition == static_cast<int>(history.size())) historyDraft = draft;
  historyPosition = std::clamp(historyPosition + direction, 0, static_cast<int>(history.size()));
  return historyPosition == static_cast<int>(history.size()) ? historyDraft : history[historyPosition];
}
std::vector<std::string> Workbench::Completions(const std::string& prefix) {
  std::vector<std::string> result;
  for (const auto& command : commands)
    if (command.starts_with(Lower(prefix))) result.push_back(command);
  return result;
}
} // namespace mock
