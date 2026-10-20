#pragma once

#include <string>
#include <vector>

// This is the mock application's data and behavior, with no ImGui or OS headers.
// Both buttons and console commands call these methods. A Windows window can use
// the same model without changing any of the logic below.
namespace mock {
struct Instruction {
  std::string address, text;
  int codeLine; // Zero-based pseudocode line, or -1 when no exact mapping exists.
};
struct Function {
  std::string name, address, signature, variableType, explanation;
  std::vector<std::string> code;
  std::vector<Instruction> assembly;
};
struct Reference {
  int id, function, firstLine, lastLine, revision;
  std::string name, text; // A captured copy, never a pointer into editable code.
};
struct Message {
  std::string role, text;
  std::vector<Reference> references;
};
enum class Operation { Idle, Analysis, Chat };
enum class Scenario { Complete, Partial, ProviderError };

class Workbench {
public:
  Workbench();
  std::vector<Function> functions;
  // selected identifies a function; line and anchor describe the inclusive code
  // selection. All three are zero-based indexes. instruction is -1 if unmapped.
  int selected = 0, line = 0, anchor = 0, instruction = -1, revision = 7;
  bool showNotes = false, partial = false;
  std::string notes, savedNotes, status;
  std::vector<Reference> references;
  std::vector<Message> messages;
  std::vector<std::string> activity, console, history;
  Operation operation = Operation::Idle;
  Scenario scenario = Scenario::Complete;
  float progress = 0;
  std::string streaming;

  bool Busy() const { return operation != Operation::Idle; }
  // Saving notes means updating an in-memory checkpoint, never writing a file.
  bool Dirty() const { return notes != savedNotes; }
  bool SelectFunction(int index);
  bool SelectLine(int index, bool extend = false);
  bool SelectInstruction(int index);
  bool Navigate(const std::string& nameOrAddress);
  bool OpenNotes();
  void SaveNotes();
  void DiscardNotes();
  bool AddReference();
  void RemoveReference(int id);
  bool FollowReference(const Reference& reference);
  bool StartAnalysis();
  bool Send(const std::string& question);
  void Cancel();
  void Tick(float seconds); // Called once per frame; no sleeping or worker thread.
  bool ApplyEdit(int function, int expectedRevision, const std::string& kind,
                 const std::string& value);
  void Execute(const std::string& command);
  void RecordCommand(const std::string& command); // Shared history for real and mock consoles.
  std::string RecallHistory(int direction, const std::string& draft);
  static std::vector<std::string> Completions(const std::string& prefix);
  void Log(const std::string& text);

private:
  bool Fail(const std::string& reason);
  int nextReference = 1, historyPosition = 0;
  float elapsed = 0;
  Scenario runningScenario = Scenario::Complete;
  std::string reply, historyDraft;
  std::vector<Reference> replyReferences;
};
} // namespace mock
