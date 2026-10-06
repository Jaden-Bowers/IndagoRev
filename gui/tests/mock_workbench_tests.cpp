#include "mock_workbench.hpp"
#include <cstdlib>
#include <iostream>

// These checks exercise application behavior without a window or graphics API.
// Unlike assert(), CHECK still runs in Release builds, where NDEBUG is set.
#define CHECK(expression) do { if (!(expression)) { \
  std::cerr << "Line " << __LINE__ << ": " << #expression << " failed\n"; \
  std::exit(1); } } while (false)

int main() {
  mock::Workbench app;
  CHECK(app.functions.size() == 4);
  CHECK(app.Navigate("0x140001128"));
  CHECK(app.selected == 2 && app.line == 3 && app.instruction == 1);
  CHECK(!app.Navigate("0xdeadbeef"));
  CHECK(app.selected == 2); // A failed lookup must preserve the selection.

  CHECK(app.SelectLine(1));
  CHECK(app.SelectLine(3, true));
  CHECK(app.AddReference());
  const auto quote = app.references.front();
  CHECK(quote.firstLine == 1 && quote.lastLine == 3);
  CHECK(quote.text.find("0x5A") != std::string::npos);
  CHECK(app.Send("What does this loop do?"));
  CHECK(!app.StartAnalysis()); // Only one mock operation may run at a time.
  CHECK(app.SelectFunction(0));
  app.Tick(3);
  CHECK(!app.Busy() && app.references.empty());
  CHECK(app.messages.back().text.find("decode_buffer") != std::string::npos);
  CHECK(app.messages.back().references.front().text == quote.text);
  CHECK(app.FollowReference(quote));
  CHECK(app.selected == 2 && app.line == 3 && app.anchor == 1);

  CHECK(app.AddReference());
  CHECK(app.Send("Explain"));
  app.Tick(0.5f);
  CHECK(!app.streaming.empty());
  app.Cancel();
  CHECK(!app.Busy() && app.references.size() == 1);
  CHECK(app.messages.back().role == "Agent (cancelled)");
  app.scenario = mock::Scenario::ProviderError;
  CHECK(app.Send("Retry"));
  app.Tick(3);
  CHECK(app.messages.back().role == "Agent (error)");
  CHECK(app.references.size() == 1);

  app.scenario = mock::Scenario::Partial;
  CHECK(app.StartAnalysis());
  app.Tick(3);
  CHECK(app.partial);
  app.scenario = mock::Scenario::Complete;
  CHECK(app.StartAnalysis());
  app.Cancel();
  CHECK(app.partial); // Cancellation retains the last completed result.
  CHECK(app.StartAnalysis());
  app.Tick(3);
  CHECK(!app.partial);

  CHECK(app.OpenNotes());
  app.notes += "Unsaved observation";
  CHECK(app.Dirty());
  CHECK(!app.SelectFunction(0));
  CHECK(!app.StartAnalysis());
  app.SaveNotes();
  app.notes += " discard this";
  app.DiscardNotes();
  CHECK(!app.Dirty());
  CHECK(app.notes.ends_with("Unsaved observation"));
  CHECK(app.SelectFunction(2));

  const int oldRevision = app.revision;
  CHECK(!app.ApplyEdit(2, oldRevision, "rename", "bad name"));
  CHECK(!app.ApplyEdit(2, oldRevision, "rename", "main"));
  CHECK(app.ApplyEdit(2, oldRevision, "rename", "decode_bytes"));
  CHECK(app.revision == oldRevision + 1 && app.references.empty());
  CHECK(!app.FollowReference(quote));
  CHECK(!app.ApplyEdit(2, oldRevision, "type", "int"));
  CHECK(app.ApplyEdit(2, app.revision, "signature", "void decode_bytes(byte *buf)"));
  CHECK(app.functions[2].code[0] == "void decode_bytes(byte *buf) {");
  CHECK(app.ApplyEdit(2, app.revision, "type", "size_t"));
  CHECK(!app.ApplyEdit(2, app.revision, "type", "unsupported"));

  app.Execute("functions");
  app.Execute("goto 0x140001183");
  CHECK(app.selected == 3 && app.line == 1);
  CHECK(app.RecallHistory(-1, "unfinished") == "goto 0x140001183");
  CHECK(app.RecallHistory(-1, "") == "functions");
  CHECK(app.RecallHistory(1, "") == "goto 0x140001183");
  CHECK(app.RecallHistory(1, "") == "unfinished");
  CHECK(mock::Workbench::Completions("ana") == std::vector<std::string>{"analyze"});
  CHECK(mock::Workbench::Completions("open main").empty());
  app.Execute("rm -rf imaginary-file");
  CHECK(app.status.find("Unknown command") != std::string::npos);
  app.Execute("explain   ");
  CHECK(!app.Busy());
  app.Execute("clear");
  CHECK(app.console.empty());
  for (int i = 0; i < 400; ++i) app.Execute("status");
  CHECK(app.console.size() <= 300 && app.activity.size() <= 200);
  CHECK(app.history.size() == 100);
  std::cout << "Mock workbench checks passed\n";
}
