#pragma once
#include "project.hpp"
#include "../gui/mock_workbench.hpp"
#include <atomic>
#include <functional>

namespace macbuild {
// Keep context preparation independent of ImGui, Cocoa and any provider SDK.
// The same request can later be translated to a hosted or local model's format.
struct ChatOptions {
  bool assembly = false;
  bool savedNotes = false;
};
constexpr std::size_t ChatRequestLimit = 64 * 1024;
Json BuildChatRequest(const Project& project, const Json& report,
                      const mock::Workbench& model, const std::string& question,
                      ChatOptions options = {});

// A provider consumes an immutable snapshot on a worker thread. Future adapters
// must honour cancellation and impose their own network/response deadlines.
// The default implementation has no network access or credentials and returns
// a preparation receipt, never an invented explanation of the selected code.
std::string OfflineChatReply(const Json& request, const std::atomic_bool& cancelled);
struct ChatProvider {
  std::string label = "Offline preview";
  std::function<std::string(const Json&, const std::atomic_bool&)> complete = OfflineChatReply;
};
} // namespace macbuild
