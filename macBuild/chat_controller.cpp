#include "controller.hpp"
#include <stdexcept>

namespace macbuild {
namespace {
// Keep both the visible conversation and its disk representation bounded.
// Requests contain snapshots; persisted messages intentionally omit navigation
// indexes because those indexes may refer to different functions after reopening.
Json Conversation(const std::vector<mock::Message>& messages) {
  auto items = Json::array();
  for (const auto& message : messages)
    items.push_back({{"role", message.role}, {"text", message.text}});
  return items;
}
} // namespace

bool Controller::PrepareChat(const std::string& question) {
  if (!project || view.busy || view.chatBusy) {
    view.chatStatus = "Open an analyzed project and finish active work first.";
    return false;
  }
  try {
    auto request = BuildChatRequest(*project, activeReport, state, question,
                                   {view.chatAssembly, view.chatNotes});
    view.chatContext = request.dump(2);
    lastChatRequest = std::move(request);
    view.chatStatus = "Context prepared locally / nothing sent";
    return true;
  } catch (const std::exception& error) {
    view.chatStatus = error.what();
    return false;
  }
}

bool Controller::SendChat(const std::string& question) {
  if (!PrepareChat(question)) return false;
  try {
    if (!chatProvider.complete) throw std::runtime_error("No chat provider is configured.");
    chatCancelled = false;
    const auto request = lastChatRequest;
    const auto complete = chatProvider.complete;
    chatPending = std::async(std::launch::async, [this, request, complete] {
      return complete(request, chatCancelled);
    });
    // The immutable request already owns its evidence before a worker starts.
    // Navigating or editing the draft cannot silently change that request.
    state.messages.push_back({"You", request.at("question").get<std::string>(), state.references});
    view.chatBusy = true;
    view.chatStatus = chatProvider.label + " / preparing reply";
    SaveChat();
    return true;
  } catch (const std::exception& error) {
    view.chatStatus = error.what();
    return false;
  }
}

void Controller::PollChat() {
  if (!view.chatBusy || chatPending.wait_for(std::chrono::seconds(0)) != std::future_status::ready) return;
  try {
    auto text = chatPending.get();
    if (chatCancelled) throw std::runtime_error("Chat cancelled; captured context retained.");
    if (text.empty() || text.size() > 16 * 1024)
      throw std::runtime_error("Chat provider returned an empty reply or exceeded 16 KiB.");
    // Validate UTF-8 before accepting provider text into saved JSON/UI state.
    Json(text).dump();
    state.messages.push_back({chatProvider.label, text, {}});
    view.chatStatus = chatProvider.label + " / finished";
  } catch (const std::exception& error) {
    // An error is not an AI answer and is excluded from future model history.
    const auto message = chatCancelled ? "Chat cancelled; captured context retained." :
                                        std::string("Chat failed: ") + error.what();
    state.messages.push_back({"Chat status", message.substr(0, 4096), {}});
    view.chatStatus = message;
  }
  view.chatBusy = false;
  SaveChat();
}

void Controller::ClearChat() {
  if (view.chatBusy) return;
  state.messages.clear();
  lastChatRequest = Json{};
  view.chatContext.clear();
  view.chatDraft.clear();
  view.chatStatus = "Conversation cleared / offline preview";
  SaveChat();
}

void Controller::SaveChat() {
  if (!project) return;
  try {
    while (state.messages.size() > 40) state.messages.erase(state.messages.begin());
    Json document{{"schema_version", 1}, {"original_sha256", project->metadata.at("sha256")},
                  {"messages", Conversation(state.messages)}, {"last_request", lastChatRequest}};
    // Escaped text can expand. Trim the oldest messages until the actual file
    // fits, always retaining the last exchange and last prepared request.
    while (document.dump(2).size() > 512 * 1024 && state.messages.size() > 2) {
      state.messages.erase(state.messages.begin());
      document["messages"] = Conversation(state.messages);
    }
    WriteAtomic(project->directory / "chat.json", document.dump(2));
  } catch (const std::exception& error) {
    state.Log(std::string("Chat could not be saved: ") + error.what());
    view.chatStatus += " / conversation could not be saved";
  }
}

void Controller::RestoreChat() {
  state.messages.clear();
  lastChatRequest = Json{};
  view.chatContext.clear(); view.chatDraft.clear();
  view.chatAssembly = view.chatNotes = false;
  view.chatStatus = "Offline preview / no AI model connected";
  if (!project || !fs::exists(project->directory / "chat.json")) return;
  try {
    const auto saved = Json::parse(ReadBytes(project->directory / "chat.json", 1024 * 1024));
    if (saved.at("schema_version") != 1 || saved.at("original_sha256") != project->metadata.at("sha256") ||
        !saved.at("messages").is_array() || saved.at("messages").size() > 40)
      throw std::runtime_error("Invalid chat history identity or format.");
    std::vector<mock::Message> messages;
    for (const auto& message : saved.at("messages")) {
      const auto role = message.at("role").get<std::string>();
      const auto text = message.at("text").get<std::string>();
      if (role.size() > 128 || text.size() > 16 * 1024)
        throw std::runtime_error("Chat history entry exceeds its limit.");
      messages.push_back({role, text, {}});
    }
    const auto& request = saved.at("last_request");
    if (!request.is_null()) {
      if (request.at("schema_version") != 1 || request.dump(2).size() > ChatRequestLimit ||
          request.at("evidence").at("original_sha256") != project->metadata.at("sha256"))
        throw std::runtime_error("Invalid saved chat context.");
      view.chatContext = request.dump(2);
    }
    state.messages = std::move(messages);
    lastChatRequest = request;
    view.chatStatus = "Conversation restored / offline preview";
  } catch (const std::exception& error) {
    // Broken chat data must not prevent binary evidence and notes from opening.
    state.Log(std::string("Chat history not restored: ") + error.what());
    view.chatStatus = "Chat history could not be restored; see Console.";
  }
}
} // namespace macbuild
