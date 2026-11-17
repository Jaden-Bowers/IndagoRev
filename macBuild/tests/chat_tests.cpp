#include "chat.hpp"
#include <iostream>
#include <stdexcept>

namespace {
int checks = 0;
void Check(bool value, int line) {
  ++checks;
  if (!value) throw std::runtime_error("Chat check failed at line " + std::to_string(line));
}
#define CHECK(value) Check(bool(value), __LINE__)
template<class F> void Rejected(F action) {
  bool failed = false;
  try { action(); } catch (const std::exception&) { failed = true; }
  CHECK(failed);
}
} // namespace

int main() {
  try {
    using namespace macbuild;
    mock::Workbench model;
    model.messages.clear();
    Project project{fs::path("not-read-by-chat"), {{"name", "decoder"}, {"sha256", std::string(64, 'a')},
        {"bundle_executable", "/private/path/must-not-appear"}}};
    Json report{{"partial", true}, {"ghidra_version", "12.0.3"}};
    model.selected = 2;
    model.savedNotes = "private notes opt in";
    model.notes = "unsaved draft must not appear";
    const auto request = BuildChatRequest(project, report, model, "  Explain this function  ");
    CHECK(request.at("question") == "Explain this function");
    const auto& evidence = request.at("evidence");
    CHECK(evidence.at("partial_analysis") == true);
    CHECK(evidence.at("target_executed") == false);
    CHECK(evidence.at("original_sha256") == project.metadata.at("sha256"));
    CHECK(evidence.at("analysis_identity").get<std::string>().size() == 64);
    CHECK(evidence.at("function").at("name") == "decode_buffer");
    CHECK(evidence.at("function").at("pseudocode").front().at("line") == 1);
    CHECK(!evidence.at("function").at("pseudocode").empty());
    CHECK(evidence.at("function").at("assembly").empty());
    CHECK(!evidence.contains("saved_notes"));
    CHECK(request.dump().find("/private/path") == std::string::npos);
    CHECK(request.dump().find("unsaved draft") == std::string::npos);
    CHECK(request.dump().find("private notes") == std::string::npos);
    CHECK(request.at("instructions").get<std::string>().find("untrusted data") != std::string::npos);

    const auto detailed = BuildChatRequest(project, report, model, "Explain", {true, true});
    CHECK(!detailed.at("evidence").at("function").at("assembly").empty());
    CHECK(detailed.at("evidence").at("saved_notes").at("text") == model.savedNotes);
    CHECK(detailed.dump().find("unsaved draft") == std::string::npos);
    // Snapshots own their text: later navigation, note edits and code loading
    // cannot change evidence that has already been prepared for a provider.
    model.functions[2].code[0] = "changed after capture";
    CHECK(request.at("evidence").at("function").at("pseudocode")[0].at("text") != model.functions[2].code[0]);
    auto newReport = report; newReport["partial"] = false;
    CHECK(BuildChatRequest(project, newReport, model, "Explain").at("evidence").at("analysis_identity") !=
        evidence.at("analysis_identity"));
    Rejected([&] { BuildChatRequest(project, report, model, " \n\t "); });
    Rejected([&] { BuildChatRequest(project, report, model, std::string(4097, 'q')); });
    Rejected([&] { BuildChatRequest(project, Json{}, model, "Explain"); });

    model.notes = model.savedNotes;
    CHECK(model.SelectLine(1));
    CHECK(model.AddReference());
    auto quoted = BuildChatRequest(project, report, model, "Follow quote");
    CHECK(quoted.at("evidence").at("references").size() == 1);
    CHECK(quoted.at("evidence").at("references")[0].at("first_line") == 2);
    CHECK(quoted.at("evidence").at("references")[0].at("quote").at("text") == model.references[0].text);
    model.references[0].revision--;
    Rejected([&] { BuildChatRequest(project, report, model, "Stale quote"); });
    model.references.clear();

    auto& function = model.functions[model.selected];
    function.code = {std::string(20000, 'x')};
    function.assembly.resize(200, {"0x1000", "instruction", -1});
    model.savedNotes = std::string(5000, 'n');
    auto limited = BuildChatRequest(project, report, model, "Explain", {true, true});
    const auto& bounded = limited.at("evidence").at("function");
    CHECK(bounded.at("pseudocode_truncated") == true);
    CHECK(bounded.at("pseudocode")[0].at("text").get<std::string>().size() == 12 * 1024);
    CHECK(bounded.at("assembly").size() == 128);
    CHECK(bounded.at("assembly_truncated") == true);
    CHECK(limited.at("evidence").at("saved_notes").at("truncated") == true);
    CHECK(limited.dump(2).size() <= ChatRequestLimit);
    // Cutting just before a multi-byte character must not create invalid UTF-8.
    function.code = {std::string(12 * 1024 - 1, 'a') + "€"};
    CHECK(!BuildChatRequest(project, report, model, "UTF8").dump().empty());
    function.code = {std::string(20000, '\x01')};
    Rejected([&] { BuildChatRequest(project, report, model, "Escaped JSON is bounded too"); });
    function.detailsAvailable = false;
    auto missing = BuildChatRequest(project, report, model, "Not loaded", {true, false});
    CHECK(missing.at("evidence").at("function").at("pseudocode").empty());
    CHECK(missing.at("evidence").at("function").at("assembly").empty());
    function.detailsAvailable = true;
    function.pseudocodeAvailable = false;
    function.code = {"// No pseudocode available. See evidence diagnostics."};
    CHECK(BuildChatRequest(project, report, model, "Failed decompile").at("evidence").at("function").at("pseudocode").empty());
    function.external = true;
    CHECK(BuildChatRequest(project, report, model, "Imported code").at("evidence").at("function").at("external") == true);
    for (int i = 0; i < 9; ++i) model.messages.push_back({"You", "Question " + std::to_string(i), {}});
    model.messages.push_back({"Offline preview", "Do not use a receipt as AI reasoning", {}});
    auto followup = BuildChatRequest(project, report, model, "Follow up");
    CHECK(followup.at("conversation").size() == 6);
    CHECK(followup.at("conversation")[0].at("content").at("text") == "Question 3");
    CHECK(followup.dump().find("Do not use a receipt") == std::string::npos);
    std::atomic_bool cancelled{false};
    CHECK(OfflineChatReply(request, cancelled).find("No AI model is connected") != std::string::npos);
    cancelled = true;
    Rejected([&] { OfflineChatReply(request, cancelled); });
    model.selected = 9999;
    Rejected([&] { BuildChatRequest(project, report, model, "Invalid selection"); });
    model.functions.clear();
    Rejected([&] { BuildChatRequest(project, report, model, "Empty list"); });
    std::cout << "Chat context checks passed: " << checks << '\n';
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
