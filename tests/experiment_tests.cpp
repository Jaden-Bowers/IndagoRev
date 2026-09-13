#include "../src/harness_experiment.hpp"
#include "../src/harness_workbench.hpp"
#include "../src/model_controller.hpp"
#include "indago/harness.hpp"
#include "indago/runtime.hpp"
#include <cstdlib>
#include <iostream>
using namespace indago;
using J = nlohmann::json;
void check(bool v, const char *m) {
  if (!v)
    throw std::runtime_error(m);
}
template <class F> void rejects(F f) {
  try {
    f();
  } catch (...) {
    return;
  }
  throw std::runtime_error("expected rejection");
}
int main(int argc, char **argv) {
  if (argc > 1 && std::string(argv[1]) == "--fixture") {
    std::string input;
    std::getline(std::cin, input);
    const auto env = std::getenv("EXPERIMENT_VALUE");
    std::ifstream file("payload");
    std::string payload;
    file >> payload;
    const auto output = std::string(input == "yes" ? "accepted" : "rejected") +
                        ":" + (env ? env : "missing") + ":" + payload;
    std::ofstream("delivery.txt", std::ios::binary) << output;
    std::cout << output;
    return 0;
  }
  auto root = fs::temp_directory_path() / make_id("experiment_checks");
  try {
    StaticService service(root);
    auto &store = service.store();
    store.create_project("experiments");
    const auto file = fs::canonical(argc > 1 ? argv[1] : argv[0]);
    auto t = store.import_target("experiments", file);
    J create{
        {"project", "experiments"},
        {"target_id", t.id},
        {"objective", "Bounded trusted fixture experiments"},
        {"required_facts", {"Contrasting inputs"}},
        {"owner", {{"mode", "external"}, {"name", "offline"}}},
        {"workbench_mutations", true},
        {"budget",
         {{"max_actions", 4}, {"wall_ms", 180000}, {"output_bytes", 262144}}},
        {"runtime_execution",
         {{"trusted_host_execution", true},
          {"targets",
           J::array({{{"target_id", t.id}, {"file", file.string()}}})},
          {"engines", {"io"}}}}};
    auto inv = harness_action(service, "create", create);
    J cases = J::array({{{"label", "positive"},
                         {"argv", {"--fixture"}},
                         {"input_hex", "7965730a"},
                         {"files", {{"payload", "626f756e64"}}},
                         {"environment", {{"EXPERIMENT_VALUE", "explicit"}}}},
                        {{"label", "negative"},
                         {"argv", {"--fixture"}},
                         {"input_hex", "6e6f0a"},
                         {"files", {{"payload", "626f756e64"}}},
                         {"environment", {{"EXPERIMENT_VALUE", "explicit"}}}}});
    J request{{"backend", "workbench"},
              {"operation", "experiment.run"},
              {"arguments",
               {{"engine", "io"},
                {"prediction", "Only yes changes output"},
                {"cases", cases}}}};
    auto normalized = normalize_harness_workbench(store, inv, request);
    auto denied = inv;
    denied["envelope"].erase("runtime_execution");
    rejects([&] { normalize_harness_workbench(store, denied, request); });
    auto bad = request;
    bad["arguments"]["cases"][0]["files"] = {{"../escape", "00"}};
    rejects([&] { normalize_harness_workbench(store, inv, bad); });
    bad = request;
    bad["arguments"]["engine"] = "debugger";
    rejects([&] { normalize_harness_workbench(store, inv, bad); });
    bad = request;bad["arguments"]["cases"][0]["engine"]="frida";
    rejects([&] { normalize_harness_workbench(store, inv, bad); });
    bad = request;
    bad["arguments"]["cases"][1] = bad["arguments"]["cases"][0];
    rejects([&] { normalize_harness_workbench(store, inv, bad); });
    bad = normalized;
    bad["arguments"]["sealed"]["target"]["file"] = "other";
    rejects([&] { normalize_harness_workbench(store, inv, bad); });
    const auto id = inv.at("id"), token = inv.at("owner_token");
    auto owned = [&](const char *op, J r) {
      r["project"] = "experiments";
      r["id"] = id;
      r["owner_token"] = token;
      r["expected_revision"] =
          harness_action(service, "show",
                         {{"project", "experiments"}, {"id", id}})
              .at("revision");
      return harness_action(service, op, r);
    };
    auto action =
        owned("propose", {{"key", "experiment_pair"},
                          {"proposal",
                           {{"gap", "input behavior"},
                            {"expected_evidence", "contrasting outputs"},
                            {"prediction", "yes differs"},
                            {"fallback", "inspect partial receipt"}}},
                          {"request", request}});
    auto result = owned("run", {{"action_id", action.at("id")}});
    const auto record =
        wb::knowledge(store, "show",
                      {{"project", "experiments"},
                       {"id", result.at("result").at("knowledge_ids")[0]}});
    const auto body = record.at("body");
    check(body.at("comparison").at("complete") == true, "complete pair");
    check(body.at("comparison").at("output_changed") == true,
          "contrasting output");
    check(body.at("comparison").at("acceptance_proven") == false,
          "no acceptance inflation");
    check(body.at("comparison").at("changed_controls")[0].at("field")=="input_hex","input contrast not recorded");
    auto environment_request=request;
    environment_request["arguments"]["cases"][1]=environment_request["arguments"]["cases"][0];
    environment_request["arguments"]["cases"][1]["label"]="environment-variant";
    environment_request["arguments"]["cases"][1]["environment"]["EXPERIMENT_VALUE"]="variant";
    const auto environment_result=execute_experiment(store,normalize_harness_workbench(store,inv,environment_request).at("arguments"));
    check(environment_result.at("body").at("comparison").at("output_changed")==true&&environment_result.at("body").at("comparison").at("changed_controls")[0].at("field")=="environment","environment contrast failed");
    check(body["cases"][0]["state"]["observation"]["data"]["output"] ==
              "accepted:explicit:bound",
          "all input channels delivered");
    check(body["cases"][1]["state"]["observation"]["data"]["output"] ==
              "rejected:explicit:bound",
          "negative delivered");
    check(body["cases"][0]["state"]["observation"]["data"]
              ["environment_policy"] == "explicit replacement",
          "clean environment");
    auto again = owned("run", {{"action_id", action.at("id")}});
    check(again.at("result").at("knowledge_ids") ==
              result.at("result").at("knowledge_ids"),
          "experiment was replayed");
    auto page = harness_action(
        service, "read",
        {{"project", "experiments"},
         {"id", id},
         {"family", "experiment"},
         {"operation", "read"},
         {"request", {{"id", record.at("id")}, {"pointer", "/comparison"}}}});
    check(page.at("value").at("output_changed") == true,
          "experiment receipt retrieval");
    auto refreshed = harness_action(service, "show",
                                    {{"project", "experiments"}, {"id", id}});
    check(refreshed.at("runtime_observation_sessions").size() == 2,
          "experiment sessions admitted for reasoning feedback");
    auto recovered =
        harness_action(service, "read",
                       {{"project", "experiments"},
                        {"id", id},
                        {"family", "experiment"},
                        {"operation", "reconcile"},
                        {"request", {{"action_id", action.at("id")}}}});
    check(recovered.at("journal_found") == true &&
              recovered.at("known_sessions_terminal") == true,
          "read-only experiment reconciliation");
    J cleanup_request{{"backend", "workbench"},
                      {"operation", "experiment.cleanup"},
                      {"arguments", {{"action_id", action.at("id")}}}};
    auto cleanup_args = normalize_harness_workbench(store, inv, cleanup_request)
                            .at("arguments");
    auto cleanup = cleanup_experiment(store, cleanup_args);
    check(cleanup.at("body").at("status") == "completed",
          "terminal experiment cleanup");
    rejects(
        [&] { normalize_harness_workbench(store, denied, cleanup_request); });
    // Synthetic captured instructions exercise the solver-to-original-input
    // plumbing only; they are not asserted to come from the fixture executable.
    J code{{"address", "0x1000"}, {"hex", "803f417505807f0142750290c3"}};
    J cap{{"id", "synthetic_capture"},
          {"sha256", "synthetic"},
          {"data",
           {{"location", {{"runtime_address", "0x1000"}}},
            {"instruction_bytes", code},
            {"code_bytes", code},
            {"registers",
             {{"arch", "x64"},
              {"values", {{"rdi", "0x2000"}, {"eflags", "0x0"}}}}},
            {"memory", J::array({{{"address", "0x2000"}, {"hex", "0000"}}})}}}};
    auto symbolic = runtime_symbolic(
        cap,
        {{"path", {"0x1000", "0x1005"}},
         {"timeout_ms", 5000},
         {"input_ranges",
          J::array(
              {{{"source", "stdin"}, {"address", "0x2000"}, {"size", 2}}})}});
    const auto sid =
        refreshed.at("runtime_observation_sessions")[0].get<std::string>();
    J synthetic{{"id", "obs_synthetic_solver"},
                {"session_id", sid},
                {"kind", "symbolic"},
                {"data", symbolic}};
    {
      wb::Db db(store.root() / "runtime.sqlite3");
      wb::Q q(
          db,
          "INSERT INTO runtime_observations(id,session,kind,anchor,sha,record) "
          "VALUES(?,?,'symbolic','derived',?,?)");
      q.s(1, "obs_synthetic_solver")
          .s(2, sid)
          .s(3, sha256_text(symbolic.dump()))
          .s(4, synthetic.dump())
          .row();
    }
    auto replay_request = request;
    replay_request["arguments"]["cases"] = J::array({cases[0]});
    replay_request["arguments"]["cases"][0]["input_hex"] = "00000a";
    replay_request["arguments"]["cases"][0]["solver_candidate"] = {
        {"session", sid},
        {"observation", "obs_synthetic_solver"},
        {"terminal", 0},
        {"branch", 1},
        {"candidate", 0}};
    auto replay_args =
        normalize_harness_workbench(store, refreshed, replay_request)
            .at("arguments");
    check(replay_args["cases"][0]["input_hex"] == "41420a",
          "native candidate patches only mapped baseline bytes");
    auto replay = execute_experiment(store, replay_args);
    check(replay["body"]["cases"][0]["state"]["observation"]["data"]
                ["complete"] == true,
          "solver candidate replay produces original-target receipt");
    replay_request["arguments"]["cases"][0]["solver_candidate"]["session"] =
        "foreign";
    rejects(
        [&] { normalize_harness_workbench(store, refreshed, replay_request); });
    J claims = J::array(
        {{{"fact", "Contrasting inputs"},
          {"text", "The two observed outputs differ"},
          {"evidence_ids", J::array({record.at("id")})},
          {"limitations", {"bounded observation, no acceptance proof"}}}});
    rejects([&] {
      owned("finish", {{"status", "answered"},
                       {"answer", "not a proved answer"},
                       {"claims", claims},
                       {"gaps", J::array()}});
    });
    auto partial =
        owned("finish", {{"status", "partial"},
                         {"answer", "Observed contrast"},
                         {"claims", claims},
                         {"gaps", {"independent acceptance predicate"}}});
    check(partial.at("status") == "partial",
          "native receipt cited in partial report");
    auto model_create = create;
    model_create["owner"] = {{"mode", "builtin"},
                             {"name", "offline"},
                             {"profile",
                              {{"provider", "local"},
                               {"model", "offline-fixture"},
                               {"generation_ms", 1000},
                               {"context_tokens", 65536}}}};
    auto model_inv = harness_action(service, "create", model_create);
    unsigned turns = 0;
    auto model_result = harness_explore(
        service,
        {{"project", "experiments"},
         {"id", model_inv.at("id")},
         {"owner_token", model_inv.at("owner_token")},
         {"expected_revision", model_inv.at("revision")},
         {"allow_inference", true},
         {"max_generations", 4},
         {"recipe", "general"}},
        [&](const J &, const J &prompt, const ModelCancel &) {
          J d;
          if (turns++ == 0)
            d = {{"kind", "plan"},
                 {"payload",
                  {{"collection", "tasks"},
                   {"records",
                    J::array({{{"id", "contrast"},
                               {"question", "Does input change output?"},
                               {"summary", "Run trusted contrast"},
                               {"status", "open"},
                               {"depends_on", J::array()},
                               {"priority", 8}}})}}}};
          else if (turns == 2)
            d = {{"kind", "analyze"},
                 {"payload",
                  {{"proposal",
                    {{"gap", "input behavior"},
                     {"prediction", "yes differs"},
                     {"expected_evidence", "two receipts"},
                     {"fallback", "retain uncertainty"}}},
                   {"request", request}}}};
          else {
            auto feedback = J::parse(
                prompt.at("messages").back().at("content").get<std::string>());
            check(feedback.contains("experiment") &&
                      feedback.at("experiment")
                              .at("comparison")
                              .at("output_changed") == true,
                  "single model experiment feedback");
            d = {{"kind", "finish"},
                 {"payload",
                  {{"status", "partial"},
                   {"answer",
                    "Contrasting fixture output, not independent acceptance"},
                   {"claims", J::array()},
                   {"gaps", {"independent oracle"}}}}};
          }
          return J{
              {"model", "offline-fixture"},
              {"usage", {{"prompt_tokens", 100}, {"completion_tokens", 80}}},
              {"choices",
               J::array({{{"finish_reason", "tool_calls"},
                          {"message",
                           {{"role", "assistant"},
                            {"content", nullptr},
                            {"tool_calls",
                             J::array({{{"id", "call_fixture"},
                                        {"type", "function"},
                                        {"function",
                                         {{"name", "investigate"},
                                          {"arguments", d.dump()}}}}})}}}}})}}
              .dump();
        });
    check(turns == 3 && model_result.at("status") == "partial",
          "offline model orchestration");
    std::cout << "experiment grant, bounds, two original-target runs, inputs, "
                 "receipts and comparison passed\n";
    fs::remove_all(root);
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << "\nworkspace: " << root << "\n";
    return 1;
  }
}
