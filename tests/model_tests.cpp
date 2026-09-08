#include "../src/model_controller.hpp"
#include "../src/model_fact_ledger.hpp"
#include "indago/harness.hpp"
#include <iostream>
#include <thread>

using namespace indago;
using J = nlohmann::json;
void check(bool b, const char *m) {
  if (!b)
    throw std::runtime_error(m);
}
template <class F> void rejects(F f, const char *m) {
  bool rejected = false;
  try {
    f();
  } catch (const std::exception &) {
    rejected = true;
  }
  check(rejected, m);
}
J decision(std::string kind, J payload) {
  return {{"kind", kind}, {"payload", payload}};
}
#include "reasoning_checks.hpp"
std::string response(const J &d, std::string model = "offline-fixture") {
  return J{
      {"model", model},
      {"usage", {{"prompt_tokens", 100}, {"completion_tokens", 80}}},
      {"choices",
       J::array(
           {{{"finish_reason", "tool_calls"},
             {"message",
              {{"role", "assistant"},
               {"content", nullptr},
               {"tool_calls", J::array({{{"id", "call_fixture"},
                                         {"type", "function"},
                                         {"function",
                                          {{"name", "investigate"},
                                           {"arguments", d.dump()}}}}})}}}}})}}
      .dump();
}
int main() {
  auto root = fs::temp_directory_path() / make_id("indago_model_test");
  try {
    J raw{{"provider", "local"},
          {"model", "offline-fixture"},
          {"generation_ms", 1000}};
    auto profile = normalize_model_profile(raw);
    check(profile["endpoint"] == "http://127.0.0.1:8080/v1/chat/completions",
          "loopback default");
    auto wrong = raw;
    wrong["endpoint"] = "http://evil.test:8080/v1/chat/completions";
    rejects([&] { normalize_model_profile(wrong); },
            "nonloopback local provider rejected");
    wrong = raw;
    wrong["endpoint"] = "http://127.0.0.1:0/v1/chat/completions";
    rejects([&] { normalize_model_profile(wrong); }, "port zero rejected");
    wrong = {{"provider", "openrouter"},
             {"model", "chosen"},
             {"credential_file", "not-read"},
             {"provider_order", J::array({"pinned"})},
             {"allow_target_context", false}};
    rejects([&] { normalize_model_profile(wrong); }, "cloud policy required");
    auto finish = decision(
        "finish", {{"status", "partial"},
                   {"answer", "Offline fixture has unresolved behavior"},
                   {"claims", J::array()},
                   {"gaps", J::array({"inventory"})}});
    check(decode_model_response(response(finish), profile)["decision"] ==
              finish,
          "structured decision parse");
    rejects(
        [&] {
          decode_model_response(response(finish, "other-model"), profile);
        },
        "model replacement rejected");
    auto truncated = J::parse(response(finish));
    truncated["choices"][0]["finish_reason"] = "length";
    rejects([&] { decode_model_response(truncated.dump(), profile); },
            "truncated tool call never executed");
    std::string wire;
    auto args = finish.dump();
    for (std::size_t at = 0; at < args.size(); at += 7) {
      J delta{
          {"tool_calls",
           J::array({{{"index", 0},
                      {"function", {{"arguments", args.substr(at, 7)}}}}})}};
      if (at == 0) {
        delta["tool_calls"][0]["id"] = "stream_call";
        delta["tool_calls"][0]["function"]["name"] = "investigate";
      }
      wire += "data: " +
              J{{"model", "offline-fixture"},
                {"choices",
                 J::array({{{"delta", delta}, {"finish_reason", nullptr}}})}}
                  .dump() +
              "\n\n";
    }
    wire += "data: " +
            J{{"model", "offline-fixture"},
              {"choices", J::array({{{"delta", J::object()},
                                     {"finish_reason", "tool_calls"}}})}}
                .dump() +
            "\n\ndata: [DONE]\n\n";
    check(decode_model_response(wire, profile)["decision"] == finish,
          "fragmented SSE tool arguments reconstructed");
    auto switched =
        "data: " +
        J{{"model", "different-model"}, {"choices", J::array()}}.dump() +
        "\n\n" + wire;
    rejects([&] { decode_model_response(switched, profile); },
            "earlier stream identity mismatch cannot be hidden by final event");
    rejects(
        [&] {
          decode_model_response(wire.substr(0, wire.find("data: [DONE]")),
                                profile);
        },
        "incomplete stream rejected");
    bool called = false;
    rejects(
        [&] {
          model_complete(
              profile, J::array(), [] { return true; },
              [&](auto &, auto &, auto &) {
                called = true;
                return response(finish);
              });
        },
        "cancellation before inference");
    check(!called, "cancelled generation did not contact provider");
    bool preflight_transport=false,typed_context=false;
    try{model_complete(profile,J::array({{{"role","user"},{"content",std::string(20000,'x')}}}),[]{return false;},
      [&](const auto&,const auto&,const auto&){preflight_transport=true;return response(finish);});}
    catch(const ModelContextError&){typed_context=true;}
    check(typed_context&&!preflight_transport,"typed context rejection happens before any inference transport");
    auto reasoning_only=J::parse(response(finish));
    reasoning_only["choices"][0]["finish_reason"]="stop";
    reasoning_only["choices"][0]["message"]["tool_calls"]=J::array();
    reasoning_only["choices"][0]["message"]["reasoning_content"]=finish.dump();
    rejects([&]{decode_model_response(reasoning_only.dump(),profile);},
            "reasoning-only decision text is not an authorized structured tool invocation");
    model_complete(profile,J::array(),[]{return false;},[&](const auto&,const auto& body,const auto&){
      const auto& request=body;
      check(request.at("tool_choice")=="required","local provider uses compatible required tool choice");
      check(request.at("tools").size()==1&&request.at("tools")[0].at("function").at("name")=="investigate","required still offers exactly one bounded tool");
      return response(finish);
    });
    model_complete(profile,J::array(),[]{return false;},[&](const auto&,const auto& body,const auto&){
      check(body.at("tools")[0].at("function").at("parameters").at("properties").at("kind").at("enum")==J::array({"finish"}),
            "final reserved turn offers only finish");
      return response(finish);
    },true);
    rejects([&]{model_complete(profile,J::array(),[]{return false;},[&](const auto&,const auto&,const auto&){
      return response(J{{"kind","retrieve"},{"payload",J::object()}});
    },true);},"final turn rejects non-finish decisions even when the provider ignores the schema");
    auto encoded_raw=raw;encoded_raw["tool_payload_encoding"]="json_string";
    auto encoded_profile=normalize_model_profile(encoded_raw);
    auto encoded_finish=finish;encoded_finish["payload"]=finish.at("payload").dump();
    check(decode_model_response(response(encoded_finish),encoded_profile).at("decision")==finish,
          "explicit JSON-string wire encoding normalizes a real tool parameter");
    rejects([&]{decode_model_response(response(encoded_finish),profile);},"unsolicited encoded string still rejected by object profile");
    rejects([&]{decode_model_response(response(finish),encoded_profile);},"pinned encoded profile rejects wrong wire type");
    auto malformed_encoded=encoded_finish;malformed_encoded["payload"]="{} trailing text";
    rejects([&]{decode_model_response(response(malformed_encoded),encoded_profile);},"encoded payload must be exactly one JSON object");
    model_complete(encoded_profile,J::array(),[]{return false;},[&](const auto&,const auto& body,const auto&){
      check(body.at("tools")[0].at("function").at("parameters").at("properties").at("payload").at("type")=="string",
            "encoded wire representation declared in offered tool schema");
      return response(encoded_finish);
    });
    StaticService svc(root);
    auto structured_raw=raw;structured_raw["response_mode"]="json_schema";
    auto structured_profile=normalize_model_profile(structured_raw);
    auto structured_response=J::parse(response(finish));
    structured_response["choices"][0]["finish_reason"]="stop";
    structured_response["choices"][0]["message"]={{"role","assistant"},{"content",finish.dump()}};
    check(decode_model_response(structured_response.dump(),structured_profile)["decision"]==finish,"explicit structured content protocol");
    rejects([&]{decode_model_response(structured_response.dump(),profile);},"no implicit content fallback from tools protocol");
    rejects([&]{decode_model_response(response(finish),structured_profile);},"no implicit tool fallback from structured protocol");
    model_complete(structured_profile,J::array(),[]{return false;},[&](const J &,const J &body,const ModelCancel &){
      check(body.contains("response_format")&&!body.contains("tools"),"structured response schema replaces tool template");
      return structured_response.dump();
    });
    structured_raw["tool_payload_encoding"]="json_string";
    rejects([&]{normalize_model_profile(structured_raw);},"nested encoded payload forbidden in structured mode");
    const auto content_wire="data: "+J{{"model","offline-fixture"},{"choices",J::array({{{"delta",{{"content",finish.dump()}}},{"finish_reason","stop"}}})}}.dump()+"\n\ndata: [DONE]\n\n";
    check(decode_model_response(content_wire,structured_profile)["decision"]==finish,"structured SSE content parsed without reasoning scraping");
    svc.store().create_project("demo");
    auto first_target = svc.store().import_target(
        "demo", fs::path(INDAGO_SOURCE_ROOT) /
                    "xair/XAIR/tests/corpus/phase3/control-flow.pe64");
    auto component_target = svc.store().import_target(
        "demo", fs::path(INDAGO_SOURCE_ROOT) /
                    "xair/XAIR/tests/corpus/phase3/compiler-prologue.pe64");
    J create{
        {"project", "demo"},
        {"target_id", first_target.id},
        {"scope",
         {{"target_ids", J::array({first_target.id, component_target.id})}}},
        {"objective", "Inventory a benign fixture"},
        {"required_facts", J::array({"inventory"})},
        {"owner",
         {{"mode", "builtin"}, {"name", "offline-test"}, {"profile", raw}}}};
    rejects([&]{svc.normalize({{"project","demo"},{"backend","airece"},{"operation","flow"},{"address","0x140001000"}});},
            "flow without source/target selectors fails before spawning a worker");
    auto inv = harness_action(svc, "create", create);
    std::vector<J> investigations{inv};
    auto makeRun = [&](const J &v) {
      return J{{"project", "demo"},
               {"id", v["id"]},
               {"owner_token", v["owner_token"]},
               {"expected_revision", v["revision"]},
               {"allow_inference", true},
               {"max_generations", 4}};
    };
    J run = makeRun(inv);
    wrong = run;
    wrong["allow_inference"] = false;
    rejects([&] { harness_explore(svc, wrong); },
            "explicit inference authorization required");
    auto unauthorized = J{{"project", "demo"},
                          {"id", inv["id"]},
                          {"owner_token", inv["owner_token"]},
                          {"expected_revision", inv["revision"]},
                          {"board", J::object()}};
    rejects([&] { harness_action(svc, "checkpoint", unauthorized); },
            "external owner cannot decide for builtin mode");
    int generations = 0;
    auto result = harness_explore(
        svc, run, [&](const J &p, const J &body, const ModelCancel &) {
          check(p["model"] == "offline-fixture" && !body.contains("provider"),
                "one local model, no remote routing");
          if (generations++ == 0)
            return response(
                decision("analyze", {{"proposal",
                                      {{"gap", "inventory"},
                                       {"prediction", "PE inventory"},
                                       {"expected_evidence", "native format"},
                                       {"fallback", "report partial"}}},
                                     {"request",
                                      {{"backend", "xair"},
                                       {"operation", "inventory"},
                                       {"target_id", component_target.id}}}}));
          check(body["messages"].back()["role"] == "tool",
                "tool continuation supplied");
          auto feedback =
              J::parse(body["messages"].back()["content"].get<std::string>());
          check(!feedback["evidence_ids"].empty(),
                "native evidence returned to model");
          return response(finish);
        });
    check(result["status"] == "partial" && generations == 2 &&
              result["controller_usage"]["generations"] == 2,
          "bounded two-generation native loop");
    auto action_history = harness_action(
        svc, "actions", {{"project", "demo"}, {"id", inv["id"]}});
    check(action_history["records"][0]["request"]["artifact_sha256"] ==
              component_target.sha256,
          "built-in controller selects a non-primary scoped component");
    auto saved = harness_action(svc, "controller",
                                {{"project", "demo"}, {"id", inv["id"]}});
    check(saved["phase"] == "terminal" &&
              saved["profile_sha256"] == profile["profile_sha256"],
          "durable pinned generation state");
    inv = harness_action(svc, "create", create);
    investigations.push_back(inv);
    run = makeRun(inv);
    int memory_turn = 0;
    result = harness_explore(svc, run, [&](const J &, const J &body, const ModelCancel &) {
      const int turn = memory_turn++;
      if (turn == 0)
        return response(decision("analyze", {{"proposal", {{"gap","inventory"},{"prediction","PE"},{"expected_evidence","program"},{"fallback","gap"}}},
                                             {"request",{{"backend","xair"},{"operation","inventory"}}}}));
      if (turn == 1) {
        auto feedback = J::parse(body["messages"].back()["content"].get<std::string>());
        return response(decision("retrieve", {{"family","evidence"},{"operation","read"},
            {"request",{{"id",feedback.at("evidence_ids")[0]},{"pointer","/program"}}}}));
      }
      auto packet = J::parse(body["messages"][1]["content"].get<std::string>());
      const auto &observed = packet.at("observed_values");
      check(observed.dump().size() <= 1536 && observed.size() <= 4,
            "native observation memory is bounded");
      check(observed[0].at("values").at("/program/format") == "PE" &&
            observed[0].at("values").at("/program/architecture") == "x64",
            "retrieved native values survive subsequent tool feedback");
      if (turn == 2)
        return response(decision("checkpoint",{{"board",{{"hypotheses",J::array()},{"failed_approaches",J::array()},{"next_actions",J::array()},{"notes","Retain evidence, not a guessed format."}}}}));
      check(body.at("tools")[0].at("function").at("parameters").at("properties").at("kind").at("enum")==J::array({"finish"}),
            "controller reserves its actual last turn for finish");
      return response(finish);
    });
    check(memory_turn == 4 && result["status"] == "partial", "bounded observation-to-final-report loop");
    inv=harness_action(svc,"create",create);investigations.push_back(inv);run=makeRun(inv);
    int ledger_turn=0;J ledger_source;
    result=harness_explore(svc,run,[&](const J &,const J &body,const ModelCancel &){
      const auto turn=ledger_turn++;
      if(turn==0)return response(decision("analyze",{{"proposal",{{"gap","inventory"},{"prediction","PE"},{"expected_evidence","metadata"},{"fallback","partial"}}},
        {"request",{{"backend","xair"},{"operation","inventory"}}}}));
      if(turn==1)ledger_source=J::parse(body["messages"].back()["content"].get<std::string>()).at("evidence_ids")[0];
      if(turn<3)return response(decision("record",{{"fact_index",0},{"evidence_id",ledger_source},{"pointer","/program/format"}}));
      return response(decision("finish",{{"saved",true}}));
    });
    check(result["status"]=="partial"&&result["report"]["claims"].size()==1&&
      result["report"]["claims"][0]["checks"][0]["expected"]=="PE"&&
      result["report"]["claims"][0]["check_result"]["status"]=="passed"&&
      !result["report"]["gaps"].empty(),"controller copies native values, deduplicates observations and assembles checked partial report without declaring solve");
    rejects([&]{model_record_fact(svc.store(),inv,{{"fact_index",99},{"evidence_id",ledger_source},{"pointer","/program/format"}});},"ledger rejects invented fact index");
    rejects([&]{model_record_fact(svc.store(),inv,{{"fact_index",0},{"evidence_id",ledger_source},{"pointer","/program"}});},"ledger rejects containers");
    const auto function_plan=model_function_plan(svc.store(),inv,{{"evidence_id",ledger_source},{"pointer","/program/entry"}});
    reasoning_checks(svc,inv,ledger_source);
    check(model_function_plan(svc.store(),inv,{{"evidence_id",ledger_source},{"pointer","/program/entry"}},true).at("requests").size()==6,"acceptance workflow adds existing symbolic branch and taint operations");
    check(function_plan.at("requests").size()==4&&function_plan["requests"][0]["backend"]=="ghidra"&&
      function_plan["requests"][1]["backend"]=="xair"&&function_plan["requests"][0]["artifact_sha256"]==first_target.sha256,
      "function plan pins component from native evidence and keeps four separately budgeted native views");
    rejects([&]{model_function_plan(svc.store(),inv,{{"evidence_id",ledger_source},{"pointer","/program/format"}});},"function cannot use a non-address scalar");
    J function_bounds={{"budget",{{"max_actions",12},{"wall_ms",180000},{"output_bytes",2097152}}},
      {"reserved",{{"actions",1},{"wall_ms",10000},{"output_bytes",65536}}}};
    check(model_function_budget(function_bounds)==2,"function budget takes tightest aggregate resource");
    function_bounds["reserved"]["wall_ms"]=170000;
    check(model_function_budget(function_bounds)==0,"insufficient time blocks partial function dispatch");
    function_bounds["reserved"]["wall_ms"]=200000;
    check(model_function_budget(function_bounds)==0,"overreserved budget cannot wrap unsigned arithmetic");
    inv=harness_action(svc,"create",create);investigations.push_back(inv);run=makeRun(inv);
    run["recipe"]="assisted_static";run["max_generations"]=2;
    int bootstrap_calls=0;
    result=harness_explore(svc,run,[&](const J &,const J &body,const ModelCancel &){
      ++bootstrap_calls;
      const auto packet=J::parse(body["messages"][1]["content"].get<std::string>());
      check(packet.at("saved_observations").size()==4,"bootstrap saves native metadata before first inference");
      return std::string("invalid provider response");
    });
    check(bootstrap_calls==2&&result["status"]=="budget_exhausted"&&result["report"]["claims"].size()==4,
      "provider protocol failure retains controller-assembled checked facts and exact model-call budget");
    inv = harness_action(svc, "create", create);
    investigations.push_back(inv);
    run = makeRun(inv);
    int recovery_turn=0;
    result=harness_explore(svc,run,[&](const J &,const J &body,const ModelCancel &){
      const int turn=recovery_turn++;
      if(turn==3) {
        auto packet=J::parse(body["messages"][1]["content"].get<std::string>());
        check(packet.contains("recovery_history"),"failure history survives successful backend recovery");
        return response(finish);
      }
      return response(decision("analyze",{{"proposal",{{"gap","recover missing function"},{"prediction","bounded result"},{"expected_evidence","native inventory or explicit failure"},{"fallback","narrow or switch query"}}},
        {"request",turn<2?J{{"backend","xair"},{"operation","cfg"},{"address","0x1"}}:J{{"backend","xair"},{"operation","inventory"}}}}));
    });
    auto recovery_actions=harness_action(svc,"actions",{{"project","demo"},{"id",inv["id"]}});
    check(result["status"]=="partial"&&recovery_actions.at("records").size()==2,
          "identical failed native action is suppressed, changed query can recover");
    inv = harness_action(svc, "create", create);
    investigations.push_back(inv);
    run = makeRun(inv);
    auto compact_create=create;
    compact_create["owner"]["profile"]["context_tokens"]=12288;
    compact_create["owner"]["profile"]["output_tokens"]=1024;
    auto compact_inv=harness_action(svc,"create",compact_create);investigations.push_back(compact_inv);
    auto compact_run=makeRun(compact_inv);int compact_calls=0;
    auto compact_result=harness_explore(svc,compact_run,[&](const J &,const J &body,const ModelCancel &){
      if(compact_calls++==0)return response(decision("analyze",{{"proposal",{{"gap",std::string(1800,'g')},{"prediction",std::string(1800,'p')},{"expected_evidence",std::string(1800,'e')},{"fallback",std::string(1800,'f')}}},
        {"request",{{"backend","xair"},{"operation","inventory"}}}}));
      check(body["messages"].back()["role"]=="user" &&
            J::parse(body["messages"].back()["content"].get<std::string>()).contains("previous_tool_result"),
            "compaction keeps tool feedback but omits oversized assistant argument history");
      return response(finish);
    });
    check(compact_calls==2&&compact_result["controller_usage"]["generations"]==2,
          "context preflight failures do not consume inference generation reservations");
    int repairs = 0;
    result = harness_explore(svc, run, [&](auto &, auto &, auto &) {
      ++repairs;
      return std::string("malformed");
    });
    check(repairs == 3 && result["status"] == "partial",
          "at most two invalid-response repair attempts");
    inv = harness_action(svc, "create", create);
    investigations.push_back(inv);
    run = makeRun(inv);
    int attempts = 0;
    result =
        harness_explore(svc, run, [&](auto &, auto &, auto &) -> std::string {
          ++attempts;
          throw std::runtime_error("connection lost");
        });
    check(attempts == 1 && result["status"] == "environment_unavailable",
          "uncertain transport request not retried");
    inv = harness_action(svc, "create", create);
    investigations.push_back(inv);
    run = makeRun(inv);
    std::jthread canceller([&] {
      std::this_thread::sleep_for(std::chrono::milliseconds(150));
      harness_action(svc, "cancel",
                     {{"project", "demo"},
                      {"id", inv["id"]},
                      {"owner_token", inv["owner_token"]}});
    });
    result = harness_explore(
        svc, run, [&](const J &, const J &, const ModelCancel &cancel) {
          for (int i = 0; i < 100 && !cancel(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
          return response(finish);
        });
    canceller.join();
    check(result["status"] == "cancelled",
          "cancellation reaches in-flight generation");
    auto mutation_create = create;
    mutation_create["workbench_mutations"] = true;
    inv = harness_action(svc, "create", mutation_create);
    investigations.push_back(inv);
    run = makeRun(inv);
    int mutations = 0;
    run["max_generations"] = 6;
    J note_id;
    result = harness_explore(
        svc, run, [&](const J &, const J &body, const ModelCancel &) {
          J feedback;
          if (mutations)
            feedback =
                J::parse(body["messages"].back()["content"].get<std::string>());
          J tool_request;
          if (mutations == 0)
            tool_request = {
                {"backend", "workbench"},
                {"operation", "knowledge.put"},
                {"arguments",
                 {{"kind", "summary"},
                  {"title", "Finite equality hypothesis"},
                  {"body", {{"text", "Compare explicit fixture bytes"}}}}}};
          else if (mutations == 2) {
            check(feedback["passed"] == false &&
                      !feedback["counterexamples"].empty(),
                  "model receives validator counterexample");
            tool_request = {
                {"backend", "workbench"},
                {"operation", "knowledge.revise"},
                {"arguments",
                 {{"id", note_id},
                  {"expected_revision", 1},
                  {"body", {{"text", "Revised after negative finite test"}}}}}};
          } else if (mutations == 1 || mutations == 3) {
            if (mutations == 1) {
              check(feedback["state"] == "inferred",
                    "model receives note receipt");
              note_id = feedback["knowledge_ids"][0];
            } else
              check(feedback["record_revision"] == 2 &&
                        feedback["knowledge_ids"][0] == note_id,
                    "model receives guarded assertion revision");
            tool_request = {
                {"backend", "workbench"},
                {"operation", "validate.compare"},
                {"arguments",
                 {{"subject", note_id},
                  {"cases",
                   J::array({{{"actual_artifact", first_target.sha256},
                              {"expected_artifact",
                               mutations == 1 ? component_target.sha256
                                              : first_target.sha256}}})}}}};
          } else {
            check(feedback["passed"] == true &&
                      feedback["semantic_entailment_checked"] == false,
                  "corrected byte comparison does not claim semantic proof");
            ++mutations;
            return response(finish);
          }
          ++mutations;
          return response(decision(
              "analyze",
              {{"proposal",
                {{"gap", "finite comparison"},
                 {"prediction", "bytes match"},
                 {"expected_evidence", "knowledge or validator receipt"},
                 {"fallback", "retain counterexample"}}},
               {"request", tool_request}}));
        });
    check(mutations == 5 && result["status"] == "partial",
          "offline model completes note, counterexample and revision loop");
    atomic_write(root / "wrapped.bin",
                 "XX" + wb::read(first_target.object_path, 4194304));
    auto wrapped = svc.store().import_target("demo", root / "wrapped.bin");
    auto derived_create = mutation_create;
    derived_create["target_id"] = wrapped.id;
    derived_create["scope"] = {{"target_ids", J::array({wrapped.id})}};
    derived_create["derived_artifacts"] = {{"max_artifacts", 2},
                                           {"max_bytes", 1048576}};
    inv = harness_action(svc, "create", derived_create);
    investigations.push_back(inv);
    run = makeRun(inv);
    run["max_generations"] = 6;
    int derivations = 0;
    J derived_receipt;
    result = harness_explore(
        svc, run, [&](const J &, const J &body, const ModelCancel &) {
          J feedback;
          if (derivations)
            feedback =
                J::parse(body["messages"].back()["content"].get<std::string>());
          J req;
          if (derivations == 0)
            req = {{"backend", "workbench"},
                   {"operation", "transform.run"},
                   {"arguments",
                    {{"offset", 2},
                     {"size", first_target.size},
                     {"spec", {{"method", "slice"}}}}}};
          else if (derivations == 1) {
            derived_receipt = feedback.at("derived_artifact");
            check(derived_receipt["admitted"] == true &&
                      derived_receipt["target_id"] == first_target.id,
                  "scoped extraction admits deduplicated existing PE only by "
                  "derivation");
            req = {{"backend", "xair"},
                   {"operation", "inventory"},
                   {"target_id", derived_receipt["target_id"]}};
          } else if (derivations < 4) {
            if (derivations == 2)
              check(!feedback.at("evidence_ids").empty(),
                    "derived PE receives native static evidence");
            else
              check(feedback["passed"] == false &&
                        !feedback["counterexamples"].empty(),
                    "derived validation returns negative case to controller");
            J c{{"actual_artifact", first_target.sha256}};
            if (derivations == 2)
              c["expected_hex"] = "00";
            else
              c["expected_artifact"] = first_target.sha256;
            req = {{"backend", "workbench"},
                   {"operation", "validate.compare"},
                   {"target_id", first_target.id},
                   {"arguments", {{"cases", J::array({c})}}}};
          } else {
            check(feedback["passed"] == true &&
                      feedback["semantic_entailment_checked"] == false,
                  "derived equality does not become a behavioral proof");
            ++derivations;
            return response(finish);
          }
          ++derivations;
          return response(decision(
              "analyze", {{"proposal",
                           {{"gap", "decoded component"},
                            {"prediction", "derived PE can be inventoried"},
                            {"expected_evidence",
                             "derivation, native inventory, finite validator"},
                            {"fallback", "retain partial result"}}},
                          {"request", req}}));
        });
    check(
        derivations == 5 && result["status"] == "partial",
        "offline transform, admission, native reanalysis and validation chain");
    auto derived_state =
        harness_action(svc, "show", {{"project", "demo"}, {"id", inv["id"]}});
    check(derived_state["target_id"] == wrapped.id &&
              derived_state["derived_components"].size() == 1,
          "derived controller does not change primary target");
    for (const auto &created : investigations) {
      auto current = harness_action(
          svc, "show", {{"project", "demo"}, {"id", created["id"]}});
      harness_action(svc, "release",
                     {{"project", "demo"},
                      {"id", created["id"]},
                      {"owner_token", created["owner_token"]},
                      {"expected_revision", current["revision"]}});
    }
    auto bundle = root.parent_path() / make_id("model_bundle"),
         restored = root.parent_path() / make_id("model_restored");
    workbench_action(svc, "bundle", "export",
                     {{"project", "demo"}, {"destination", bundle.string()}});
    workbench_action(
        svc, "bundle", "import",
        {{"source", bundle.string()}, {"destination", restored.string()}});
    StaticService imported(restored);
    auto importedInv =
        harness_action(imported, "show",
                       {{"project", "demo"}, {"id", investigations[0]["id"]}});
    check(importedInv["owner"]["mode"] == "external" &&
              importedInv["envelope"]["model_calls"] == false,
          "bundle cannot import inference grants or credentials");
    std::cout
        << J{{"status", "passed"},
             {"workspace", root.string()},
             {"live_inference", false},
             {"checks",
              "profiles, routing policy, SSE, truncation, single model loop, "
              "native evidence, repairs, no transport replay, cancellation"}}
               .dump()
        << '\n';
  } catch (const std::exception &e) {
    std::cerr << e.what() << " (retained " << root << ")\n";
    return 1;
  }
}
