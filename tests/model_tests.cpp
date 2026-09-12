#include "../src/model_controller.hpp"
#include "../src/model_fact_ledger.hpp"
#include "../src/model_credentials.hpp"
#include "../src/model_investigation.hpp"
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
    check(parse_model_credential("OTHER=ignored\nexport OPENROUTER_API_KEY = 'test-key' # note\n","dotenv")=="test-key","dotenv quoted credential");
    check(parse_model_credential("openrouter_key=test-key\n","dotenv","openrouter_key")=="test-key","explicit dotenv variable");
    rejects([&]{parse_model_credential("OPENROUTER_API_KEY=a\nOPENROUTER_API_KEY=b","dotenv");},"duplicate secret rejected");
    rejects([&]{parse_model_credential("OPENROUTER_API_KEY=$(command)","dotenv");},"no dotenv interpolation");
    const J row_with_nested={{"address","0x1000"},{"text","MOV EAX, 7"},{"width",32},{"location",{{"space","ram"}}},{"long_text",std::string(1025,'x')}};
    const auto projected=evidence_scalar_projection(row_with_nested);
    check(projected.at("text")=="MOV EAX, 7"&&projected.at("width")==32&&!projected.contains("location")&&!projected.contains("long_text"),"scalar projection preserves instruction semantics and omits nested/large values explicitly");
    auto goal_queue=investigation_state();
    investigation_plan(goal_queue,{{"expected_revision",0},{"collection","goals"},{"active_task","input"},{"records",J::array({{{"id","input"},{"question","Find input"},{"status","open"},{"priority",9},{"summary","Find dependencies"}}})}});
    check(goal_queue["planned"]==true&&investigation_queue(goal_queue)["records"][0]["id"]=="input","goal decomposition forms a queue without duplicate task records");
    auto durable=investigation_state();
    auto task=[](std::string id,J deps,int priority) {return J{{"id",id},{"question","Which data reaches acceptance?"},{"status","open"},{"depends_on",deps},{"priority",priority},{"summary","Unverified assessment"}};};
    J rows=J::array();for(int i=0;i<40;++i)rows.push_back(task("task_"+std::to_string(i),J::array(),i%10));
    for(int start=0;start<40;start+=20) {
      J patch=J::array();for(int i=start;i<start+20;++i)patch.push_back(rows[i]);
      investigation_plan(durable,{{"expected_revision",durable["revision"]},{"collection","tasks"},{"records",patch}});
    }
    auto restored_state=J::parse(durable.dump());
    check(investigation_page(restored_state,{{"collection","tasks"},{"offset",32},{"limit",8}})["records"].size()==8,"durable state beyond old frontier cap survives restart and paging");
    for(int i=0;i<40;++i)restored_state["values"].push_back({{"evidence_id","ev_test"},{"raw_sha256","source-pin"},{"offset",i*2048},{"partial",true},{"values",{{"/text","exact instruction bytes and constants"}}}});
    restored_state=J::parse(restored_state.dump());
    check(investigation_page(restored_state,{{"collection","values"},{"offset",32},{"limit",8}})["records"][0]["offset"]==65536,"native chunk history remains pageable beyond legacy cache size");
    check(investigation_queue(restored_state)["records"][0]["priority"]==9,"question priority drives queue");
    const auto before=restored_state;
    rejects([&]{investigation_plan(restored_state,{{"expected_revision",restored_state["revision"]},{"collection","tasks"},{"records",J::array({task("task_0",J::array({"task_1"}),5),task("task_1",J::array({"task_0"}),5)})}});},"dependency cycle rejected");
    check(restored_state==before,"invalid plan atomicity");
    auto query=decision("analyze",{{"request",{{"backend","xair"},{"operation","inventory"}}}});
    investigation_observe(restored_state,query,{{"evidence_ids",J::array({"ev_test"})}},1,"native_snapshot");
    investigation_observe(restored_state,query,{{"evidence_ids",J::array({"ev_test"})}},1,"native_snapshot");
    check(restored_state["query_counts"][investigation_query_key(query)]==0,"resume does not double charge progress");
    investigation_observe(restored_state,query,{{"evidence_ids",J::array({"ev_again"})}},2,"native_snapshot");
    investigation_observe(restored_state,query,{{"evidence_ids",J::array({"ev_again"})}},3,"native_snapshot");
    query["payload"]["request"]["budget"]={{"wall_ms",50000}};
    rejects([&]{investigation_guard(restored_state,query);},"changed budget cannot bypass repeated query guard");
    query["payload"]["request"]["operation"]="cfg";investigation_guard(restored_state,query);
    auto hypothesis=task("hypothesis_0",J::array(),5);hypothesis["status"]="supported";
    investigation_plan(restored_state,{{"expected_revision",restored_state["revision"]},{"collection","hypotheses"},{"records",J::array({hypothesis})}});
    investigation_observe(restored_state,decision("retrieve",J::object()),{{"status","contradicted"}},4);
    check(restored_state["hypotheses"][0]["status"]=="open","contradiction reopens assumptions");
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
    auto cloud=normalize_model_profile({{"provider","openrouter"},{"model","deepseek/deepseek-v4-flash-0731"},{"credential_file","not-read"},{"credential_format","dotenv"},{"credential_variable","openrouter_key"},{"provider_order",J::array({"open-inference/fp8"})},{"allow_target_context",true},{"reasoning_effort","medium"}});
    model_complete(cloud,J::array(),[]{return false;},[&](const J &,const J &body,const ModelCancel &){
      check(body.at("provider").at("allow_fallbacks")==false&&!body.contains("models"),"no cloud model fallback");
      check(body.at("stream")==false&&!body.contains("stream_options"),"reasoning-enabled OpenRouter retains complete non-streaming messages");
      check(!body.contains("parallel_tool_calls")&&body.at("reasoning").at("effort")=="medium","OpenRouter supported tool/reasoning payload");
      check(!body.contains("credential_file")&&!body.contains("credential_variable"),"credential configuration excluded from provider payload");
      return response(decision("finish",{{"status","partial"}}),"deepseek/deepseek-v4-flash-0731");
    });
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
    auto encoded_cloud_input=cloud;encoded_cloud_input.erase("profile_sha256");encoded_cloud_input.erase("sampling");encoded_cloud_input["tool_payload_encoding"]="json_string";
    auto encoded_cloud=normalize_model_profile(encoded_cloud_input);
    check(decode_model_response(response(encoded_finish,"deepseek/deepseek-v4-flash-0731"),encoded_cloud).at("decision")==finish,"explicit OpenRouter encoded object protocol");
    auto reasoning_response=J::parse(response(encoded_finish,"deepseek/deepseek-v4-flash-0731"));
    const J reasoning_blocks=J::array({{{"type","reasoning.encrypted"},{"data","opaque-fixture"},{"id","r1"},{"format","unknown"},{"index",0}}});
    reasoning_response["choices"][0]["message"]["reasoning_details"]=reasoning_blocks;
    check(decode_model_response(reasoning_response.dump(),encoded_cloud).at("message").at("reasoning_details")==reasoning_blocks,"provider reasoning blocks preserved without interpretation");
    const auto padded_response="\r\n \t"+reasoning_response.dump()+"\n";
    const auto padded_decoded=decode_model_response(padded_response,encoded_cloud);
    check(padded_decoded.at("message").at("reasoning_details")==reasoning_blocks&&padded_decoded.at("response_sha256")==sha256_text(padded_response),"JSON whitespace does not masquerade as incomplete SSE; source digest stays exact");
    rejects([&]{decode_model_response(" \r\n\t",encoded_cloud);},"whitespace-only response rejected");
    auto malformed_encoded=encoded_finish;malformed_encoded["payload"]="{} trailing text";
    rejects([&]{decode_model_response(response(malformed_encoded),encoded_profile);},"encoded payload must be exactly one JSON object");
    model_complete(encoded_profile,J::array(),[]{return false;},[&](const auto&,const auto& body,const auto&){
      check(body.at("tools")[0].at("function").at("parameters").at("properties").at("payload").at("type")=="string",
            "encoded wire representation declared in offered tool schema");
      return response(encoded_finish);
    });
    J history_fixture=J::array();
    for(int n=0;n<20;++n)history_fixture.push_back({{"generation",n},{"assistant",{{"reasoning_details",reasoning_blocks}}},{"feedback",{{"text",std::string(1000,'x')}}}});
    check(investigation_history(history_fixture,131072,8192,20000,false).size()==20,"conversation retains more than eight exchanges when pinned context permits");
    const auto narrow_history=investigation_history(history_fixture,16384,8192,20000,false);
    check(narrow_history.size()==1&&narrow_history[0]==history_fixture.back(),"context narrowing preserves the latest complete opaque reasoning exchange");
    auto large_cloud=encoded_cloud;large_cloud.erase("profile_sha256");large_cloud.erase("sampling");large_cloud["context_tokens"]=1048576;large_cloud["generation_ms"]=300000;
    check(normalize_model_profile(large_cloud).at("context_tokens")==1048576&&normalize_model_profile(large_cloud).at("generation_ms")==300000,"explicit OpenRouter profile permits a one-million-token context");
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
    auto extended_create=create;extended_create["budget"]={{"wall_ms",3600000}};
    auto extended_inv=harness_action(svc,"create",extended_create);investigations.push_back(extended_inv);
    check(extended_inv.at("budget").at("wall_ms")==3600000,"explicit investigation reservation can fund a bounded longer work queue");
    extended_create["budget"]["wall_ms"]=3600001;
    rejects([&]{harness_action(svc,"create",extended_create);},"investigation time budget remains bounded");
    auto general_create=create;general_create["owner"]["profile"]["context_tokens"]=65536;
    auto general_inv=harness_action(svc,"create",general_create);investigations.push_back(general_inv);
    auto artifact_page=harness_read_packet(svc,general_inv,{{"family","artifact"},{"operation","read"},{"request",{{"offset",0},{"max_bytes",2}}}});
    check(artifact_page.at("hex")=="4d5a"&&artifact_page.at("raw_sha256")==first_target.sha256,"scoped artifact page reads exact PE signature");
    auto mapped_page=harness_read_packet(svc,general_inv,{{"family","artifact"},{"operation","read"},{"request",{{"address","0x140001000"},{"max_bytes",16}}}});
    auto calculated_page=harness_read_packet(svc,general_inv,
      {{"family","calculation"},{"operation","evaluate"},{"request",
        {{"source",{{"offset",0},{"max_bytes",2}}},{"iterations",2},
         {"variables",J::object()},{"body",J::array()},
         {"emit",J::array({"byte","i"})}}}});
    check(calculated_page.at("hex")=="4d5a"&&calculated_page.at("ascii")=="MZ"&&
          calculated_page.at("source_verified")==true,
          "finite calculator evaluates model-declared expressions over scoped bytes");
    auto xor_page=harness_read_packet(svc,general_inv,
      {{"family","calculation"},{"operation","evaluate"},{"request",
        {{"source",{{"offset",0},{"max_bytes",2}}},{"iterations",2},
         {"variables",J::object()},{"body",J::array()},
         {"emit",J::array({"xor",J::array({"byte","i"}),255})}}}});
    check(xor_page.at("hex")=="b2a5"&&!xor_page.contains("ascii"),
          "finite calculator returns exact non-printable hex without inventing text");
    check(mapped_page.at("source_verified")==true&&mapped_page.at("length")==16&&!mapped_page.at("mapping").is_null(),"artifact VA read uses native file-backed mapping");
    rejects([&]{harness_read_packet(svc,general_inv,{{"family","artifact"},{"operation","read"},{"request",{{"target_id","tgt_outside_scope"},{"offset",0}}}});},"artifact read cannot expand scope");
    rejects([&]{harness_read_packet(svc,general_inv,{{"family","artifact"},{"operation","read"},{"request",{{"address","0xffffffffffffffff"}}}});},"artifact read rejects unmapped address");
    rejects([&]{harness_read_packet(svc,general_inv,{{"family","artifact"},{"operation","read"},{"request",{{"raw_sha256",std::string(64,'0')}}}});},"artifact read rejects stale source pin");
    auto general_run=makeRun(general_inv);general_run["recipe"]="general";
    int general_turn=0;
    auto general_result=harness_explore(svc,general_run,[&](const J &,const J &body,const ModelCancel &) {
      const auto packet=J::parse(body.at("messages")[1].at("content").get<std::string>());
      check(packet.contains("investigation_state"),"general policy exposes durable state");
      if(general_turn++==0)return response(decision("plan",{{"expected_revision","irrelevant-model-version"},{"collection","tasks"},{"records",J::array({task("input_dependency",J::array(),9)})}}));
      if(general_turn==2)return response(decision("analyze",{{"proposal",{{"gap","inventory"},{"prediction","native metadata"},{"expected_evidence","inventory"},{"fallback","report gap"}}},{"request",{{"backend","xair"},{"operation","inventory"},{"target_id",first_target.id},{"budget",{{"wall_ms",120000}}}}}}));
      const auto feedback=J::parse(body.at("messages").back().at("content").get<std::string>());
      if(general_turn==4) {
        check(feedback.at("source_verified")==true&&!feedback.value("omitted",false),"oversized model page requests are safely narrowed and remain usable");
        return response(finish);
      }
      check(feedback.contains("previews")&&!feedback.at("previews").empty(),"general analysis includes native evidence preview");
      check(feedback.at("previews")[0].at("source_verified")==true,"preview is verified against immutable native bytes");
      return response(decision("retrieve",{{"family","evidence"},{"operation","read"},{"request",{{"id",feedback.at("evidence_ids")[0]},{"limit",999},{"max_bytes",9999}}}}));
    });
    check(general_turn==4&&general_result["status"]=="partial","general controller accepts plan/analyze/read/finish without entry traversal");
    auto general_saved=harness_action(svc,"controller",{{"project","demo"},{"id",general_inv["id"]}});
    check(general_saved.at("investigation_state").at("tasks")[0].at("id")=="input_dependency","plan retained by native controller persistence");
    auto general_actions=harness_action(svc,"actions",{{"project","demo"},{"id",general_inv["id"]}});
    check(general_actions.at("records")[0].at("request").at("budget").at("output_bytes")==131072,"partial model budget receives bounded output default");
    check(general_actions.at("records")[0].at("request").at("budget").at("wall_ms")==10000,"controller bounds model-requested time by selected backend policy");
    auto malformed_inv=harness_action(svc,"create",general_create);investigations.push_back(malformed_inv);
    auto malformed_run=makeRun(malformed_inv);malformed_run["recipe"]="general";
    int malformed_turn=0;
    const auto malformed_result=harness_explore(svc,malformed_run,[&](const J &,const J &body,const ModelCancel &) {
      if(malformed_turn++==0)return response(decision("plan",{{"collection","tasks"},{"records",J::array({task("discover",J::array(),5)})}}));
      if(malformed_turn==2)return response(decision("analyze",{{"proposal",{{"request",{{"backend","xair"},{"operation","inventory"}}}}}}));
      const auto feedback=J::parse(body.at("messages").back().at("content").get<std::string>());
      check(feedback.contains("error"),"malformed analysis reaches model as a durable error receipt");
      return response(finish);
    });
    const auto malformed_saved=harness_action(svc,"controller",{{"project","demo"},{"id",malformed_inv["id"]}});
    check(malformed_turn==3&&malformed_result.at("status")=="partial"&&malformed_saved.at("phase")=="terminal","malformed request accounting does not strand a response_saved checkpoint");
    check(malformed_saved.at("investigation_state").at("observations")[0].at("novel_evidence")==false,"invalid analysis does not count as investigation progress");
    auto rate_inv=harness_action(svc,"create",general_create);investigations.push_back(rate_inv);
    auto rate_run=makeRun(rate_inv);rate_run["recipe"]="general";
    const auto rate_result=harness_explore(svc,rate_run,[&](const J &,const J &,const ModelCancel &)->std::string {throw ModelRateLimitError(20);});
    auto rate_saved=harness_action(svc,"controller",{{"project","demo"},{"id",rate_inv["id"]}});
    check(rate_result.at("status")=="rate_limited"&&rate_saved.at("phase")=="ready"&&rate_saved.contains("retry_not_before"),"explicit provider rejection pauses a restartable checkpoint");
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    rate_run["expected_revision"]=harness_action(svc,"show",{{"project","demo"},{"id",rate_inv["id"]}}).at("revision");
    const auto rate_resumed=harness_explore(svc,rate_run,[&](const J &,const J &,const ModelCancel &){return response(finish);});
    check(rate_resumed.at("status")=="partial"&&rate_resumed.at("controller_usage").at("generations")==2,"rate-limit resume preserves the original generation allowance");
    // Reconstruct a crash after native completion but before feedback checkpointing.
    // The last action exhausted the balance; resume must reuse its original request.
    auto replay_create=general_create;
    replay_create["budget"]={{"max_actions",1},{"wall_ms",10000},{"output_bytes",131072}};
    auto replay_inv=harness_action(svc,"create",replay_create);investigations.push_back(replay_inv);
    auto replay_run=makeRun(replay_inv);replay_run["recipe"]="general";
    int replay_turn=0;
    harness_explore(svc,replay_run,[&](const J &,const J &,const ModelCancel &)->std::string {
      if(replay_turn++==0)return response(decision("plan",{{"collection","tasks"},{"records",J::array({task("discover",J::array(),8)})}}));
      if(replay_turn==2)return response(decision("analyze",{{"proposal",{{"gap","inventory"},{"prediction","metadata"},{"expected_evidence","inventory"},{"fallback","report gap"}}},{"request",{{"backend","xair"},{"operation","inventory"}}}}));
      throw ModelRateLimitError(1);
    });
    {
      wb::Db db(svc.store().root()/"indago-native.sqlite3");
      wb::Q get(db,"SELECT record FROM wb_model_runs WHERE project=? AND id=?");
      get.s(1,"demo").s(2,replay_inv.at("id").get<std::string>()).row();
      auto saved=J::parse(get.text(0));
      saved["pending"]=saved.at("investigation_state").at("turns").back().at("decision");
      saved["phase"]="response_saved";saved["generations"]=2;saved["prepared_analysis_generation"]=2;
      saved.erase("retry_not_before");
      wb::Q put(db,"UPDATE wb_model_runs SET record=? WHERE project=? AND id=?");
      put.s(1,saved.dump()).s(2,"demo").s(3,replay_inv.at("id").get<std::string>()).row();
    }
    replay_run["expected_revision"]=harness_action(svc,"show",{{"project","demo"},{"id",replay_inv["id"]}}).at("revision");
    harness_explore(svc,replay_run,[&](const J &,const J &body,const ModelCancel &) {
      const auto feedback=J::parse(body.at("messages").back().at("content").get<std::string>());
      check(feedback.contains("evidence_ids")&&!feedback.contains("error"),"completed native action resumes despite exhausted reservation budget");
      return response(finish);
    });
    const auto replay_actions=harness_action(svc,"actions",{{"project","demo"},{"id",replay_inv["id"]}});
    check(replay_actions.at("records").size()==1,"restart reuses native action without another reservation");
    auto large_create=create;large_create["owner"]["profile"]["context_tokens"]=131072;
    auto large_inv=harness_action(svc,"create",large_create);investigations.push_back(large_inv);
    auto large_run=makeRun(large_inv);large_run["recipe"]="general";large_run["max_generations"]=13;
    int large_turn=0;
    harness_explore(svc,large_run,[&](const J &,const J &,const ModelCancel &) {
      if(large_turn==12)return response(finish);
      J records=J::array();
      for(int n=0;n<32;++n) {auto record=task("subsystem_"+std::to_string(large_turn*32+n),J::array(),5);record["summary"]=std::string(800,'x');records.push_back(record);}
      ++large_turn;return response(decision("plan",{{"collection","tasks"},{"records",records}}));
    });
    const auto large_saved=harness_action(svc,"controller",{{"project","demo"},{"id",large_inv["id"]}});
    check(large_saved.at("investigation_state").at("tasks").size()==384&&large_saved.dump().size()>262144,"native checkpoint persists pageable state above legacy 256 KiB cap");
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
