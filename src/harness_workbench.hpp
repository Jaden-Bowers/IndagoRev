#pragma once
#include "harness_scope.hpp"
#include "indago/contracts.hpp"
#include "analysis_helper.hpp"
#include "harness_experiment.hpp"
#include "research_workflow.hpp"
#include "guest.hpp"

namespace indago {
// A deliberately small native worker capsule. Target execution requires the
// explicit original-target grant; no arbitrary shell or inference. Derived imports need
// a separate bounded grant and can only originate from a scoped parent.
inline wb::J normalize_harness_workbench(const ProjectStore &store,
                                         const wb::J &inv, wb::J req) {
  using namespace wb;
  if (!inv.at("envelope").value("workbench_mutations", false))
    throw std::runtime_error(
        "capability_blocked: explicit workbench mutation grant required");
  keys(req, {"project", "target_id", "artifact_sha256", "backend", "operation",
             "arguments", "budget", "dependency_pins", "derived_reservation"});
  auto selected = harness_select_component(inv, req);
  const auto p = inv.at("project").get<std::string>();
  const auto op = req.at("operation").get<std::string>();
  if (req.at("backend") != "workbench" ||
      !std::set<std::string>{"knowledge.put", "knowledge.revise",
                             "validate.compare", "validate.transform",
                             "transform.run", "helper.run", "experiment.run", "experiment.cleanup", "research.run", "guest.run"}
           .contains(op))
    throw std::runtime_error(
        "capability_blocked: workbench mutation not granted");
  auto args = req.at("arguments");
  if (args.contains("project") && args["project"] != p)
    throw std::runtime_error("cross-project workbench arguments");
  args["project"] = p;
  auto scope =
      args.value("scope", J{{"artifact_sha256", selected["artifact_sha256"]}});
  keys(scope, {"artifact_sha256"});
  if (scope.at("artifact_sha256") != selected["artifact_sha256"])
    throw std::runtime_error("workbench scope differs from selected component");
  args["scope"] = scope;
  Db db(store.root() / "indago-native.sqlite3");
  J deps = J::array();
  auto pin = [&](J d) {
    keys(d, {"type", "id", "pin"});
    auto type = d.at("type").get<std::string>(),
         id = d.at("id").get<std::string>();
    std::string version;
    if (type == "artifact") {
      if (!harness_contains_artifact(inv, id))
        throw std::runtime_error(
            "artifact dependency outside investigation scope");
      version = id;
    } else if (type == "record" || type == "evidence") {
      Q q(db, type == "record"
                  ? "SELECT CAST(revision AS TEXT) FROM wb_heads WHERE "
                    "project=? AND id=?"
                  : "SELECT revision FROM evidence WHERE project=? AND id=?");
      if (!q.s(1, p).s(2, id).row())
        throw std::runtime_error("unknown workbench dependency");
      version = q.text(0);
    } else
      throw std::runtime_error("capability_blocked: mutation dependency must "
                               "be artifact, record or evidence");
    if (d.contains("pin") && d["pin"] != version)
      throw std::runtime_error("dependency pin is stale");
    d["pin"] = version;
    deps.push_back(d);
    return d;
  };
  pin({{"type", "artifact"}, {"id", selected["artifact_sha256"]}});
  if (op == "guest.run") {
#ifndef __linux__
    throw std::runtime_error("capability_blocked: guest execution requires the Linux CLI; no host fallback");
#endif
    keys(args,{"project","scope","body","sealed"});
    keys(args.at("body"),{"profile","actions","previous","mode"});
    const auto grants=inv.at("envelope").value("guest_profiles",J::array());
    if(!grants.is_array()||grants.size()>4||std::find(grants.begin(),grants.end(),args.at("body").at("profile"))==grants.end())throw std::runtime_error("guest profile was not granted by operator");
    const auto profile=guest_action(store,"show",{{"id",args.at("body").at("profile")}});
    if(profile.at("image").at("sha256")!=selected.at("artifact_sha256"))throw std::runtime_error("guest image differs from selected investigation target");
    if(profile.contains("transfer")&&!harness_contains_artifact(inv,profile.at("transfer").at("sha256")))throw std::runtime_error("guest transfer asset must be explicitly admitted to investigation scope");
    if(profile.contains("transfer"))pin({{"type","artifact"},{"id",profile.at("transfer").at("sha256")}});
    const J seal{{"profile_sha256",profile.at("profile_sha256")}};
    if(args.contains("sealed")&&args.at("sealed")!=seal)throw std::runtime_error("guest profile changed");args["sealed"]=seal;
  } else if (op == "research.run") {
    args=normalize_research(store,inv,selected,args);
    std::function<void(const J&)> references=[&](const J &v){
      if(v.is_object()) {
        if(v.contains("id")&&v.contains("revision"))pin({{"type","record"},{"id",v.at("id")},{"pin",std::to_string(v.at("revision").get<std::uint64_t>())}});
        if(v.contains("target_id")) {const auto c=harness_select_component(inv,{{"target_id",v.at("target_id")}});pin({{"type","artifact"},{"id",c.at("artifact_sha256")}});}
        for(const auto &x:v.items())references(x.value());
      }else if(v.is_array())for(const auto &x:v)references(x);
    };references(args.at("body"));
  } else if (op == "experiment.cleanup") {
    args=normalize_experiment_cleanup(store,inv,selected,args);
  } else if (op == "experiment.run") {
    args=normalize_experiment(store,inv,selected,args);
  } else if (op == "helper.run") {
    if(!inv.at("envelope").value("analysis_helpers",false))
      throw std::runtime_error("capability_blocked: explicit analysis_helpers grant required");
    args=normalize_helper(store,selected,args,harness_components(inv));
    for(const auto &input:args.at("sealed").at("inputs"))
      pin({{"type","artifact"},{"id",input.at("page").at("artifact_sha256")}});
  } else if (op == "transform.run") {
    const auto grant =
        inv.at("envelope").value("derived_artifacts", J::object());
    if (!grant.value("max_artifacts", 0ULL) || !grant.value("max_bytes", 0ULL))
      throw std::runtime_error(
          "capability_blocked: explicit derived-artifact grant required");
    args.erase("scope");
    keys(args, {"project", "artifact", "offset", "size", "spec", "title",
                "assumptions"});
    if (args.contains("artifact") &&
        args["artifact"] != selected["artifact_sha256"])
      throw std::runtime_error(
          "transform parent differs from selected component");
    args["artifact"] = selected["artifact_sha256"];
    const bool container=args.at("spec").at("method")=="container_member";
    if (!std::set<std::string>{"slice", "xor", "hex_decode", "base64_decode", "container_member"}
             .contains(args.at("spec").at("method").get<std::string>()))
      throw std::runtime_error(
          "capability_blocked: transform method is not admitted");
    Q q(db, "SELECT size FROM targets WHERE project=? AND sha=?");
    if (!q.s(1, p).s(2, selected["artifact_sha256"].get<std::string>()).row() ||
        q.num(0) < 0 || q.num(0) > 4194304)
      throw std::runtime_error(
          "harness transform input exceeds 4 MiB or is unavailable");
    const auto bytes = static_cast<std::size_t>(q.num(0));
    auto offset = bound(args, "offset", 0, bytes);
    auto size = bound(args, "size", bytes - offset, container?4194304:1048576);
    if (size > 1048576&&!container)
      throw std::runtime_error("harness transform selection exceeds 1 MiB; "
                               "provide an explicit range");
    if (size > bytes - offset)
      throw std::runtime_error("transform range exceeds parent artifact");
    args["offset"] = offset;
    args["size"] = size;
    // All currently admitted methods preserve or shrink the selected byte
    // count.
    J reservation{{"artifacts", 1}, {"bytes", container?1048576:size}};
    if (req.contains("derived_reservation") &&
        req["derived_reservation"] != reservation)
      throw std::runtime_error("derived storage reservation mismatch");
    req["derived_reservation"] = reservation;
  } else if (op == "knowledge.put" || op == "knowledge.revise") {
    J previous = J::object();
    if (op == "knowledge.revise") {
      if (!args.contains("id") || !args.contains("expected_revision") ||
          !args.contains("body"))
        throw std::runtime_error("knowledge.revise requires id, "
                                 "expected_revision and replacement body");
      previous =
          knowledge(store, "show", {{"project", p}, {"id", args.at("id")}});
      if (previous.at("revision") != args.at("expected_revision"))
        throw std::runtime_error("revision_conflict: assertion head changed");
      if (previous.value("author", std::string{}) !=
              "harness:" + inv.at("id").get<std::string>() ||
          !previous.contains("harness_origin") ||
          previous.at("harness_origin").at("investigation") != inv.at("id"))
        throw std::runtime_error(
            "capability_blocked: only this investigation's untouched "
            "assertions may be revised");
      if (previous.at("scope") != scope)
        throw std::runtime_error(
            "assertion revision cannot change component scope");
      const auto &origin = previous.at("harness_origin");
      Q prior(db, "SELECT record FROM wb_investigation_actions WHERE project=? "
                  "AND id=?");
      if (!prior.s(1, p).s(2, origin.at("action").get<std::string>()).row())
        throw std::runtime_error("assertion publication action is unavailable");
      auto prior_request = J::parse(prior.text(0)).at("request");
      if (origin.at("request_sha256") != sha256_text(prior_request.dump()) ||
          prior_request.at("backend") != "workbench" ||
          (prior_request.at("operation") != "knowledge.put" &&
           prior_request.at("operation") != "knowledge.revise"))
        throw std::runtime_error(
            "assertion publication origin is inconsistent");
      // Copy the original bounded caller fields, not auto-expanded database
      // dependencies. Explicit replacements remain explicit (including []).
      for (const char *key : {"kind", "title", "state", "assumptions",
                              "dependencies", "support", "counterevidence"})
        if (!args.contains(key) && prior_request.at("arguments").contains(key))
          args[key] = prior_request.at("arguments").at(key);
      if (args.at("kind") != previous.at("kind"))
        throw std::runtime_error(
            "assertion revision cannot change record kind");
      pin({{"type", "record"},
           {"id", args.at("id")},
           {"pin",
            std::to_string(previous.at("revision").get<std::uint64_t>())}});
    }
    keys(args, {"project", "kind", "title", "state", "scope", "body",
                "assumptions", "dependencies", "support", "counterevidence",
                "author", "id", "expected_revision"});
    if (op == "knowledge.put" &&
        (args.contains("id") || args.contains("expected_revision")))
      throw std::runtime_error("use knowledge.revise for existing assertions");
    if (!std::set<std::string>{"summary", "hypothesis", "behavior", "question",
                               "assumption", "product"}
             .contains(args.at("kind").get<std::string>()))
      throw std::runtime_error(
          "computed knowledge kinds require their own operation");
    auto state = args.value("state", std::string("inferred"));
    if (!std::set<std::string>{"inferred", "unknown", "contradicted"}.contains(
            state))
      throw std::runtime_error(
          "harness assertions cannot claim observed or validated state");
    args["state"] = state;
    args["author"] = "harness:" + inv.at("id").get<std::string>();
    auto source = args.value("dependencies", J::array());
    if (!source.is_array() || source.size() > 32)
      throw std::runtime_error("mutation dependency count exceeds 32");
    J pinned = J::array();
    for (const auto &d : source)
      pinned.push_back(pin(d));
    args["dependencies"] = pinned;
    for (const char *key : {"support", "counterevidence"}) {
      auto refs = args.value(key, J::array());
      if (!refs.is_array() || refs.size() > 16)
        throw std::runtime_error("mutation evidence list exceeds 16");
      for (const auto &ref : refs) {
        J dependency{{"type", "evidence"}, {"id", ref}};
        // Retained evidence cannot silently move to a newer backend revision.
        if (!previous.empty())
          for (const auto &old : previous.at("dependencies"))
            if (old.at("type") == "evidence" && old.at("id") == ref)
              dependency = old;
        pin(dependency);
      }
    }
  } else {
    keys(args, {"project", "subject", "cases", "spec", "title", "scope",
                "dependencies"});
    if (args.contains("subject")) {
      auto subject = pin({{"type", "record"}, {"id", args["subject"]}});
      auto pinned = J::array({subject});
      if (args.contains("dependencies") && args["dependencies"] != pinned)
        throw std::runtime_error(
            "validator subject dependency pin is stale or inconsistent");
      args["dependencies"] = pinned;
    } else if (args.contains("dependencies"))
      throw std::runtime_error("validator dependency pin requires a subject");
    auto cases = args.at("cases");
    if (!cases.is_array() || cases.empty() || cases.size() > 16)
      throw std::runtime_error("harness validator requires 1..16 cases");
    std::uint64_t bytes = 0;
    for (const auto &c : cases) {
      keys(c, {"input_artifact", "actual_artifact", "expected_artifact",
               "expected_hex", "label"});
      if (!c.contains(op == "validate.transform" ? "input_artifact"
                                                 : "actual_artifact") ||
          c.contains("expected_artifact") == c.contains("expected_hex"))
        throw std::runtime_error("validator requires source and exactly one "
                                 "expected representation");
      for (const char *key :
           {"input_artifact", "actual_artifact", "expected_artifact"}) {
        if (!c.contains(key))
          continue;
        auto sha = c.at(key).get<std::string>();
        pin({{"type", "artifact"}, {"id", sha}});
        Q q(db, "SELECT size FROM targets WHERE project=? AND sha=?");
        if (!q.s(1, p).s(2, sha).row() || q.num(0) < 0 || q.num(0) > 262144)
          throw std::runtime_error(
              "harness validator artifact exceeds 256 KiB or is unavailable");
        bytes += static_cast<std::uint64_t>(q.num(0));
      }
      if (c.contains("expected_hex"))
        bytes += c.at("expected_hex").get<std::string>().size() / 2;
    }
    if (bytes > 1048576)
      throw std::runtime_error("harness validator aggregate exceeds 1 MiB");
  }
  if (op != "transform.run" && req.contains("derived_reservation"))
    throw std::runtime_error(
        "derived reservation is valid only for transform.run");
  harness_check_knowledge(db, inv,
                          {{"id", "prospective"},
                           {"revision", 0},
                           {"scope", scope},
                           {"dependencies", deps}});
  if (req.contains("dependency_pins") && req["dependency_pins"] != deps)
    throw std::runtime_error(
        "dependency pin is stale; proposal cannot be dispatched");
  if (args.dump().size() > 32768)
    throw std::runtime_error("workbench mutation arguments exceed 32 KiB");
  auto dot = op.find('.');
  validate_contract("workbench", {{"family", op.substr(0, dot)},
                                  {"operation", op.substr(dot + 1)},
                                  {"request", args}});
  // Wall time is enforced by the parent; memory remains declared accounting,
  // not an OS quota (including the embedded executable's mapped payload).
  J budget{{"wall_ms", (op=="experiment.run"||op=="experiment.cleanup"||op=="guest.run")?40000:op=="helper.run"?20000:10000},
           {"output_bytes", 65536},
           {"memory_bytes", op=="helper.run"?805306368:67108864},
           {"max_items", 16}};
  if (req.contains("budget") && req["budget"] != budget)
    throw std::runtime_error(
        "workbench capsule uses a fixed bounded reservation");
  req["budget"] = budget;
  req["arguments"] = args;
  req["dependency_pins"] = deps;
  req["project"] = p;
  req["target_id"] = selected["target_id"];
  req["artifact_sha256"] = selected["artifact_sha256"];
  return req;
}
inline wb::J summarize_harness_workbench(const wb::J &req, const wb::J &record,
                                         const wb::J &native) {
  using namespace wb;
  auto op = req.at("operation").get<std::string>();
  // The full immutable record remains in the knowledge store. Do not serialize
  // a possibly large validator case matrix into every action/model
  // continuation.
  J out{{"status", "completed"},
        {"knowledge_ids", J::array({record.at("id")})},
        {"record_revision", record.at("revision")},
        {"state", record.at("state")},
        {"freshness", record.at("freshness")},
        {"semantic_entailment_checked", false}};
  if(op=="guest.run") {
    const auto &body=record.at("body");out["guest"]={{"id",body.at("id")},{"status",body.at("status")},{"stopped_verified",body.value("stopped_verified",false)},{"verified_solve",false}};
  }
  if(op=="research.run") {
    const auto &body=record.at("body");out["research"]={{"kind",body.at("kind")},{"status",body.at("status")},{"universal_equivalence",false},{"verified_solve",false}};
    for(const char *key:{"next_action","scope_limit","source_sha256"})if(body.contains(key))out["research"][key]=body.at(key);
    if(body.contains("suggested_inputs")){out["research"]["suggested_inputs"]=J::array();for(const auto &input:body.at("suggested_inputs"))if(out["research"]["suggested_inputs"].size()<8)out["research"]["suggested_inputs"].push_back(input);}
    if(body.contains("counterexamples"))out["research"]["counterexample_count"]=body.at("counterexamples").size();
    if(body.contains("tested_domain"))out["research"]["tested_case_count"]=body.at("tested_domain").size();
    out["research"]["read"]="research/read with this knowledge id, revision and a bounded body pointer";
  }
  if(op=="helper.run") {
    const auto& body=record.at("body");
    out["helper"]={{"status",body.at("status")},{"validation_passed",body.at("validation_passed")},
      {"repeatable_observed",body.at("repeatable_observed")},{"verified_solve",false},
      {"output_hex",body.value("output_hex",std::string{}).substr(0,1024)},
      {"output_preview_truncated",body.value("output_hex",std::string{}).size()>1024},
      {"receipt","retrieve helper/read request:{id:KNOWLEDGE_ID,revision:RECORD_REVISION,pointer:/source_code|/output_hex|/stages/0/result/compile/stderr_hex,offset:0,max_bytes:1024}"}};
    out["helper"]["untrusted_diagnostic_preview"]=body.value("untrusted_diagnostic_preview",std::string{});
    if(body.contains("emulation")){
      const auto &emulation=body.at("emulation");
      out["helper"]["emulation"]={{"status",emulation.at("status")},{"stop_reason",emulation.at("stop_reason")},{"registers",emulation.at("registers")},{"trace_partial",emulation.at("trace_partial")},{"receipt_pointer","/emulation"}};
    }
  }
  if(op=="experiment.cleanup") {
    out["cleanup"]={{"status",record.at("body").at("status")},{"after",record.at("body").at("after")}};
  }
  if(op=="experiment.run") {
    const auto &body=record.at("body");
    out["experiment"]={{"status",body.at("status")},{"comparison",body.at("comparison")},
      {"outcome_unknown",body.at("outcome_unknown")},{"verified_solve",false}};
    out["runtime_sessions"]=wb::J::array();
    out["experiment"]["case_previews"]=wb::J::array();
    std::size_t case_index=0;
    for(const auto &c:body.at("cases")) {
      wb::J preview{{"index",case_index},{"label",c.at("label")},{"status",c.value("status",std::string("unknown"))},
        {"receipt_pointer","/cases/"+std::to_string(case_index++)}};
      if(c.contains("state")&&c.at("state").contains("observation")) {
        const auto &data=c.at("state").at("observation").at("data");
        preview["output_hex"]=data.value("output_hex",std::string{}).substr(0,512);
        preview["output_preview_truncated"]=data.value("output_hex",std::string{}).size()>512;
        preview["complete"]=data.value("complete",false);preview["operator_accepted"]=data.value("accepted",false);
      }
      out["experiment"]["case_previews"].push_back(preview);
      if(c.contains("code_recoveries"))out["experiment"]["case_previews"].back()["code_recoveries"]=c.at("code_recoveries").size();
      if(c.contains("input_solutions")) {
        auto &solutions=out["experiment"]["case_previews"].back()["input_solutions"];solutions=wb::J::array();
        for(const auto &s:c.at("input_solutions"))solutions.push_back({{"session",c.at("session")},{"observation",s.at("id")},{"status",s.at("status")},
          {"results",s.at("data").at("results")},{"usage","Replay with case.solver_candidate:{session,observation,terminal:0,branch:0|1,candidate:0} and the original baseline input_hex. Equality is branch 0; counterexample is branch 1. Acceptance needs original-target oracle."}});
      }
      if(c.contains("session"))out["runtime_sessions"].push_back(c.at("session"));
      if(c.contains("replay_session"))out["runtime_sessions"].push_back(c.at("replay_session"));
      for(const auto &peer:c.value("companions",wb::J::array()))out["runtime_sessions"].push_back(peer.at("id"));
    }
    out["experiment"]["reporting"]="Use returned knowledge_ids as evidence_ids for a PARTIAL observation report. These typed receipts never establish an answered/verified solve. Case indices are numeric (0,1), not labels; use experiment/read for narrower pointers only if the previews are insufficient.";
  }
  if (op == "transform.run") {
    out["derived_artifact"] = {
        {"target_id", native.at("target_id")},
        {"artifact_sha256", native.at("artifact_sha256")},
        {"parent_artifact_sha256", req.at("artifact_sha256")},
        {"bytes", native.at("mapping").at("output_size")},
        {"knowledge_id", record.at("id")}};
    out["mapping"] = native.at("mapping");
    out["target_selection_changed"] =
        native.value("target_selection_changed", J(nullptr));
  }
  if (record.at("kind") == "validation") {
    out["passed"] = record.at("body").at("passed");
    out["scope_limit"] = record.at("body").at("scope_limit");
    out["counterexamples"] = J::array();
    for (const auto &c : record.at("body").at("cases"))
      if (c.contains("counterexample") && out["counterexamples"].size() < 4)
        out["counterexamples"].push_back(
            {{"label", c.value("label", std::string{}).substr(0, 256)},
             {"detail", c["counterexample"]}});
  }
  return out;
}
inline wb::J execute_harness_workbench(StaticService &service,
                                       const wb::J &req) {
  const auto op = req.at("operation").get<std::string>();
  const auto dot = op.find('.');
  if(op=="guest.run") {
    const auto &args=req.at("arguments");const auto profile=guest_action(service.store(),"show",{{"id",args.at("body").at("profile")}});
    if(profile.at("profile_sha256")!=args.at("sealed").at("profile_sha256"))throw std::runtime_error("guest profile changed before execution");
    auto body=guest_action(service.store(),"run",args.at("body"));body["request_sha256"]=sha256_text(args.dump());
    auto record=wb::knowledge_put(service.store(),{{"project",args.at("project")},{"kind","product"},{"state","unknown"},{"title","Bounded QEMU guest experiment"},{"scope",args.at("scope")},{"body",body},{"dependencies",req.at("dependency_pins")},{"author","native-guest"}},true);
    auto result=summarize_harness_workbench(req,record,record);result["guest"]={{"id",body.at("id")},{"status",body.at("status")},{"stopped_verified",body.value("stopped_verified",false)}};return result;
  }
  if(op=="research.run") {
    auto record=execute_research(service.store(),req.at("arguments"));
    return summarize_harness_workbench(req,record,record);
  }
  if(op=="experiment.cleanup") {
    auto record=cleanup_experiment(service.store(),req.at("arguments"));
    auto result=summarize_harness_workbench(req,record,record);result["cleanup_status"]=record.at("body").at("status");return result;
  }
  if(op=="experiment.run") {
    auto record=execute_experiment(service.store(),req.at("arguments"));
    return summarize_harness_workbench(req,record,record);
  }
  if(op=="helper.run") {
    auto record=execute_helper(service.store(),req.at("arguments"));
    return summarize_harness_workbench(req,record,record);
  }
  auto native =
      workbench_action(service, op.substr(0, dot),
                       op == "knowledge.revise" ? "put" : op.substr(dot + 1),
                       req.at("arguments"));
  return summarize_harness_workbench(
      req, op == "transform.run" ? native.at("record") : native, native);
}
inline wb::J recover_harness_publication(StaticService &service,
                                         const wb::J &action) {
  using namespace wb;
  const auto p = action.at("project").get<std::string>();
  const auto &req = action.at("request"), &pub = action.at("publication");
  const J origin{{"investigation", action.at("investigation")},
                 {"action", action.at("id")},
                 {"request_sha256", sha256_text(req.dump())}};
  if (pub.at("origin") != origin || req.at("backend") != "workbench")
    throw std::runtime_error("publication origin does not match action");
  Db db(service.store().root() / "indago-native.sqlite3");
  Q get(db, "SELECT record,sha FROM wb_records WHERE project=? AND id=? AND "
            "revision=?");
  if (!get.s(1, p)
           .s(2, pub.at("knowledge_id").get<std::string>())
           .n(3, pub.at("revision").get<std::int64_t>())
           .row())
    throw std::runtime_error("committed publication is missing");
  const auto raw = get.text(0);
  if (pub.at("sha256") != get.text(1) || sha256_text(raw) != get.text(1) ||
      J::parse(raw).at("harness_origin") != origin)
    throw std::runtime_error("committed publication integrity mismatch");
  auto record = knowledge(service.store(), "show",
                          {{"project", p},
                           {"id", pub.at("knowledge_id")},
                           {"revision", pub.at("revision")}});
  J native = J::object();
  const auto op = req.at("operation").get<std::string>();
  if (op == "transform.run") {
    const auto &body = record.at("body");
    if (record.at("kind") != "transformation" ||
        body.at("input_artifact") != req.at("artifact_sha256") ||
        body.at("spec") != req.at("arguments").at("spec") ||
        body.at("mapping").at("input_offset") !=
            req.at("arguments").at("offset") ||
        body.at("mapping").at("input_size") != req.at("arguments").at("size"))
      throw std::runtime_error(
          "transformation publication differs from request");
    Q target(db, "SELECT id FROM targets WHERE project=? AND sha=?");
    if (!target.s(1, p)
             .s(2, body.at("output_artifact").get<std::string>())
             .row())
      throw std::runtime_error("published derived target is missing");
    native = {{"target_id", target.text(0)},
              {"artifact_sha256", body.at("output_artifact")},
              {"mapping", body.at("mapping")}};
  } else if (op=="guest.run") {
    if(record.at("kind")!="product"||record.at("body").at("schema")!="indago.guest-run.v1"||record.at("body").at("request_sha256")!=sha256_text(req.at("arguments").dump()))throw std::runtime_error("guest publication differs from request");
  } else if (op=="research.run") {
    if(record.at("kind")!="product"||record.at("body").at("schema")!="indago.research.v1"||record.at("body").at("request_sha256")!=sha256_text(req.at("arguments").dump()))throw std::runtime_error("research publication differs from request");
  } else if (op=="experiment.cleanup") {
    if(record.at("kind")!="product"||record.at("body").at("schema")!="indago.experiment-cleanup.v1"||record.at("body").at("request_sha256")!=sha256_text(req.at("arguments").dump()))throw std::runtime_error("cleanup publication differs from request");
  } else if (op=="experiment.run") {
    const auto &body=record.at("body");
    if(record.at("kind")!="product"||body.at("schema")!="indago.experiment.v1"||body.at("request_sha256")!=sha256_text(req.at("arguments").dump()))
      throw std::runtime_error("experiment publication differs from request");
  } else if (op=="helper.run") {
    const auto& body=record.at("body");
    if(record.at("kind")!="product" || body.at("schema")!="indago.helper-run.v1" ||
       body.at("request_sha256")!=sha256_text(req.at("arguments").dump()))
      throw std::runtime_error("helper publication differs from request");
  } else if (((op == "knowledge.put" || op == "knowledge.revise") &&
              record.at("kind") != req.at("arguments").at("kind")) ||
             ((op == "validate.compare" || op == "validate.transform") &&
              record.at("kind") != "validation") ||
             (op != "knowledge.put" && op != "knowledge.revise" &&
              op != "validate.compare" && op != "validate.transform"))
    throw std::runtime_error("unsupported publication recovery operation");
  if (op == "knowledge.revise" &&
      (record.at("id") != req.at("arguments").at("id") ||
       record.at("revision").get<std::uint64_t>() !=
           req.at("arguments").at("expected_revision").get<std::uint64_t>() +
               1))
    throw std::runtime_error(
        "revision publication differs from requested predecessor");
  auto result = summarize_harness_workbench(req, record, native);
  result["publication_recovered"] = true;
  result["recovery"] = "Exact committed knowledge revision recovered; "
                       "operation was not replayed";
  return result;
}
} // namespace indago
