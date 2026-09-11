#pragma once
#include "../src/harness_reasoning.hpp"
inline void runtime_proof_checks(const indago::fs::path &root,const indago::fs::path &fixture) {
  using namespace indago;using J=nlohmann::json;
  StaticService svc(root);auto &store=svc.store();store.create_project("receipts");
  auto target=store.import_target("receipts",fixture);
  const auto oracle=root.parent_path()/"io-oracle.json";
  atomic_write(oracle,J{{"schema","indago.io-oracle.v1"},{"artifact_sha256",target.sha256},{"fact","accepted input"},
    {"stdout_hex","4f4b"},{"exit_code",0},{"negative_input_hex","4e4f"}}.dump());
  J io{{"operation","io-run"},{"project","receipts"},{"file",fixture.string()},
    {"artifact",target.sha256},{"input_hex","4f50454e"},{"trusted_target_ack",true},{"acceptance_oracle",oracle.string()},{"timeout_ms",3000}};
  const auto session=runtime_command(store,{},io);
  auto bounded=io;bounded["argv"]=J::array({"flood"});bounded["max_output_bytes"]=1;
  const auto partial=runtime_command(store,{},bounded);
  bounded=io;bounded["argv"]=J::array({"child"});
  const auto child=runtime_command(store,{},bounded);
  if(partial.at("observation").at("data").at("complete")!=false||child.at("observation").at("data").at("complete")!=false||
     child.at("observation").at("data").at("output_eof")!=false)throw std::runtime_error("Incomplete process output was certified");
  auto job=svc.prepare({{"project","receipts"},{"backend","xair"},{"operation","inventory"}});
  const auto published=store.publish_result(target,job,"xair",{0,"completed",J{{"diagnostic_input","OPEN"}}.dump()});
  const J source{{"evidence_id",published.at("evidence_ids")[0]},{"pointer","/diagnostic_input"}};
  for(const auto kind:{"accepted_input","observed_output"}) {
    auto inv=harness_action(svc,"create",{{"project","receipts"},{"target_id",target.id},{"required_facts",J::array({"accepted input"})},
      {"proof_requirements",J::array({kind})},{"objective","benign native receipt diagnostic"},
      {"runtime_observation_sessions",J::array({session.at("id"),partial.at("id")})},
      {"owner",{{"mode","external"},{"name","fixture"},{"model_declaration","no inference"}}},
      {"budget",{{"max_actions",8},{"wall_ms",60000},{"output_bytes",262144}}}});
    const auto token=inv.at("owner_token");
    auto update=[&](const std::string &op,const J &record) {
      const auto changed=harness_action(svc,"reason",{{"project","receipts"},{"id",inv.at("id")},{"owner_token",token},{"expected_revision",inv.at("revision")},
        {"request",{{"operation",op},{"expected_revision",inv.value("reasoning",reasoning_initial(inv)).at("revision")},{"record",record}}}});
      inv["revision"]=changed.at("revision");inv["reasoning"]=changed.at("reasoning");
    };
    update("hypothesize",{{"obligation","o0_acceptance"},{"statement","Fixture accepts this candidate"},{"prediction","Exact oracle match"},
      {"falsifier","Contrasting input also succeeds"},{"sources",J::array({source})}});
    const auto hypothesis=inv.at("reasoning").at("hypotheses")[0].at("id");
    update("derive",{{"obligation","o0_candidate_validation"},{"source",source},{"representation","utf8"},
      {"spec",{{"method","xor"},{"key_hex","00"}}},{"encoding","UTF8"},{"assumptions","Generated test candidate"}});
    const auto candidate=inv.at("reasoning").at("candidates")[0].at("id");
    const bool accepted=std::string(kind)=="accepted_input";
    update("experiment",{{"hypothesis",hypothesis},{"candidate",candidate},{"prediction","Recorded I/O matches"},
      {"observe","io_result"},{"pointer",accepted?"/data/accepted":"/data/output"},{"expected",accepted?J(true):J("OK")},
      {"fact_index",0},{"proof_kind",kind},{"sources",J::array({source})}});
    const auto experiment=inv.at("reasoning").at("experiments")[0].at("id"),receipt=session.at("observation");
    bool rejected=false;
    try {update("feedback",{{"id",experiment},{"session",session.at("id")},{"observation",receipt.at("id")},{"sha256",std::string(64,'0')}});}
    catch(const std::exception &){rejected=true;}
    if(!rejected)throw std::runtime_error("Changed runtime receipt pin accepted");
    rejected=false;
    try {update("feedback",{{"id",experiment},{"session",partial.at("id")},{"observation",partial.at("observation").at("id")},
      {"sha256",partial.at("observation").at("sha256")}});}catch(const std::exception &){rejected=true;}
    if(!rejected)throw std::runtime_error("Incomplete runtime receipt accepted as proof");
    update("feedback",{{"id",experiment},{"session",session.at("id")},{"observation",receipt.at("id")},{"sha256",receipt.at("sha256")}});
    update("prove_observation",{{"experiment",experiment},{"answer",accepted?"OPEN":"OK"}});
    update("solution",{{"proof",inv.at("reasoning").at("proofs").back().at("id")},{"answer",accepted?"OPEN":"OK"}});
    const auto report=requirement_report(inv);
    inv=harness_action(svc,"finish",{{"project","receipts"},{"id",inv.at("id")},{"owner_token",token},{"expected_revision",inv.at("revision")},
      {"status","answered"},{"answer",report.at("answer")},{"claims",report.at("claims")},{"gaps",report.at("gaps")}});
    if(inv.at("report").at("behavior_verified")!=true||inv.at("report").at("verified_solve")!=false)
      throw std::runtime_error("Runtime proof changed independent-grading semantics");
  }
}
