#pragma once
#include "../src/harness_verification.hpp"
inline void proof_publication_checks(const indago::fs::path &root) {
  using namespace indago;using J=nlohmann::json;
  StaticService service(root);auto &store=service.store();store.create_project("proofs");
  atomic_write(root/"fixture.bin","benign proof publication fixture");auto target=store.import_target("proofs",root/"fixture.bin");
  auto job=service.prepare({{"project","proofs"},{"backend","xair"},{"operation","inventory"}});
  const std::string raw="{\"value\":\"candidate\"}";
  auto published=store.publish_result(target,job,"xair",{3,"partial",raw});
  auto created=harness_action(service,"create",{{"project","proofs"},{"required_facts",J::array({"candidate"})},
    {"proof_requirements",J::array({"recovered_candidate"})},{"objective","publication boundary diagnostic"},
    {"owner",{{"mode","external"},{"name","fixture"},{"model_declaration","no inference"}}},
    {"budget",{{"max_actions",4},{"wall_ms",60000},{"output_bytes",262144}}}});
  const auto id=created.at("id").get<std::string>(),token=created.at("owner_token").get<std::string>();
  wb::Db db(root/"indago-native.sqlite3");J inv;
  {wb::Q row(db,"SELECT record FROM wb_investigations WHERE project=? AND id=?");
    if(!row.s(1,"proofs").s(2,id).row())throw std::runtime_error("Fixture investigation missing");inv=J::parse(row.text(0));}
  const auto page=harness_evidence_page(store,inv,{{"id",published.at("evidence_ids")[0]},{"pointer","/value"}});
  J proof{{"schema","indago.solution-proof.v1"},{"id","diagnostic-proof"},{"kind","recovered_candidate"},
    {"project","proofs"},{"investigation",id},{"artifact_sha256",target.sha256},{"fact_index",0},
    {"question","candidate"},{"obligation","o0_candidate_validation"},{"answer","candidate"},{"state","verified"},
    {"sources",J::array({{{"evidence_id",page.at("id")},{"pointer","/value"},{"revision",page.at("revision")},
      {"native_status",page.at("native_status")},{"raw_sha256",page.at("raw_sha256")}}})}};
  auto install=[&](J p) {
    p.erase("record_sha256");p["record_sha256"]=sha256_text(p.dump());
    inv["reasoning"]["proofs"]=J::array({p});
    inv["reasoning"]["solutions"]=J::array({{{"proof",p.at("id")},{"fact_index",0},{"question","candidate"},
      {"obligation","o0_candidate_validation"},{"answer","candidate"},{"proof_kind","recovered_candidate"},{"state","question_answer_selected"}}});
    wb::Q save(db,"UPDATE wb_investigations SET record=? WHERE project=? AND id=?");save.s(1,inv.dump()).s(2,"proofs").s(3,id).row();
  };
  auto finish=[&] {
    const auto report=requirement_report(inv);
    return harness_action(service,"finish",{{"project","proofs"},{"id",id},{"owner_token",token},{"expected_revision",inv.at("revision")},
      {"status","answered"},{"answer",report.at("answer")},{"claims",report.at("claims")},{"gaps",report.at("gaps")}});
  };
  auto rejected=[&] {bool caught=false;try{finish();}catch(const std::exception &){caught=true;}if(!caught)throw std::runtime_error("Unsound typed publication accepted");};
  install(proof);
  const auto object=wb::object(store,page.at("raw_sha256").get<std::string>());
  atomic_write(object,"{\"value\":\"corrupt\"}");rejected();atomic_write(object,raw);
  auto changed=proof;changed["sources"][0]["revision"]="different";install(changed);rejected();
  changed=proof;changed["sources"][0]["pointer"]="/missing";install(changed);rejected();
  install(proof);
  const auto revision=page.at("revision").get<std::string>();
  std::string scope;{wb::Q q(db,"SELECT scope FROM analysis_heads WHERE project=? AND revision=?");if(!q.s(1,"proofs").s(2,revision).row())throw std::runtime_error("Missing head");scope=q.text(0);}
  {wb::Q q(db,"DELETE FROM analysis_heads WHERE project=? AND revision=?");q.s(1,"proofs").s(2,revision).row();}
  rejected();
  {wb::Q q(db,"INSERT INTO analysis_heads(project,scope,revision) VALUES(?,?,?)");q.s(1,"proofs").s(2,scope).s(3,revision).row();}
  const auto accepted=finish();
  if(!accepted.at("report").at("requirements_verified").get<bool>()||accepted.at("report").at("verified_solve").get<bool>())
    throw std::runtime_error("Current exact field in a partial envelope lost its limited proof semantics");
}
