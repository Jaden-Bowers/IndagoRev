#pragma once
#include "harness_validation.hpp"
#include "harness_verification.hpp"

namespace indago {
inline std::uint64_t model_function_budget(const wb::J &inv,unsigned count=4) {
  auto remaining=[&](const char *limit,const char *used,std::uint64_t cost) {
    const auto maximum=inv.at("budget").at(limit).get<std::uint64_t>();
    const auto reserved=inv.at("reserved").at(used).get<std::uint64_t>();
    return maximum>reserved?(maximum-reserved)/cost:0ULL;
  };
  return std::min({remaining("max_actions","actions",count),remaining("wall_ms","wall_ms",20000ULL*count),remaining("output_bytes","output_bytes",131072ULL*count)});
}
inline wb::J model_function_plan(const ProjectStore &store,const wb::J &inv,const wb::J &payload,bool acceptance=false) {
  using namespace wb;
  keys(payload,{"evidence_id","pointer"});
  const auto page=harness_evidence_page(store,inv,{{"id",payload.at("evidence_id")},{"pointer",payload.at("pointer")},{"max_bytes",64}});
  if(!page.value("source_verified",false)||page.value("partial",true)||!page.contains("text"))
    throw std::runtime_error("function requires a complete native hexadecimal address reference");
  const auto address=page.at("text").get<std::string>();
  if(!address.starts_with("0x")||harness_unsigned(address)==0)
    throw std::runtime_error("function requires a nonzero hexadecimal address");
  wb::J requests=wb::J::array();
  for(const auto &[backend,operation]:{std::pair{"ghidra","decompile"},{"xair","cfg"},{"ghidra","calls"},{"ghidra","xrefs"}})
    requests.push_back({{"backend",backend},{"operation",operation},{"address",address},
      {"artifact_sha256",page.at("artifact_sha256")},
      {"budget",{{"wall_ms",20000},{"output_bytes",131072},{"memory_bytes",2147483648ULL},{"max_items",256}}}});
  if(acceptance)for(const auto *operation:{"solve_branch","taint"})
    requests.push_back({{"backend","sym"},{"operation",operation},{"address",address},{"artifact_sha256",page.at("artifact_sha256")},
      {"budget",{{"wall_ms",20000},{"output_bytes",131072},{"memory_bytes",2147483648ULL},{"max_items",256}}}});
  return {{"source",page},{"requests",requests}};
}
// The controller, not the language model, copies values and constructs citations.
// A snapshot observation is deliberately not promoted to a behavioral proof.
inline wb::J model_record_fact(const ProjectStore &store, const wb::J &inv,
                               const wb::J &payload) {
  using namespace wb;
  keys(payload,{"fact_index","evidence_id","pointer"});
  const auto index=harness_unsigned(payload.at("fact_index"));
  if(index>=inv.at("required_facts").size())
    throw std::runtime_error("fact_index outside required facts");
  auto page=harness_evidence_page(store,inv,{{"id",payload.at("evidence_id")},
      {"pointer",payload.at("pointer")},{"max_bytes",512}});
  if(!page.value("source_verified",false)||page.value("partial",true))
    throw std::runtime_error("record requires a complete verified scalar; select a narrower pointer");
  const auto value=page.contains("text")?page.at("text"):page.at("value");
  if(!value.is_primitive()||value.dump().size()>512)
    throw std::runtime_error("record requires a bounded scalar, not a container");
  wb::J ref={{"evidence_id",page.at("id")},{"pointer",page.at("pointer")},
             {"raw_sha256",page.at("raw_sha256")}};
  wb::J checks=wb::J::array({{{"operation","equal"},{"operands",wb::J::array({ref})},{"expected",value}}});
  auto receipt=harness_validate(store,inv,checks);
  wb::J claim={{"fact",inv.at("required_facts")[index]},
    {"text","Native snapshot "+page.at("id").get<std::string>()+" at "+page.at("pointer").get<std::string>()+" = "+value.dump()},
    {"evidence_ids",wb::J::array({page.at("id")})},{"checks",checks},
    {"limitations",wb::J::array({"Exact native snapshot observation only; relevance to the required fact and behavioral entailment are not proven."})}};
  return {{"id","fact_"+sha256_text(claim.dump())},{"fact_index",index},
          {"claim",claim},{"receipt",receipt}};
}
inline wb::J model_ledger_report(const wb::J &inv,const wb::J &ledger,
                                 const std::string &status,const std::string &reason) {
  wb::J claims=wb::J::array();
  for(const auto &entry:ledger)claims.push_back(entry.at("claim"));
  return {{"status",status},{"answer",reason},{"claims",claims},
          {"gaps",inv.at("required_facts")}};
}
inline wb::J model_solution_report(const wb::J &inv) {
  auto report=requirement_report(inv);
  // The public finish request accepts only these fields; native proof metadata
  // is assembled again at publication, not trusted from model JSON.
  return {{"status",report.at("status")},{"answer",report.at("answer")},
    {"claims",report.at("claims")},{"gaps",report.at("gaps")}};
}
}
