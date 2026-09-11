#pragma once
#include "indago/core.hpp"
#include <set>

namespace indago {
using VerificationJson=nlohmann::json;

inline const std::set<std::string> &solution_proof_kinds() {
  static const std::set<std::string> kinds{
    "recovered_candidate",
    "verified_transformation",
    "observed_output",
    "accepted_input",
    "independently_graded_challenge_solve"};
  return kinds;
}

inline std::string required_proof_kind(const VerificationJson &inv,std::size_t index) {
  const auto requirements=inv.value("proof_requirements",VerificationJson::array());
  if(index>=requirements.size())return {};
  return requirements.at(index).get<std::string>();
}

inline std::string proof_obligation_id(const std::string &kind,std::size_t index) {
  const auto prefix="o"+std::to_string(index)+"_";
  if(kind=="recovered_candidate")return prefix+"candidate_validation";
  if(kind=="verified_transformation"||kind=="observed_output")return prefix+"output";
  if(kind=="accepted_input")return prefix+"acceptance";
  if(kind=="independently_graded_challenge_solve")return prefix+"challenge_solve";
  return {};
}

inline bool verification_record_intact(const VerificationJson &record) {
  if(!record.is_object()||!record.contains("record_sha256"))return false;
  auto unsigned_record=record;
  const auto digest=unsigned_record.at("record_sha256").get<std::string>();
  unsigned_record.erase("record_sha256");
  return sha256_text(unsigned_record.dump())==digest;
}

inline bool selected_reasoning_proof(const VerificationJson &reasoning,const VerificationJson &proof) {
  for(const auto &solution:reasoning.value("solutions",VerificationJson::array()))
    if(solution.value("state",std::string())=="question_answer_selected"&&
       solution.value("proof",std::string())==proof.value("id",std::string())&&
       solution.value("fact_index",std::size_t(-1))==proof.value("fact_index",std::size_t(-2))&&
       solution.value("question",std::string())==proof.value("question",std::string())&&
       solution.value("obligation",std::string())==proof.value("obligation",std::string())&&
       solution.value("proof_kind",std::string())==proof.value("kind",std::string())&&
       solution.value("answer",std::string())==proof.value("answer",std::string()))return true;
  return false;
}

// Proof kinds are intentionally not ranked. An observed output does not prove an
// accepted input, and an independent answer grade does not prove program behavior.
inline VerificationJson verified_requirements(const VerificationJson &inv) {
  using J=VerificationJson;J matched=J::array();
  if(!inv.contains("proof_requirements"))return matched;
  const auto &facts=inv.at("required_facts");
  const auto &requirements=inv.at("proof_requirements");
  if(!requirements.is_array()||requirements.size()!=facts.size())
    throw std::runtime_error("Proof requirements no longer match requested questions");
  const auto reasoning=inv.value("reasoning",J::object());
  for(std::size_t i=0;i<facts.size();++i) {
    const auto required=required_proof_kind(inv,i);J selected;
    for(const auto &proof:reasoning.value("proofs",J::array())) {
      if(!verification_record_intact(proof)||proof.value("schema",std::string())!="indago.solution-proof.v1"||
         proof.value("kind",std::string())!=required||proof.value("fact_index",facts.size())!=i||
         proof.value("question",std::string())!=facts[i].get<std::string>()||
         proof.value("obligation",std::string())!=proof_obligation_id(required,i)||
         proof.value("artifact_sha256",std::string())!=inv.at("artifact_sha256").get<std::string>()||
         proof.value("investigation",std::string())!=inv.at("id").get<std::string>()||
         proof.value("project",std::string())!=inv.at("project").get<std::string>()||
         !selected_reasoning_proof(reasoning,proof))continue;
      if(selected.is_null())selected=proof;
      else if(selected.at("answer")!=proof.at("answer"))throw std::runtime_error("Contradictory proofs for one question");
    }
    for(const auto &proof:inv.value("verifications",J::array())) {
      if(!verification_record_intact(proof)||proof.value("schema",std::string())!="indago.solution-proof.v1"||
         proof.value("kind",std::string())!=required||proof.value("fact_index",facts.size())!=i||
         proof.value("question",std::string())!=facts[i].get<std::string>()||
         proof.value("obligation",std::string())!=proof_obligation_id(required,i)||
         proof.value("artifact_sha256",std::string())!=inv.at("artifact_sha256").get<std::string>()||
         proof.value("investigation",std::string())!=inv.at("id").get<std::string>()||
         proof.value("project",std::string())!=inv.at("project").get<std::string>())continue;
      if(selected.is_null())selected=proof;
      else if(selected.at("answer")!=proof.at("answer"))throw std::runtime_error("Contradictory proofs for one question");
    }
    if(!selected.is_null())matched.push_back(selected);
  }
  return matched;
}

inline std::string proof_claim_text(const std::string &kind) {
  if(kind=="recovered_candidate")return "The answer is a question-bound recovered candidate; no transformation or behavior proof is claimed.";
  if(kind=="verified_transformation")return "XAIR instruction decoding and control-flow checks reproduce the transformation and track the value to the recorded call/comparison sink.";
  if(kind=="observed_output")return "A hash-pinned authorized runtime observation contains this output for the recorded execution.";
  if(kind=="accepted_input")return "A hash-pinned authorized runtime observation shows this exact input reaching the declared acceptance result.";
  return "The submitted answer passed the independent question- and artifact-bound challenge grader.";
}

inline VerificationJson requirement_report(const VerificationJson &inv) {
  using J=VerificationJson;const auto records=verified_requirements(inv);
  if(records.size()!=inv.at("required_facts").size()||records.empty())
    throw std::runtime_error("The declared proof type is required for every requested question; use partial");
  J claims=J::array(),answers=J::object(),kinds=J::array();
  for(const auto &proof:records) {
    answers[proof.at("question").get<std::string>()]=proof.at("answer");
    if(std::find(kinds.begin(),kinds.end(),proof.at("kind"))==kinds.end())kinds.push_back(proof.at("kind"));
    J claim{{"fact",proof.at("question")},{"text",proof_claim_text(proof.at("kind"))},
      {"proof_id",proof.at("id")},{"proof_sha256",proof.at("record_sha256")},
      {"proof_kind",proof.at("kind")},{"limitations",proof.value("limitations",J::array())}};
    J evidence=J::array();
    for(const auto &source:proof.value("sources",J::array()))
      if(source.contains("evidence_id")&&std::find(evidence.begin(),evidence.end(),source.at("evidence_id"))==evidence.end())
        evidence.push_back(source.at("evidence_id"));
    if(!evidence.empty())claim["evidence_ids"]=evidence;
    claims.push_back(claim);
  }
  const std::string answer=records.size()==1?records[0].at("answer").get<std::string>():answers.dump();
  const bool independently_graded=std::any_of(records.begin(),records.end(),[](const J &p){
    return p.at("kind")=="independently_graded_challenge_solve";
  });
  return {{"status","answered"},{"answer",answer},{"claims",claims},{"gaps",J::array()},
    {"requirements_verified",true},{"verified_solve",independently_graded},{"proof_kinds",kinds},
    {"independently_graded",independently_graded},
    {"behavior_verified",std::any_of(records.begin(),records.end(),[](const J &p){return p.at("kind")=="observed_output"||p.at("kind")=="accepted_input";})}};
}
}
