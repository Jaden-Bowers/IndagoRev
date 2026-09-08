#pragma once
#include "../src/harness_reasoning.hpp"
inline void reasoning_checks(indago::StaticService &svc,nlohmann::json inv,const nlohmann::json &evidence) {
  using namespace indago;using J=nlohmann::json;
  {
    std::vector<unsigned char> blob={0xe8,0,0,0,0,0x8b,0x34,0x24,0x83,0xc6,0x17,0xb9,7,0,0,0,
      0x83,0xf9,0,0x74,7,0x80,0x36,0x66,0x46,0x49,0xeb,0xf4,
      static_cast<unsigned char>(0x68^0x66),static_cast<unsigned char>(0x54^0x66),
      static_cast<unsigned char>(0x45^0x66),static_cast<unsigned char>(0x53^0x66),
      static_cast<unsigned char>(0x54^0x66),static_cast<unsigned char>(0x89^0x66),
      static_cast<unsigned char>(0xe1^0x66)};
    std::string decompiled;
    for(std::size_t i=0;i<blob.size();++i)
      decompiled+="local_"+hex_address(blob.size()-i).substr(2)+" = "+std::to_string(blob[i])+";\n";
    const auto recovered=recover_initialized_x86_blob(decompiled);
    check(recovered.at("answer")=="TEST"&&recovered.at("stages").size()==1,
          "bounded initialized-x86 recovery peels a recognized decoder and finds its final stack string");
  }
  {
    std::vector<unsigned char> inner={0x68,'K','E','Y','!',0x89,0xe3,0xe8,0,0,0,0,0x8b,0x34,0x24,0x83,0xc6,0,
      0x89,0xf1,0x81,0xc1,7,0,0,0,0x89,0xd8,0x83,0xc0,4,0x39,0xd8,0x75,5,0x89,0xe3,0x83,0xc3,4,
      0x39,0xce,0x74,8,0x8a,0x13,0x30,0x16,0x43,0x46,0xeb,0xeb};
    inner[17]=static_cast<unsigned char>(inner.size()-12);
    for(auto byte:std::vector<unsigned char>{0x68,'D','O','N','E',0x89,0xe1})
      inner.push_back(byte^std::vector<unsigned char>{'K','E','Y','!'}[(inner.size()-52)%4]);
    std::vector<unsigned char> blob={0xe8,0,0,0,0,0x8b,0x34,0x24,0x83,0xc6,0x17,0xb9,
      static_cast<unsigned char>(inner.size()),0,0,0,0x83,0xf9,0,0x74,7,0x80,0x36,0x66,0x46,0x49,0xeb,0xf4};
    for(auto byte:inner)blob.push_back(byte^0x66);
    std::string decompiled;
    for(std::size_t i=0;i<blob.size();++i)
      decompiled+="local_"+hex_address(blob.size()-i).substr(2)+" = "+std::to_string(blob[i])+";\n";
    const auto recovered=recover_initialized_x86_blob(decompiled);
    check(recovered.at("answer")=="DONE"&&recovered.at("stages").size()==2,
          "nested initialized-x86 recovery handles computed bounds and skips a loop-local key reset");
  }
  const J source={{"evidence_id",evidence},{"pointer","/program/format"}};
  auto update=[&](const std::string &op,const J &record) {
    inv["reasoning"]=reasoning_update(svc.store(),inv,{{"operation",op},{"expected_revision",inv.value("reasoning",reasoning_initial(inv)).at("revision")},{"record",record}});
  };
  update("bind",{{"id","o0_input"},{"description","Native metadata is a lead, not the input channel"},{"sources",J::array({source})}});
  check(inv["reasoning"]["obligations"][0]["state"]=="located_unproven","binding evidence cannot resolve an acceptance obligation");
  rejects([&]{reasoning_update(svc.store(),inv,{{"operation","bind"},{"expected_revision",0},{"record",J::object()}});},"stale reasoning edit rejected");
  update("hypothesize",{{"obligation","o0_acceptance"},{"statement","A declared byte transform may explain expected bytes"},{"prediction","XOR round trip matches native bytes"},{"falsifier","A differing byte"},{"sources",J::array({source})}});
  const auto hypothesis=inv["reasoning"]["hypotheses"][0]["id"];
  update("derive",{{"obligation","o0_candidate_validation"},{"source",source},{"representation","utf8"},
    {"spec",{{"method","xor"},{"key_hex","01"}}},{"encoding","raw bytes"},{"assumptions","Spec is a test hypothesis, not proven target semantics"}});
  const auto candidate=inv["reasoning"]["candidates"][0]["id"];
  check(inv["reasoning"]["candidates"][0]["hex"]=="5144","derivation reuses exact native byte transforms");
  update("validate_transform_candidate",{{"id",candidate},{"expected",source},{"representation","utf8"},{"spec",{{"method","xor"},{"key_hex","01"}}}});
  check(inv["reasoning"]["candidates"][0]["state"]=="finite_transform_matched"&&inv["reasoning"]["candidates"][0]["acceptance_proven"]==false,"passing byte test is not accepted input proof");
  update("validate_transform_candidate",{{"id",candidate},{"expected",source},{"representation","utf8"},{"spec",{{"method","xor"},{"key_hex","02"}}}});
  check(inv["reasoning"]["candidates"][0]["state"]=="finite_transform_contradicted","negative candidate test retained");
  update("experiment",{{"hypothesis",hypothesis},{"candidate",candidate},{"prediction","The current-state witness reaches its predicted destination"},
    {"observe","branch_witness"},{"pointer","/data/verdict"},{"expected","predicted destination observed"},{"sources",J::array({source})}});
  const auto experiment=inv["reasoning"]["experiments"][0]["id"];
  check(inv["reasoning"]["experiments"][0]["execution_authorized"]==false,"experiment planning cannot grant execution");
  rejects([&]{update("feedback",{{"id",experiment},{"session","run_ungranted"},{"observation","obs_unknown"},{"sha256",std::string(64,'a')}});},"runtime feedback requires explicit session read scope");
  rejects([&]{update("bind",{{"id","o0_input"},{"description","fake validation"},{"sources",J::array({source})},{"state","proven"}});},"model cannot supply proven state");
  const auto before=inv["reasoning"];
  rejects([&]{update("derive",{{"obligation","o0_candidate_validation"},{"source",source},{"representation","implicit"},
    {"spec",{{"method","xor"},{"key_hex","01"}}},{"encoding","raw"},{"assumptions","bad representation"}});},"byte representation must be explicit");
  check(inv["reasoning"]==before,"failed reasoning operation leaves state unchanged");
}
