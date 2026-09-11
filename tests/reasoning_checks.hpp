#pragma once
#include "../src/harness_reasoning.hpp"
inline void reasoning_checks(indago::StaticService &svc,nlohmann::json inv,const nlohmann::json &evidence) {
  using namespace indago;using J=nlohmann::json;
  auto decompiled_blob=[](const std::vector<unsigned char> &blob) {
    std::string decompiled;
    for(std::size_t i=0;i<blob.size();++i)
      decompiled+="local_"+hex_address(blob.size()-i).substr(2)+" = "+std::to_string(blob[i])+";\n";
    decompiled+="(*(code *)&local_"+hex_address(blob.size()).substr(2)+")();\n";
    return decompiled;
  };
  auto one_layer=[](std::vector<unsigned char> payload) {
    std::vector<unsigned char> blob={0xe8,0,0,0,0,0x8b,0x34,0x24,0x83,0xc6,0x17,0xb9,
      static_cast<unsigned char>(payload.size()),0,0,0,0x83,0xf9,0,0x74,7,0x80,0x36,0x66,0x46,0x49,0xeb,0xf4};
    for(auto byte:payload)blob.push_back(byte^0x66);return blob;
  };
  const std::vector<unsigned char> valid_sink={0x68,'T','E','S','T',0x89,0xe1,0x31,0xc0,0x51,0x50,0xff,0xd7,0xc3};
  {
    const auto recovered=recover_initialized_x86_blob(decompiled_blob(one_layer(valid_sink)));
    check(recovered.at("answer")=="TEST"&&recovered.at("stages").size()==1&&
          recovered.at("native_control_flow_verified")==true&&recovered.at("value_to_sink_verified")==true,
          "reachable initialized-x86 recovery uses XAIR instruction and control-flow validation and tracks its value to the call sink");
  }
  {
    std::vector<unsigned char> inner={0x68,'K','E','Y','!',0x89,0xe3,0xe8,0,0,0,0,0x8b,0x34,0x24,0x83,0xc6,0,
      0x89,0xf1,0x81,0xc1,7,0,0,0,0x89,0xd8,0x83,0xc0,4,0x39,0xd8,0x75,5,0x89,0xe3,0x83,0xc3,4,
      0x39,0xce,0x74,8,0x8a,0x13,0x30,0x16,0x43,0x46,0xeb,0xeb};
    inner[17]=static_cast<unsigned char>(inner.size()-12);
    const std::vector<unsigned char> payload={0x68,'D','O','N','E',0x89,0xe1,0x31,0xc0,0x51,0x50,0xff,0xd7,0xc3};
    inner[22]=static_cast<unsigned char>(payload.size());
    for(auto byte:payload)
      inner.push_back(byte^std::vector<unsigned char>{'K','E','Y','!'}[(inner.size()-52)%4]);
    auto bad_reset=inner;bad_reset[39]=8;
    rejects([&]{recover_initialized_x86_blob(decompiled_blob(one_layer(bad_reset)));},"altered key reset displacement rejected");
    std::vector<unsigned char> blob={0xe8,0,0,0,0,0x8b,0x34,0x24,0x83,0xc6,0x17,0xb9,
      static_cast<unsigned char>(inner.size()),0,0,0,0x83,0xf9,0,0x74,7,0x80,0x36,0x66,0x46,0x49,0xeb,0xf4};
    for(auto byte:inner)blob.push_back(byte^0x66);
    const auto recovered=recover_initialized_x86_blob(decompiled_blob(blob));
    check(recovered.at("answer")=="DONE"&&recovered.at("stages").size()==2,
          "nested initialized-x86 recovery handles computed bounds and skips a loop-local key reset");
  }
  {
    auto payload=valid_sink;
    payload.insert(payload.end(),{0x68,'F','A','K','E',0x89,0xe1,0x31,0xc0,0x51,0x50,0xff,0xd7});
    const auto recovered=recover_initialized_x86_blob(decompiled_blob(one_layer(payload)));
    check(recovered.at("answer")=="TEST"&&recovered.at("strings").size()==1,
      "unreachable decoy string cannot become a recovered answer");
  }
  {
    auto blob=one_layer(valid_sink);blob.insert(blob.begin(),0xc3);
    rejects([&]{recover_initialized_x86_blob(decompiled_blob(blob));},"unreachable decoder is rejected");
  }
  {
    const std::vector<unsigned char> overwritten={0x68,'T','E','S','T',0x89,0xe1,0xc6,0x01,'X',0x31,0xc0,0x51,0x50,0xff,0xd7,0xc3};
    rejects([&]{recover_initialized_x86_blob(decompiled_blob(one_layer(overwritten)));},"value overwritten before its sink is rejected");
  }
  {
    auto blob=one_layer(valid_sink);blob[19]=0x75;
    rejects([&]{recover_initialized_x86_blob(decompiled_blob(blob));},"altered decoder branch condition is rejected");
  }
  for(const auto [offset,value]:std::vector<std::pair<std::size_t,unsigned char>>{{18,1},{27,0xe4},{10,1}}) {
    auto blob=one_layer(valid_sink);blob[offset]=value;
    rejects([&]{recover_initialized_x86_blob(decompiled_blob(blob));},"changed compare operand, back edge, or overlapping write range is rejected");
  }
  {
    std::vector<unsigned char> blob={0xe8,0,0,0,0,0x8b,0x34,0x24,0x83,0xc6,30,0xb9,16,0,0,0,
      0x83,0xf9,0,0x7e,14,0x81,0x36,1,2,3,4,0x83,0xc6,4,0x83,0xe9,4,0xeb,0xed};
    auto payload=valid_sink;payload.resize(16,0x90);
    for(std::size_t n=0;n<payload.size();++n)blob.push_back(payload[n]^static_cast<unsigned char>(n%4+1));
    check(recover_initialized_x86_blob(decompiled_blob(blob)).at("answer")=="TEST","DWORD loop exact-state positive control");
    blob[32]=1;
    rejects([&]{recover_initialized_x86_blob(decompiled_blob(blob));},"changed DWORD counter decrement rejected");
  }
#if INDAGO_HAS_XAIR
  {
    const auto blob=one_layer(valid_sink);auto recovered=recover_initialized_x86_blob(decompiled_blob(blob));
    recovered["local_base"]=blob.size()+4;
    std::vector<unsigned char> native={0x55,0x89,0xe5,0x81,0xec};
    auto put=[&](std::uint32_t v){for(unsigned n=0;n<4;++n)native.push_back(static_cast<unsigned char>(v>>(8*n)));};
    put(static_cast<std::uint32_t>(blob.size()));
    for(std::size_t n=0;n<blob.size();++n){native.insert(native.end(),{0xc6,0x85});put(static_cast<std::uint32_t>(n-blob.size()));native.push_back(blob[n]);}
    native.insert(native.end(),{0x8d,0x85});put(static_cast<std::uint32_t>(-static_cast<int>(blob.size())));native.insert(native.end(),{0xff,0xd0});
    check(recovery_native_initializer(native,recovered).at("store_count")==blob.size(),"native initializer proves exact stored bytes and invoked buffer");
    auto wrong=native;wrong[15]^=1;
    rejects([&]{recovery_native_initializer(wrong,recovered);},"different native initializer byte rejected despite unchanged Ghidra text");
    wrong=native;wrong[wrong.size()-6]++;
    rejects([&]{recovery_native_initializer(wrong,recovered);},"call to adjacent local rejected");
    wrong=native;wrong.insert(wrong.begin()+9,{0x74,0x07});
    rejects([&]{recovery_native_initializer(wrong,recovered);},"conditional initializer rejected");
    wrong=native;wrong.insert(wrong.begin()+16,native.begin()+9,native.begin()+16);
    rejects([&]{recovery_native_initializer(wrong,recovered);},"repeated native store rejected");
  }
#endif
  {
    auto gate=inv;
    gate["required_facts"]=J::array({"decoder candidate","accepted input"});
    gate["proof_requirements"]=J::array({"recovered_candidate","accepted_input"});
    gate["questions"]=J::array({
      {{"id","q0"},{"fact_index",0},{"text","decoder candidate"},{"proof_obligation","recovered_candidate"}},
      {{"id","q1"},{"fact_index",1},{"text","accepted input"},{"proof_obligation","accepted_input"}}});
    gate["reasoning"]=reasoning_initial(gate);
    auto add_proof=[&](std::size_t index,const std::string &kind,const std::string &answer) {
      J proof{{"schema","indago.solution-proof.v1"},{"id","proof_"+std::to_string(index)+"_"+kind},
        {"project",gate.at("project")},{"investigation",gate.at("id")},{"artifact_sha256",gate.at("artifact_sha256")},
        {"fact_index",index},{"question",gate.at("required_facts")[index]},{"obligation",proof_obligation_id(kind,index)},
        {"kind",kind},{"answer",answer},{"state","verified"}};
      proof["record_sha256"]=sha256_text(proof.dump());gate["reasoning"]["proofs"].push_back(proof);
      gate["reasoning"]["solutions"].push_back({{"proof",proof.at("id")},{"fact_index",index},
        {"question",proof.at("question")},{"obligation",proof.at("obligation")},{"proof_kind",kind},
        {"answer",answer},{"state","question_answer_selected"}});
    };
    add_proof(0,"recovered_candidate","TEST");
    check(verified_requirements(gate).size()==1,"a recovered candidate resolves only its bound question");
    rejects([&]{requirement_report(gate);},"a recovered string cannot resolve an unrelated accepted-input requirement");
    add_proof(1,"observed_output","TEST");
    check(verified_requirements(gate).size()==1,"an observed output is not accepted-input proof");
    add_proof(1,"accepted_input","TEST");
    const auto bounded_report=requirement_report(gate);
    check(verified_requirements(gate).size()==2&&bounded_report.at("proof_kinds").size()==2,
      "proof kinds remain distinct and satisfy only exact question requirements");
    check(bounded_report.at("requirements_verified")==true&&bounded_report.at("verified_solve")==false&&
      bounded_report.at("independently_graded")==false,
      "completed candidate and acceptance questions are not labeled an independently verified challenge solve");
    auto tampered=gate;tampered["reasoning"]["proofs"][0]["answer"]="DECOY";
    check(verified_requirements(tampered).size()==1,
      "a changed answer invalidates its signed proof without affecting another question");
    auto rebound=gate;rebound["reasoning"]["solutions"][0]["question"]="accepted input";
    check(verified_requirements(rebound).size()==1,
      "a solution cannot rebind a proof to a different question");
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
  rejects([&]{update("experiment",{{"hypothesis",hypothesis},{"candidate",candidate},{"prediction","An unrelated scalar implies acceptance"},
    {"observe","io_result"},{"pointer","/data/verdict"},{"expected","accepted"},{"fact_index",0},{"proof_kind","accepted_input"},
    {"sources",J::array({source})}});},"accepted-input proof plans require exact input bytes and the standard acceptance result");
  rejects([&]{update("feedback",{{"id",experiment},{"session","run_ungranted"},{"observation","obs_unknown"},{"sha256",std::string(64,'a')}});},"runtime feedback requires explicit session read scope");
  rejects([&]{update("bind",{{"id","o0_input"},{"description","fake validation"},{"sources",J::array({source})},{"state","proven"}});},"model cannot supply proven state");
  const auto before=inv["reasoning"];
  rejects([&]{update("derive",{{"obligation","o0_candidate_validation"},{"source",source},{"representation","implicit"},
    {"spec",{{"method","xor"},{"key_hex","01"}}},{"encoding","raw"},{"assumptions","bad representation"}});},"byte representation must be explicit");
  check(inv["reasoning"]==before,"failed reasoning operation leaves state unchanged");
}
