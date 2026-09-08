#pragma once
#include "harness_validation.hpp"
#include "indago/runtime.hpp"
#include <regex>

namespace indago {
// Durable investigation-local assertions. Only the native checker can set a
// checked state; no model-authored label is accepted as validation or a solve.
inline wb::J reasoning_initial(const wb::J &inv) {
  wb::J obligations=wb::J::array();
  for(std::size_t i=0;i<inv.at("required_facts").size();++i)
    for(const auto *role:{"input","acceptance","rejection","constraints","output","candidate_validation"})
      obligations.push_back({{"id","o"+std::to_string(i)+"_"+role},{"fact_index",i},{"role",role},{"state","unresolved"}});
  return {{"schema","indago.reasoning.v1"},{"revision",0},{"obligations",obligations},
    {"hypotheses",wb::J::array()},{"candidates",wb::J::array()},{"experiments",wb::J::array()},
    {"recoveries",wb::J::array()},{"solutions",wb::J::array()},
    {"verified_solve",false}};
}

inline std::string reasoning_hex(const std::vector<unsigned char> &bytes) {
  static constexpr char digits[]="0123456789abcdef";
  std::string out;out.reserve(bytes.size()*2);
  for(auto byte:bytes){out.push_back(digits[byte>>4]);out.push_back(digits[byte&15]);}
  return out;
}

inline wb::J recover_initialized_x86_blob(const std::string &source) {
  using namespace wb;
  if(source.size()>1024*1024)throw std::runtime_error("Decompiler source exceeds recovery bound");
  std::regex assignment(R"(local_([0-9a-fA-F]+)\s*=\s*(?:\(code\))?(0x[0-9a-fA-F]+|[0-9]+)\s*;)");
  std::map<unsigned,unsigned char,std::greater<unsigned>> locals;
  for(std::sregex_iterator it(source.begin(),source.end(),assignment),end;it!=end;++it) {
    auto offset=static_cast<unsigned>(std::stoul((*it)[1].str(),nullptr,16));
    auto value=std::stoul((*it)[2].str(),nullptr,0);
    if(value>255)continue;
    locals[offset]=static_cast<unsigned char>(value);
  }
  if(locals.size()<16||locals.size()>4096)throw std::runtime_error("No bounded initialized local-byte blob found");
  std::vector<unsigned char> bytes;bytes.reserve(locals.size());
  unsigned previous=locals.begin()->first;
  for(const auto &[offset,value]:locals) {
    if(!bytes.empty()&&offset+1!=previous)break;
    bytes.push_back(value);previous=offset;
  }
  if(bytes.size()<16)throw std::runtime_error("Initialized local bytes are not contiguous");
  const auto original_sha=sha256_text(std::string(reinterpret_cast<const char*>(bytes.data()),bytes.size()));
  J stages=J::array();std::set<std::size_t> decoded;
  auto u32=[&](std::size_t at)->std::uint32_t {
    if(at+4>bytes.size())throw std::runtime_error("Decoder immediate outside blob");
    return std::uint32_t(bytes[at])|(std::uint32_t(bytes[at+1])<<8)|(std::uint32_t(bytes[at+2])<<16)|(std::uint32_t(bytes[at+3])<<24);
  };
  auto header=[&](std::size_t loop,std::size_t &start,std::size_t &size)->bool {
    const auto begin=loop>64?loop-64:0;
    for(std::size_t call=begin;call+19<=loop;++call)
      if(bytes[call]==0xe8&&u32(call+1)==0&&bytes[call+5]==0x8b&&bytes[call+6]==0x34&&bytes[call+7]==0x24&&
         bytes[call+8]==0x83&&bytes[call+9]==0xc6) {
        if(bytes[call+11]==0xb9)size=u32(call+12);
        else if(bytes[call+11]==0x89&&bytes[call+12]==0xf1&&bytes[call+13]==0x81&&bytes[call+14]==0xc1)size=u32(call+15);
        else continue;
        start=call+5+bytes[call+10];return start<=bytes.size()&&size<=bytes.size()-start;
      }
    return false;
  };
  auto pushed_key=[&](std::size_t loop,std::size_t key_size)->std::vector<unsigned char> {
    if(key_size<1||key_size>128)return {};
    for(std::size_t cursor=loop;cursor>=2;--cursor) {
      if(bytes[cursor-2]!=0x89||bytes[cursor-1]!=0xe3)continue;
      std::vector<std::array<unsigned char,4>> pushes;
      std::size_t at=cursor-2;
      while(at>=5&&bytes[at-5]==0x68) {
        pushes.push_back({bytes[at-4],bytes[at-3],bytes[at-2],bytes[at-1]});at-=5;
      }
      std::vector<unsigned char> key;
      for(auto it=pushes.begin();it!=pushes.end();++it)key.insert(key.end(),it->begin(),it->end());
      if(key.size()>=key_size){key.resize(key_size);return key;}
    }
    return {};
  };
  for(unsigned pass=0;pass<8;++pass) {
    bool changed=false;
    for(std::size_t at=0;at+12<bytes.size();++at) {
      if(decoded.contains(at))continue;
      std::size_t start=0,size=0;std::vector<unsigned char> key;
      if(at+6<bytes.size()&&bytes[at]==0x80&&bytes[at+1]==0x36&&bytes[at+3]==0x46&&bytes[at+4]==0x49) {
        if(!header(at,start,size))continue;
        key={bytes[at+2]};
      } else if(at+15<bytes.size()&&bytes[at]==0x81&&bytes[at+1]==0x36&&bytes[at+6]==0x83&&bytes[at+7]==0xc6&&bytes[at+8]==4) {
        if(!header(at,start,size))continue;
        key={bytes[at+2],bytes[at+3],bytes[at+4],bytes[at+5]};
      } else if(at+6<bytes.size()&&bytes[at]==0x8a&&bytes[at+1]==0x13&&bytes[at+2]==0x30&&bytes[at+3]==0x16&&bytes[at+4]==0x43&&bytes[at+5]==0x46) {
        if(!header(at,start,size))continue;
        std::size_t key_size=0;
        for(std::size_t p=at>32?at-32:0;p+3<at;++p)if(bytes[p]==0x83&&bytes[p+1]==0xc0)key_size=bytes[p+2];
        key=pushed_key(at,key_size);if(key.empty())continue;
      } else continue;
      for(std::size_t i=0;i<size;++i)bytes[start+i]^=key[i%key.size()];
      decoded.insert(at);stages.push_back({{"decoder_offset",at},{"output_offset",start},{"size",size},{"key_hex",reasoning_hex(key)}});
      changed=true;break;
    }
    if(!changed)break;
  }
  J strings=J::array();
  for(std::size_t mov=0;mov+1<bytes.size();++mov)if(bytes[mov]==0x89&&bytes[mov+1]==0xe1) {
    std::vector<std::array<unsigned char,4>> pushes;std::size_t at=mov;
    while(at>=5&&bytes[at-5]==0x68){pushes.push_back({bytes[at-4],bytes[at-3],bytes[at-2],bytes[at-1]});at-=5;}
    std::string value;for(auto &part:pushes)value.append(reinterpret_cast<const char*>(part.data()),4);
    if(mov+4<bytes.size()&&bytes[mov+2]==0xfe&&bytes[mov+3]==0x49&&bytes[mov+4]<value.size())
      --value[bytes[mov+4]];
    auto zero=value.find('\0');if(zero!=std::string::npos)value.resize(zero);
    while(!value.empty()&&static_cast<unsigned char>(value.back())<=32)value.pop_back();
    auto first=value.find_first_not_of(" \t\r\n");if(first!=std::string::npos)value.erase(0,first);
    if(value.size()>=3&&std::all_of(value.begin(),value.end(),[](unsigned char c){return c>=32&&c<127;}))
      strings.push_back({{"offset",mov},{"text",value}});
  }
  if(stages.empty()||strings.empty())throw std::runtime_error("No supported static decoder chain and output string found");
  const auto answer=strings.back().at("text").get<std::string>();
  return {{"schema","indago.static-recovery.v1"},{"input_size",locals.size()},{"contiguous_size",bytes.size()},
    {"input_sha256",original_sha},{"decoded_sha256",sha256_text(std::string(reinterpret_cast<const char*>(bytes.data()),bytes.size()))},
    {"stages",stages},{"strings",strings},{"answer",answer},{"state","static_output_recovered"},
    {"proof_scope","Bounded contiguous Ghidra local-byte initializers and recognized x86 XOR loops; final printable stack argument only; target was not executed"}};
}
inline wb::J reasoning_update(ProjectStore &store,const wb::J &inv,const wb::J &request) {
  using namespace wb;
  keys(request,{"operation","expected_revision","record"});
  auto state=inv.value("reasoning",reasoning_initial(inv));
  if(request.at("expected_revision")!=state.at("revision"))throw std::runtime_error("revision_conflict: reasoning changed");
  const auto op=request.at("operation").get<std::string>();
  const auto &r=request.at("record");
  auto string=[&](const J &obj,const char *key,std::size_t max=1024) {
    auto value=obj.at(key).get<std::string>();
    if(value.empty()||value.size()>max)throw std::runtime_error(std::string("Invalid reasoning field: ")+key);
    return value;
  };
  auto lookup=[&](const char *collection,const J &id)->J& {
    for(auto &item:state.at(collection))if(item.at("id")==id)return item;
    throw std::runtime_error("Unknown reasoning record");
  };
  auto sources=[&](const J &refs) {
    if(!refs.is_array()||refs.empty()||refs.size()>8)throw std::runtime_error("Require 1..8 native source references");
    J pins=J::array();
    for(const auto &ref:refs) {
      keys(ref,{"evidence_id","pointer"});
      auto page=harness_evidence_page(store,inv,{{"id",ref.at("evidence_id")},{"pointer",ref.at("pointer")},{"max_bytes",128},{"limit",1}});
      if(!page.value("source_verified",false))throw std::runtime_error("Unverified reasoning source");
      pins.push_back({{"evidence_id",page.at("id")},{"pointer",page.at("pointer")},{"raw_sha256",page.at("raw_sha256")},
        {"revision",page.at("revision")},{"native_status",page.at("native_status")}});
    }
    return pins;
  };
  auto full_source_text=[&](const J &pin) {
    Db db(store.root()/"indago-native.sqlite3");
    Q row(db,"SELECT record,sha FROM evidence WHERE project=? AND id=?");
    if(!row.s(1,inv.at("project").get<std::string>()).s(2,pin.at("evidence_id").get<std::string>()).row())
      throw std::runtime_error("Recovery evidence unavailable");
    const auto metadata=J::parse(row.text(0));const auto raw_sha=row.text(1);
    if(raw_sha!=pin.at("raw_sha256").get<std::string>()||metadata.at("raw_sha256").get<std::string>()!=raw_sha||
       !harness_contains_artifact(inv,metadata.at("artifact_sha256")))
      throw std::runtime_error("Recovery evidence pin or scope changed");
    const auto raw_path=object(store,raw_sha);
    if(fs::file_size(raw_path)>16*1024*1024)throw std::runtime_error("Recovery evidence exceeds 16 MiB bound");
    const auto bytes=read(raw_path,16*1024*1024);
    if(sha256_text(bytes)!=raw_sha)throw std::runtime_error("Recovery evidence integrity failure");
    const auto native=J::parse(bytes);
    const auto &value=native.at(J::json_pointer(pin.at("pointer").get<std::string>()));
    if(!value.is_string())throw std::runtime_error("Recovery source must be native text");
    return value.get<std::string>();
  };
  auto append=[&](const char *collection,J item) {
    if(state.at(collection).size()>=16)throw std::runtime_error("Reasoning collection limit is 16");
    item["id"]=std::string(collection)+"_"+std::to_string(state.at("revision").get<unsigned>()+1);
    state[collection].push_back(item);
  };
  if(op=="bind") {
    keys(r,{"id","description","sources"});
    auto &item=lookup("obligations",r.at("id"));
    item["description"]=string(r,"description");item["sources"]=sources(r.at("sources"));
    item["state"]="located_unproven";
  } else if(op=="hypothesize") {
    keys(r,{"obligation","statement","prediction","falsifier","sources"});
    lookup("obligations",r.at("obligation"));
    append("hypotheses",{{"obligation",r.at("obligation")},{"statement",string(r,"statement")},
      {"prediction",string(r,"prediction")},{"falsifier",string(r,"falsifier")},
      {"sources",sources(r.at("sources"))},{"state","untested"}});
  } else if(op=="revise_hypothesis") {
    keys(r,{"id","statement","prediction","falsifier","sources"});auto &item=lookup("hypotheses",r.at("id"));
    item={{"id",item.at("id")},{"obligation",item.at("obligation")},{"statement",string(r,"statement")},
      {"prediction",string(r,"prediction")},{"falsifier",string(r,"falsifier")},{"sources",sources(r.at("sources"))},{"state","untested"}};
  } else if(op=="check_hypothesis") {
    keys(r,{"id","checks"});auto &item=lookup("hypotheses",r.at("id"));
    const auto receipt=harness_validate(store,inv,r.at("checks"));
    item["check"]=receipt;item["state"]=receipt.at("status")=="passed"?"finite_check_passed":"finite_check_contradicted";
    item["semantic_entailment_checked"]=false;
  } else if(op=="candidate") {
    keys(r,{"obligation","hex","encoding","assumptions","sources"});
    lookup("obligations",r.at("obligation"));
    const auto bytes=string(r,"hex",1024);
    if(bytes.size()%2||bytes.find_first_not_of("0123456789abcdefABCDEF")!=bytes.npos)throw std::runtime_error("Candidate requires exact hex bytes");
    append("candidates",{{"obligation",r.at("obligation")},{"hex",bytes},{"encoding",string(r,"encoding",64)},
      {"assumptions",string(r,"assumptions")},{"sources",sources(r.at("sources"))},{"state","unvalidated"}});
  } else if(op=="derive") {
    keys(r,{"obligation","source","representation","spec","encoding","assumptions"});
    lookup("obligations",r.at("obligation"));
    const auto pinned=sources(J::array({r.at("source")}));
    auto page=harness_evidence_page(store,inv,{{"id",pinned[0].at("evidence_id")},{"pointer",pinned[0].at("pointer")},
      {"raw_sha256",pinned[0].at("raw_sha256")},{"max_bytes",512}});
    if(page.value("partial",true)||!page.contains("text"))throw std::runtime_error("Derivation requires complete bounded native text or hex");
    const auto derived=candidate_transform(page.at("text"),string(r,"representation",16),r.at("spec"));
    append("candidates",{{"obligation",r.at("obligation")},{"hex",derived.at("hex")},{"encoding",string(r,"encoding",64)},
      {"assumptions",string(r,"assumptions")},{"sources",pinned},{"derivation",derived},{"state","derived_unvalidated"}});
  } else if(op=="validate_transform_candidate") {
    keys(r,{"id","expected","representation","spec"});auto &item=lookup("candidates",r.at("id"));
    const auto pinned=sources(J::array({r.at("expected")}));
    auto page=harness_evidence_page(store,inv,{{"id",pinned[0].at("evidence_id")},{"pointer",pinned[0].at("pointer")},
      {"raw_sha256",pinned[0].at("raw_sha256")},{"max_bytes",512}});
    if(page.value("partial",true)||!page.contains("text"))throw std::runtime_error("Validation requires complete native expected bytes");
    const auto expected=candidate_transform(page.at("text"),string(r,"representation",16),{{"method","slice"}});
    const auto actual=candidate_transform(item.at("hex"),"hex",r.at("spec"));
    const bool matched=expected.at("hex")==actual.at("hex");
    item["check"]={{"actual",actual},{"expected",expected},{"sources",pinned},{"matched",matched},
      {"scope","finite byte transform under declared spec only; target implements this spec is unproven"}};
    item["state"]=matched?"finite_transform_matched":"finite_transform_contradicted";
    item["acceptance_proven"]=false;
  } else if(op=="validate_candidate") {
    keys(r,{"id","actual"});auto &item=lookup("candidates",r.at("id"));
    const auto pinned=sources(J::array({r.at("actual")}));
    const auto receipt=harness_validate(store,inv,J::array({{{"operation","equal"},{"operands",J::array({
      {{"evidence_id",pinned[0].at("evidence_id")},{"pointer",pinned[0].at("pointer")},{"raw_sha256",pinned[0].at("raw_sha256")}}})},{"expected",item.at("hex")}}}));
    item["check"]=receipt;item["state"]=receipt.at("status")=="passed"?"exact_representation_matched":"representation_contradicted";
    item["acceptance_proven"]=false;
  } else if(op=="experiment") {
    keys(r,{"hypothesis","candidate","prediction","observe","sources","pointer","expected"});
    lookup("hypotheses",r.at("hypothesis"));lookup("candidates",r.at("candidate"));
    const auto observe=string(r,"observe",64);
    if(!std::set<std::string>{"capture_reanalyze","branch_witness","io_result"}.contains(observe))throw std::runtime_error("Unsupported experiment recipe");
    if(!r.at("expected").is_primitive()||r.at("expected").dump().size()>512)throw std::runtime_error("Experiment expected must be a bounded scalar");
    append("experiments",{{"hypothesis",r.at("hypothesis")},{"candidate",r.at("candidate")},
      {"hypothesis_sha256",sha256_text(lookup("hypotheses",r.at("hypothesis")).dump())},
      {"candidate_sha256",sha256_text(lookup("candidates",r.at("candidate")).dump())},
      {"pointer",string(r,"pointer",1024)},{"expected",r.at("expected")},
      {"prediction",string(r,"prediction")},{"observe",observe},{"sources",sources(r.at("sources"))},
      {"state","awaiting_operator_execution"},{"execution_authorized",false}});
  } else if(op=="feedback") {
    keys(r,{"id","session","observation","sha256"});
    auto &item=lookup("experiments",r.at("id"));
    if(item.contains("receipt"))throw std::runtime_error("Experiment already has feedback; create a new experiment for another observation");
    if(item.at("hypothesis_sha256")!=sha256_text(lookup("hypotheses",item.at("hypothesis")).dump())||
       item.at("candidate_sha256")!=sha256_text(lookup("candidates",item.at("candidate")).dump()))
      throw std::runtime_error("Experiment hypothesis or candidate changed; preserve old experiment and plan a new one");
    const auto sessions=inv.value("runtime_observation_sessions",J::array());
    if(std::find(sessions.begin(),sessions.end(),r.at("session"))==sessions.end())
      throw std::runtime_error("capability_blocked: runtime session read grant required at investigation creation");
    if(!fs::exists(store.root()/"runtime.sqlite3"))throw std::runtime_error("Runtime evidence unavailable");
    auto session=runtime_command(store,{},{{"operation","status"},{"project",inv.at("project")},{"session",r.at("session")}});
    if(!harness_contains_artifact(inv,session.at("artifact_sha256")))throw std::runtime_error("Runtime session outside artifact scope");
    auto rows=runtime_command(store,{},{{"operation","observations"},{"project",inv.at("project")},{"session",r.at("session")},{"id",r.at("observation")},{"limit",1}}).at("observations");
    if(rows.empty()||rows[0].at("sha256")!=r.at("sha256"))throw std::runtime_error("Missing or changed runtime observation pin");
    const auto &observation=rows[0];
    const auto expected_kind=item.at("observe")=="branch_witness"?"witness_validation":item.at("observe")=="capture_reanalyze"?"runtime_feedback":"io_result";
    if(observation.at("kind")!=expected_kind)throw std::runtime_error("Observation kind does not match planned experiment");
    const auto value=observation.at(J::json_pointer(item.at("pointer").get<std::string>()));
    if(!value.is_primitive()||value.dump().size()>512)throw std::runtime_error("Feedback requires a complete bounded scalar");
    const bool matches=value==item.at("expected");
    item["receipt"]={{"session",r.at("session")},{"observation",r.at("observation")},{"sha256",r.at("sha256")},
      {"actual",value},{"expected",item.at("expected")},{"matches",matches},{"scope","this recorded execution only; candidate causality and entry-point acceptance not proven"}};
    item["state"]=matches?"observation_matches_prediction":"observation_contradicts_prediction";
    lookup("hypotheses",item.at("hypothesis"))["state"]=item.at("state");
  } else if(op=="recover_initialized_x86") {
    keys(r,{"source"});
    const auto pinned=sources(J::array({r.at("source")}));
    auto recovery=recover_initialized_x86_blob(full_source_text(pinned[0]));
    recovery["sources"]=pinned;
    append("recoveries",std::move(recovery));
  } else if(op=="solution") {
    keys(r,{"recovery","answer"});
    auto &recovery=lookup("recoveries",r.at("recovery"));
    const auto answer=string(r,"answer",512);
    if(recovery.at("state").get<std::string>()!="static_output_recovered"||answer!=recovery.at("answer").get<std::string>())
      throw std::runtime_error("Candidate answer does not match the deterministically recovered output");
    append("solutions",{{"recovery",recovery.at("id")},{"answer",answer},{"sources",recovery.at("sources")},
      {"state","verified_static_output"},{"validation","Exact match to the final printable stack argument after all recorded decoder stages"}});
    for(auto &obligation:state.at("obligations"))
      obligation["state"]=obligation.at("role")=="output"||obligation.at("role")=="candidate_validation"?
        "resolved_by_static_recovery":"not_applicable_to_output_recovery";
    state["verified_solve"]=true;
  } else throw std::runtime_error("Unknown reasoning operation");
  state["revision"]=state.at("revision").get<unsigned>()+1;
  if(state.dump().size()>49152)throw std::runtime_error("Reasoning ledger exceeds 48 KiB");
  return state;
}
}
