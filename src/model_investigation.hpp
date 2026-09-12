#pragma once
#include "workbench_db.hpp"
#include "harness_evidence_read.hpp"
#include <algorithm>
#include <functional>
#include <set>

namespace indago {
// Durable model assessments are never semantic proofs. The existing publication
// gate alone decides whether an answer is supported by native evidence.
inline wb::J investigation_state() {
  using J=wb::J;J goals=J::array();
  for(const auto *name:{"input","transformation","constraints","acceptance","output"})
    goals.push_back({{"id",name},{"question",std::string("Establish ")+name},
      {"status","open"},{"depends_on",J::array()},{"priority",5},{"summary",""}});
  return {{"schema","indago.investigation-state.v1"},{"revision",0},{"planned",false},
    {"goals",goals},{"tasks",J::array()},{"summaries",J::array()},
    {"hypotheses",J::array()},{"observations",J::array()},{"values",J::array()},{"turns",J::array()},
    {"query_counts",J::object()},{"seen",J::object()},{"idle_steps",0},
    {"active_task",nullptr},{"last_generation",-1}};
}
// Retain complete exchanges according to the pinned context budget, not a
// fixed number of turns. One whole latest exchange is kept for explicit failure
// rather than truncating opaque provider reasoning if even it cannot fit.
inline wb::J investigation_history(wb::J history,std::size_t context_bytes,
                                   std::size_t output_tokens,std::size_t prefix_bytes,bool compact) {
  const auto reserve=output_tokens+prefix_bytes+8192;
  auto available=context_bytes>reserve?context_bytes-reserve:0;
  if(compact)available/=2;
  available=std::min(available,std::size_t(1024*1024));
  while(history.size()>1&&history.dump().size()>available)history.erase(history.begin());
  return history;
}
inline wb::J investigation_page(const wb::J &state,const wb::J &r) {
  using namespace wb;keys(r,{"collection","offset","limit"});
  const auto name=r.at("collection").get<std::string>();
  if(!std::set<std::string>{"goals","tasks","summaries","hypotheses","observations","facts","values","turns"}.contains(name))
    throw std::runtime_error("unknown investigation collection");
  const auto offset=bound(r,"offset",0,4096),limit=bound(r,"limit",8,32);
  const auto &all=state.at(name);if(offset>all.size()||!limit)throw std::runtime_error("invalid state page");
  J records=J::array();auto cursor=offset;
  while(cursor<all.size()&&records.size()<limit) {
    records.push_back(all[cursor]);
    if(records.dump().size()>12000){records.erase(records.end()-1);break;}
    ++cursor;
  }
  return {{"collection",name},{"revision",state.at("revision")},{"records",records},
    {"total",all.size()},{"offset",offset},{"next_offset",cursor<all.size()?J(cursor):J(nullptr)},
    {"trust","Model assessments and historical observations; re-read native evidence before proof publication"}};
}
inline void investigation_plan(wb::J &state,const wb::J &r) {
  using namespace wb;keys(r,{"expected_revision","collection","records","active_task"});
  if(r.at("expected_revision")!=state.at("revision"))throw std::runtime_error("investigation state revision conflict");
  auto next=state;
  const auto name=r.at("collection").get<std::string>();
  if(!std::set<std::string>{"goals","tasks","summaries","hypotheses"}.contains(name))throw std::runtime_error("collection is not editable");
  if(!r.at("records").is_array()||r.at("records").size()>32)throw std::runtime_error("plan patch exceeds 32 records");
  for(auto record:r.at("records")) {
    keys(record,{"id","question","status","depends_on","priority","summary","goal","backend","operation","address","evidence_ids"});
    identifier(record.at("id").get<std::string>());
    if(record.dump().size()>8192)throw std::runtime_error("plan record exceeds 8 KiB; split into subsystems");
    if(!record.at("summary").is_string()||!record.at("question").is_string())throw std::runtime_error("plan text must be strings");
    const auto status=record.at("status").get<std::string>();
    if(!std::set<std::string>{"open","supported","contradicted","blocked","superseded"}.contains(status))throw std::runtime_error("invalid assessment status");
    const auto priority=record.value("priority",5);if(priority<0||priority>10)throw std::runtime_error("priority must be 0..10");
    if(!record.contains("depends_on"))record["depends_on"]=J::array();
    if(!record.at("depends_on").is_array()||record.at("depends_on").size()>64)throw std::runtime_error("invalid dependencies");
    for(const auto &dependency:record.at("depends_on"))identifier(dependency.get<std::string>());
    record["priority"]=priority;record["assessment_only"]=true;
    auto &rows=next[name];auto found=std::find_if(rows.begin(),rows.end(),[&](const J &v){return v.at("id")==record.at("id");});
    if(found==rows.end()) {if(rows.size()>=1024)throw std::runtime_error("collection storage budget exhausted");rows.push_back(record);}
    else *found=record;
  }
  // Dependencies are within a collection, allowing deterministic DAG scheduling.
  const auto &rows=next.at(name);std::set<std::string> visiting,visited;
  std::function<void(const std::string &)> visit=[&](const std::string &id) {
    if(visited.contains(id))return;
    if(!visiting.insert(id).second)throw std::runtime_error("cyclic investigation dependency");
    auto it=std::find_if(rows.begin(),rows.end(),[&](const J &v){return v.at("id")==id;});
    if(it==rows.end())throw std::runtime_error("unknown investigation dependency");
    for(const auto &dep:it->at("depends_on"))visit(dep.get<std::string>());
    visiting.erase(id);visited.insert(id);
  };
  for(const auto &row:rows)visit(row.at("id").get<std::string>());
  if(r.contains("active_task")) {
    const auto active=r.at("active_task").get<std::string>();
    if(std::none_of(next.at("tasks").begin(),next.at("tasks").end(),[&](const J &v){return v.at("id")==active;}) &&
       std::none_of(next.at("goals").begin(),next.at("goals").end(),[&](const J &v){return v.at("id")==active;}))throw std::runtime_error("active_task must name a saved task or goal");
    next["active_task"]=active;
  }
  next["planned"]=true;
  next["revision"]=state.at("revision").get<unsigned>()+1;
  if(next.dump().size()>2*1024*1024)throw std::runtime_error("investigation state exceeds 2 MiB; summarize before continuing");
  state=std::move(next);
}
inline wb::J investigation_queue(const wb::J &state) {
  using J=wb::J;J queue=J::array();
  const auto &tasks=state.at("tasks").empty()?state.at("goals"):state.at("tasks");
  for(auto task:tasks) {
    if(task.at("status")!="open")continue;
    bool ready=true;
    for(const auto &dependency:task.at("depends_on")) {
      const auto &all=tasks;auto it=std::find_if(all.begin(),all.end(),[&](const J &v){return v.at("id")==dependency;});
      if(it==all.end()||it->at("status")!="supported")ready=false;
    }
    if(!ready)continue;
    unsigned dependents=0;for(const auto &other:tasks)
      if(other.at("status")=="open"&&std::find(other.at("depends_on").begin(),other.at("depends_on").end(),task.at("id"))!=other.at("depends_on").end())++dependents;
    task["score"]=task.value("priority",5)+std::min(dependents,10u);
    if(task.at("summary").get<std::string>().size()>512) {
      auto text=task.at("summary").get<std::string>();std::size_t end=512;
      while(end&&(static_cast<unsigned char>(text[end])&0xc0)==0x80)--end;
      task["summary"]=text.substr(0,end);
      task["summary_omitted"]=true;
    }
    queue.push_back(task);
  }
  std::stable_sort(queue.begin(),queue.end(),[](const J &a,const J &b){return a.at("score")>b.at("score");});
  const auto total=queue.size();while(queue.size()>8)queue.erase(queue.end()-1);
  return {{"ready_total",total},{"records",queue},{"policy","Unresolved data dependencies and model relevance; assessments are not proofs"}};
}
// Page sizes express upper bounds. Narrow oversized model requests before the
// strict reader validates scope/pointers; never increase an operator bound.
inline void investigation_bound_page(wb::J &decision) {
  if(decision.at("kind")!="retrieve")return;
  auto &payload=decision.at("payload");
  if(!payload.contains("request")||!payload.at("request").is_object())return;
  auto &request=payload.at("request");
  const auto family=payload.value("family",std::string());
  if(payload.value("operation",std::string())!="read")return;
  auto narrow=[&](const char *key,std::uint64_t ceiling) {
    if(request.contains(key)&&request.at(key).is_number_unsigned()&&request.at(key).get<std::uint64_t>()>ceiling)
      request[key]=ceiling;
    else if(request.contains(key)&&request.at(key).is_number_integer()&&request.at(key).get<std::int64_t>()>static_cast<std::int64_t>(ceiling))
      request[key]=ceiling;
  };
  if(family=="evidence") {narrow("limit",16);narrow("max_bytes",2048);if(!request.contains("projection"))request["projection"]="scalars";}
  if(family=="artifact")narrow("max_bytes",1024);
}
inline std::string investigation_query_key(const wb::J &decision) {
  auto request=decision.at("payload");
  // Invalid model proposals still need durable failure accounting. Preserve their
  // whole payload as the fingerprint instead of dereferencing a missing request.
  if(decision.at("kind")=="analyze"&&request.is_object()&&
     request.contains("request")&&request.at("request").is_object()) {
    request=request.at("request");request.erase("budget");
  }
  return sha256_text(wb::J{{"kind",decision.at("kind")},{"request",request}}.dump());
}
inline void investigation_guard(const wb::J &state,const wb::J &decision) {
  const auto kind=decision.at("kind");if(kind!="analyze"&&kind!="retrieve")return;
  if(state.at("query_counts").value(investigation_query_key(decision),0)>=2)
    throw std::runtime_error("Repeated query exhausted its progress allowance. Change address, evidence page, dependency, or backend; budget changes alone are not a new approach.");
}
inline void investigation_observe(wb::J &state,const wb::J &decision,const wb::J &feedback,int generation, const std::string &native_fingerprint={}) {
  using J=wb::J;
  if(state.at("last_generation")==generation)return; // resume-safe accounting
  state["last_generation"]=generation;
  const auto kind=decision.at("kind").get<std::string>();
  const bool query=kind=="analyze"||kind=="retrieve";
  bool novel=false;
  if(query) {
    const auto key=investigation_query_key(decision);
    const auto count=state["query_counts"].value(key,0);
    const auto fingerprint=native_fingerprint.empty()?sha256_text(J{{"raw_sha256",feedback.value("raw_sha256",J(nullptr))},{"pointer",feedback.value("pointer",J(nullptr))},{"offset",feedback.value("offset",J(nullptr))}}.dump()):native_fingerprint;
    const bool usable=!feedback.contains("error")&&!feedback.value("omitted",false)&&
      (feedback.value("source_verified",false)||!native_fingerprint.empty()) &&
      !std::set<std::string>{"failed","unsupported","not_found","timed_out","timeout","environment_unavailable"}.contains(feedback.value("status",std::string()));
    auto &seen=state["seen"][key];if(seen.is_null())seen=J::array();
    novel=usable&&std::find(seen.begin(),seen.end(),fingerprint)==seen.end();
    if(novel)seen.push_back(fingerprint);
    state["query_counts"][key]=novel?0:count+1;
  }
  const bool contradicted=feedback.value("status",std::string())=="contradicted";
  if(contradicted) {
    for(auto &hypothesis:state["hypotheses"])if(hypothesis.at("status")=="supported") {
      hypothesis["status"]="open";
    }
    for(auto &task:state["tasks"])if(task.at("status")=="supported")task["status"]="open";
    for(auto &goal:state["goals"])if(goal.at("status")=="supported")goal["status"]="open";
    novel=true;
  }
  state["idle_steps"]=novel?0:state.at("idle_steps").get<unsigned>()+1;
  if(kind!="state"&&kind!="plan") {
    if(state["observations"].size()>=4096)throw std::runtime_error("observation storage budget exhausted");
    J record{{"generation",generation},{"kind",kind},{"decision_sha256",sha256_text(decision.dump())},
      {"feedback_sha256",sha256_text(feedback.dump())},{"novel_evidence",novel},{"contradicted",contradicted}};
    for(const auto *key:{"id","evidence_ids","raw_sha256","pointer","offset","status","error"})if(feedback.contains(key))record[key]=feedback.at(key);
    if(record.dump().size()>8192) {record.erase("evidence_ids");record["details_omitted"]=true;}
    if(state.dump().size()+record.dump().size()>2*1024*1024)throw std::runtime_error("investigation storage budget exhausted");
    state["observations"].push_back(record);
  }
  if(contradicted)state["revision"]=state.at("revision").get<unsigned>()+1;
}

// Preview inventory, not selected function analysis. All addresses remain native
// data and every omitted field can be re-read using the retained source pin.
inline wb::J investigation_preview(const ProjectStore &store,const wb::J &inv,const std::string &id) {
  using namespace wb;
  const auto root=harness_evidence_page(store,inv,{{"id",id},{"limit",16}});
  if(!root.value("source_verified",false))return root;
  const auto sha=root.at("raw_sha256").get<std::string>();
  const auto bytes=read(object(store,sha),16*1024*1024);
  if(sha256_text(bytes)!=sha)throw std::runtime_error("preview source integrity failure");
  const auto native=J::parse(bytes);
  J preview{{"evidence_id",id},{"raw_sha256",sha},{"source_verified",true},
    {"native_status",root.at("native_status")},{"revision",root.at("revision")},
    {"root",root},{"collections",J::array()},{"projection_only",true}};
  if(native.contains("program")&&native.at("program").dump().size()<=2048)
    preview["program"]={{"pointer","/program"},{"value",native.at("program")}};
  for(const auto *name:{"functions","strings","imports","exports","instructions","assembly"}) {
    if(!native.contains(name)||!native.at(name).is_array())continue;
    const auto &rows=native.at(name);J items=J::array();std::size_t at=0;
    for(;at<rows.size()&&at<12;++at) {
      J value=J::object();const auto &row=rows[at];
      if(row.is_object())for(auto it=row.begin();it!=row.end();++it)
        if(it.value().is_primitive()&&it.value().dump().size()<=512)value[it.key()]=it.value();
      if(row.is_primitive()&&row.dump().size()<=512)value=row;
      J entry{{"pointer","/"+std::string(name)+"/"+std::to_string(at)},{"value",value},{"omitted_fields",value!=row}};
      if(preview.dump().size()+items.dump().size()+entry.dump().size()>10000)break;
      items.push_back(entry);
    }
    preview["collections"].push_back({{"name",name},{"items",items},{"total",rows.size()},{"next_offset",at<rows.size()?J(at):J(nullptr)}});
  }
  if(native.contains("decompilation")&&native.at("decompilation").is_object()&&native.at("decompilation").contains("decompiled_c"))
    preview["decompilation"]=harness_evidence_page(store,inv,{{"id",id},{"pointer","/decompilation/decompiled_c"},{"max_bytes",2048}});
  return preview;
}
}
