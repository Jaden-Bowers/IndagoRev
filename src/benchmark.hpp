#pragma once
#include "indago/airece.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <set>
#include <sstream>

// Operator-side benchmark commands. Intentionally not registered as harness tools.
namespace indago::benchmark {
using J=nlohmann::json;
inline std::string utf8_path(const fs::path &p) {const auto s=p.u8string();return {reinterpret_cast<const char*>(s.data()),s.size()};}
inline J load(const fs::path &p) {
  if(fs::file_size(p)>16*1024*1024)throw std::runtime_error("Benchmark JSON exceeds 16 MiB");
  std::ifstream in(p);J j;in>>j;return j;
}
inline std::string safe_relative(std::string s) {
  std::replace(s.begin(),s.end(),'\\','/');
  if(s.empty()||s.size()>1024||s.front()=='/'||s.find_first_of(":\"<>|?*")!=s.npos||
     std::any_of(s.begin(),s.end(),[](unsigned char c){return c<32;}))
    throw std::runtime_error("Unsafe artifact path");
  std::istringstream parts(s);std::string part;
  while(std::getline(parts,part,'/')) {
    std::string lower=part;std::transform(lower.begin(),lower.end(),lower.begin(),[](unsigned char c){return char(std::tolower(c));});
    const auto device=lower.substr(0,lower.find('.'));
    if(part.empty()||part=="."||part==".."||part.back()=='.'||part.back()==' '||
       lower==".git"||lower=="write-ups"||lower=="writeups"||lower=="solutions"||
       device=="con"||device=="prn"||device=="aux"||device=="nul"||
       (device.size()==4&&(device.starts_with("com")||device.starts_with("lpt"))&&device.back()>='0'&&device.back()<='9'))
      throw std::runtime_error("Forbidden artifact path component");
  }
  return s;
}
inline fs::path checked_path(const fs::path &root,const std::string &relative) {
  auto current=fs::absolute(root).lexically_normal();
  // Inspect ancestry too; never enter symlinked corpus/evaluator roots.
  for(auto p=current;!p.empty();) {
    if(fs::is_symlink(fs::symlink_status(p)))throw std::runtime_error("Symlink in benchmark root");
    auto parent=p.parent_path();if(parent==p)break;p=parent;
  }
  for(const auto &part:fs::u8path(safe_relative(relative))) {
    current/=part;
    if(fs::is_symlink(fs::symlink_status(current)))throw std::runtime_error("Symlink in benchmark path");
  }
  return current;
}
inline bool within(const fs::path &child,const fs::path &parent) {
  auto c=fs::weakly_canonical(child),p=fs::weakly_canonical(parent);
  auto rel=c.lexically_relative(p);
  return !rel.empty()&&!rel.is_absolute()&&*rel.begin()!="..";
}
inline void disjoint(const fs::path &a,const fs::path &b) {
  if(within(a,b)||within(b,a))throw std::runtime_error("Evaluator and analysis directories must be disjoint");
}
inline std::uint64_t bounded(const J &r,const char *key,std::uint64_t fallback,std::uint64_t maximum) {
  const auto v=r.value(key,fallback);if(!v||v>maximum)throw std::runtime_error(std::string("Invalid bound: ")+key);return v;
}
inline std::vector<J> members(const fs::path &seven,const fs::path &archive,const std::string &password,std::uint64_t ms) {
  NativeProcessOptions opt;opt.wall_time_ms=ms;opt.max_output_bytes=4*1024*1024;
  auto result=run_native_process(seven,{"l","-slt","-ba","-sccUTF-8","-p"+password,"--",utf8_path(archive)},opt);
  if(result.exit_code||result.timed_out||result.cancelled||result.truncated)throw std::runtime_error("Archive listing failed or exceeded bounds");
  std::vector<J> rows;J row=J::object();std::istringstream lines(result.output);std::string line;
  auto flush=[&]{if(!row.empty()){rows.push_back(row);row=J::object();if(rows.size()>10000)throw std::runtime_error("Archive member limit");}};
  while(std::getline(lines,line)) {
    if(!line.empty()&&line.back()=='\r')line.pop_back();
    if(line.empty()){flush();continue;}
    auto sep=line.find(" = ");if(sep!=line.npos)row[line.substr(0,sep)]=line.substr(sep+3);
  }
  flush();return rows;
}
inline std::string format_hint(const std::string &name,const std::string &bytes={}) {
  if(bytes.starts_with("MZ"))return "PE_candidate";
  if(bytes.size()>4&&bytes.substr(0,4)==std::string("\x7f" "ELF",4))return "ELF_candidate";
  const auto dot=name.find_last_of('.');auto ext=dot==name.npos?std::string():name.substr(dot);
  std::transform(ext.begin(),ext.end(),ext.begin(),[](unsigned char c){return char(std::tolower(c));});
  if(ext==".exe"||ext==".dll"||ext==".sys")return "native_or_managed_PE_candidate";
  if(ext==".apk")return "Android_archive_candidate";
  if(ext==".pcap"||ext==".pcapng")return "packet_capture_candidate";
  if(ext==".py"||ext==".js"||ext==".html"||ext==".ps1")return "script_candidate";
  if(ext==".zip"||ext==".7z"||ext==".tar"||ext==".gz")return "nested_archive";
  return "unknown";
}
inline J freeze(const J &r) {
  const auto seed=load(r.at("manifest").get<std::string>());
  const fs::path root=r.at("corpus_root").get<std::string>(),seven=r.at("archive_tool").get<std::string>();
  const auto timeout=bounded(r,"wall_ms",240000,540000),maxbytes=bounded(r,"hash_bytes",1024ULL*1024*1024,4ULL*1024*1024*1024);
  auto start=std::chrono::steady_clock::now();std::uint64_t hashed=0;J out=seed;
  std::map<std::string,J> cache;std::set<std::string> ids;
  for(auto &challenge:out.at("challenges")) {
    if(!ids.insert(challenge.at("id")).second)throw std::runtime_error("Duplicate challenge identity");
    const int year=challenge.at("year");if(year<2014||year>2024)throw std::runtime_error("Held-out year excluded");
    challenge["status"]="available";challenge["artifacts"]=J::array();
    for(const auto &input:challenge.at("inputs")) {
      const std::string path=input.at("path"),password=input.at("password");
      if(!cache.contains(path)) {
        J entry={{"path",safe_relative(path)},{"status","unavailable"}};
        try {
          const auto file=checked_path(root,path);
          if(!fs::is_regular_file(file))throw std::runtime_error("Payload absent from local corpus");
          const auto size=fs::file_size(file);if(size>maxbytes-hashed)throw std::runtime_error("Catalogue hash budget exceeded");
          const auto elapsed=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count());
          if(elapsed>=timeout)throw std::runtime_error("Catalogue wall budget exceeded");
          entry["size"]=size;entry["sha256"]=sha256_file(file);hashed+=size;
          entry["members"]=members(seven,file,password,std::min<std::uint64_t>(30000,timeout-elapsed));
          if(sha256_file(file)!=entry["sha256"].get<std::string>())throw std::runtime_error("Container changed during listing");
          entry["status"]="available";
        }catch(const std::exception &e){entry["diagnostic"]=e.what();}
        cache[path]=entry;
      }
      auto entry=cache.at(path);const std::string prefix=input.value("member_prefix",std::string());
      if(entry.at("status")=="available") {
        J selected=J::array();std::set<std::string> names;
        try {
          for(const auto &member:entry.at("members")) {
            std::string name=member.value("Path",std::string());std::replace(name.begin(),name.end(),'\\','/');
            if(!prefix.empty()&&!name.starts_with(prefix))continue;
            if(member.value("Folder",std::string())=="+"||member.value("Attributes",std::string()).find('D')!=std::string::npos)continue;
            name=safe_relative(name);auto lower=name;std::transform(lower.begin(),lower.end(),lower.begin(),[](unsigned char c){return char(std::tolower(c));});
            if(!names.insert(lower).second)throw std::runtime_error("Duplicate/case-colliding member");
            if(member.contains("Symbolic Link")||member.contains("Hard Link"))throw std::runtime_error("Archive links forbidden");
            selected.push_back({{"path",name},{"size",std::stoull(member.at("Size").get<std::string>())},
              {"sha256",nullptr},{"hash_status","pending_materialization"},{"format_hint",format_hint(name)},
              {"parent_sha256",entry.at("sha256")}});
          }
          if(selected.empty())throw std::runtime_error("No challenge members found");
          entry["members"]=selected;
        }catch(const std::exception &e){entry["status"]="unsupported";entry["diagnostic"]=e.what();entry.erase("members");}
      }
      if(entry.at("status")!="available")challenge["status"]=entry.at("status");
      challenge["artifacts"].push_back(entry);
    }
    J hints=J::array();
    for(const auto &a:challenge.at("artifacts"))for(const auto &m:a.value("members",J::array()))
      if(m.contains("format_hint")&&m.at("format_hint")!="unknown"&&m.at("format_hint")!="nested_archive")
        hints.push_back({{"container",a.at("path")},{"member",m.at("path")},{"kind",m.at("format_hint")}});
    challenge["environment"]={{"status","needs_assessment"},{"entry_point_candidates",hints},{"dependencies",J::array()},
      {"execution_authorized",false}};
    challenge["verifier"]={{"status","unconfigured"},{"location","operator evaluator store only"}};
  }
  out["schema"]="indago.benchmark-catalogue.v1";out["denominator"]=out.at("challenges").size();
  out["hash_bytes"]=hashed;out["catalogue_sha256"]=sha256_text(out.dump());return out;
}
inline void verify_catalogue(J catalog) {
  const auto hash=catalog.at("catalogue_sha256").get<std::string>();catalog.erase("catalogue_sha256");
  if(sha256_text(catalog.dump())!=hash)throw std::runtime_error("Catalogue integrity failure");
  if(catalog.at("denominator")!=catalog.at("challenges").size())throw std::runtime_error("Denominator mismatch");
}
inline J prepare(const J &r) {
  const auto catalog=load(r.at("catalogue").get<std::string>());verify_catalogue(catalog);
  const fs::path root=r.at("corpus_root").get<std::string>(),dest=fs::absolute(r.at("destination").get<std::string>()),seven=r.at("archive_tool").get<std::string>();
  disjoint(root,dest);if(fs::exists(dest))throw std::runtime_error("Preparation requires a fresh destination");
  checked_path(dest.parent_path(),utf8_path(dest.filename()));
  const auto cap=bounded(r,"max_bytes",64*1024*1024,512*1024*1024),ms=bounded(r,"wall_ms",60000,540000);
  const auto floor=r.value("minimum_free_bytes",20ULL*1024*1024*1024);
  const auto free=fs::space(dest.parent_path()).available;
  if(floor>free||cap>free-floor)throw std::runtime_error("Insufficient preparation storage");
  J selected;for(const auto &c:catalog.at("challenges"))if(c.at("id")==r.at("challenge"))selected=c;
  if(selected.is_null()||selected.at("status")!="available")throw std::runtime_error("Challenge unavailable or unsupported");
  std::uint64_t total=0;std::size_t count=0;
  for(const auto &a:selected.at("artifacts"))for(const auto &m:a.at("members")) {
    const auto size=m.at("size").get<std::uint64_t>();if(size>cap-total)throw std::runtime_error("Expansion byte budget exceeded");total+=size;
    if(++count>2048)throw std::runtime_error("Expansion member budget exceeded");
  }
  fs::create_directory(dest);auto start=std::chrono::steady_clock::now();J receipt={{"schema","indago.benchmark-inputs.v1"},{"challenge",selected.at("id")},
    {"catalogue_sha256",catalog.at("catalogue_sha256")},{"execution_authorized",false},{"artifacts",J::array()},{"status","partial"}};
  try {
    for(std::size_t n=0;n<selected.at("artifacts").size();++n) {
      const auto &a=selected.at("artifacts")[n];const auto archive=checked_path(root,a.at("path"));
      if(sha256_file(archive)!=a.at("sha256").get<std::string>())throw std::runtime_error("Container hash mismatch");
      const auto password=selected.at("inputs")[n].at("password").get<std::string>();
      for(const auto &m:a.at("members")) {
        const auto elapsed=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-start).count());
        if(elapsed>=ms)throw std::runtime_error("Preparation deadline");
        NativeProcessOptions opt;opt.wall_time_ms=ms-elapsed;opt.max_output_bytes=m.at("size").get<std::size_t>()+1;
        // Never let the archiver write target-controlled paths. Extract exactly one literal member to a bounded pipe.
        auto result=run_native_process(seven,{"x","-so","-spd","-p"+password,"--",utf8_path(archive),m.at("path")},opt);
        if(result.exit_code||result.truncated||result.timed_out||result.cancelled||result.output.size()!=m.at("size"))throw std::runtime_error("Member extraction failed or exceeded bound");
        const auto sha=sha256_text(result.output);const auto relative="inputs/"+std::to_string(n)+"/"+m.at("path").get<std::string>();
        const auto output=checked_path(dest,relative);fs::create_directories(output.parent_path());atomic_write(output,result.output);
        receipt["artifacts"].push_back({{"path",relative},{"sha256",sha},{"size",result.output.size()},
          {"parent_sha256",a.at("sha256")},{"member",m.at("path")},{"format_hint",format_hint(m.at("path"),result.output)}});
      }
      if(sha256_file(archive)!=a.at("sha256").get<std::string>())throw std::runtime_error("Container changed during extraction");
    }
    receipt["status"]="completed";
  }catch(const std::exception &e){receipt["diagnostic"]=e.what();}
  receipt["input_manifest_sha256"]=sha256_text(receipt.dump());atomic_write(dest/"input-manifest.json",receipt.dump(2));return receipt;
}
inline J grade(const J &r) {
  const fs::path evaluator=r.at("evaluator_root").get<std::string>(),analysis=r.at("analysis_root").get<std::string>();disjoint(evaluator,analysis);
  const auto catalog=load(r.at("catalogue").get<std::string>());verify_catalogue(catalog);
  const auto submission=load(checked_path(analysis,r.at("submission")));
  const auto spec=load(checked_path(evaluator,r.at("verifier")));
  bool found=false;for(const auto &c:catalog.at("challenges"))if(c.at("id")==submission.at("challenge"))found=true;
  if(!found||submission.at("catalogue_sha256")!=catalog.at("catalogue_sha256")||spec.at("catalogue_sha256")!=catalog.at("catalogue_sha256")||spec.at("challenge")!=submission.at("challenge"))throw std::runtime_error("Verifier/submission scope mismatch");
  if(spec.at("kind")!="exact_utf8_sha256"||spec.at("authority")!="independent_operator")throw std::runtime_error("Unsupported or non-independent verifier");
  const auto answer=submission.value("answer",std::string());if(answer.size()>4096)throw std::runtime_error("Answer exceeds bound");
  const auto solver=checked_path(analysis,submission.at("solver_path"));
  if(fs::file_size(solver)>1024*1024||sha256_file(solver)!=submission.at("solver_sha256").get<std::string>())throw std::runtime_error("Solver artifact integrity failure");
  const auto inputs=load(checked_path(analysis,"input-manifest.json"));auto check=inputs;check.erase("input_manifest_sha256");
  if(inputs.at("status")!="completed"||sha256_text(check.dump())!=inputs.at("input_manifest_sha256").get<std::string>()||inputs.at("challenge")!=submission.at("challenge")||inputs.at("catalogue_sha256")!=catalog.at("catalogue_sha256"))throw std::runtime_error("Prepared inputs invalid");
  for(const auto &a:inputs.at("artifacts"))if(sha256_file(checked_path(analysis,a.at("path")))!=a.at("sha256").get<std::string>())throw std::runtime_error("Prepared input changed");
  const auto attempt=submission.at("attempt").get<unsigned>();if(!attempt||attempt>1000)throw std::runtime_error("Attempt must be 1..1000");
  const auto &run=submission.at("run");
  for(const auto *field:{"model","profile_sha256","budget","usage"})if(!run.contains(field))throw std::runtime_error("Missing run declaration");
  const auto outcome=submission.value("outcome",std::string("answer"));
  if(!std::set<std::string>{"answer","timeout","unsupported","environment_missing","budget_exhausted","analysis_failed","cancelled","no_answer"}.contains(outcome))throw std::runtime_error("Unknown attempt outcome");
  const bool passed=outcome=="answer"&&sha256_text(answer)==spec.at("answer_sha256").get<std::string>();
  return {{"schema","indago.benchmark-grade.v1"},{"challenge",submission.at("challenge")},{"catalogue_sha256",catalog.at("catalogue_sha256")},
    {"attempt",attempt},{"status",passed?"passed":"failed"},{"verified_solve",passed},{"verification_kind","exact_utf8_sha256"},
    {"failure_category",passed?"none":outcome=="answer"?"wrong_answer":outcome},
    {"behavior_verified",false},{"solver_executed",false},{"solver_sha256",submission.at("solver_sha256")},
    {"submission_sha256",sha256_text(submission.dump())},{"verifier_sha256",sha256_text(spec.dump())},{"run",run},
    {"limitations",J::array({"Independent operator supplies expected-answer digest; no expected answer is exposed to the harness", "Fixed-answer grading does not prove solver correctness, behavior, clean-room execution, or absence of model training contamination"})}};
}
inline J action(const std::string &op,const J &r) {
  if(op=="freeze")return freeze(r);
  if(op=="prepare")return prepare(r);
  if(op=="grade")return grade(r);
  if(op=="score") {
    const auto catalog=load(r.at("catalogue").get<std::string>());verify_catalogue(catalog);J rows=J::array();unsigned passed=0,first=0;
    if(r.at("attempts").size()>1000)throw std::runtime_error("Score attempt bound");
    std::map<std::string,std::set<unsigned>> attempts;std::set<std::string> successes,firsts;
    for(auto request:r.at("attempts")) {
      request["catalogue"]=r.at("catalogue");request["evaluator_root"]=r.at("evaluator_root");
      auto result=grade(request);const std::string id=result.at("challenge");const unsigned n=result.at("attempt");
      if(!attempts[id].insert(n).second)throw std::runtime_error("Duplicate challenge attempt");
      if(result.at("verified_solve")==true){successes.insert(id);if(n==1)firsts.insert(id);}rows.push_back(result);
    }
    J outcomes=J::array();
    for(const auto &c:catalog.at("challenges")) {
      const std::string id=c.at("id");auto status=c.at("status").get<std::string>();
      if(successes.contains(id)){status="passed";++passed;}else if(attempts.contains(id))status="failed";else if(status=="available")status="not_run";
      if(firsts.contains(id))++first;
      outcomes.push_back({{"challenge",id},{"status",status},{"attempts",attempts[id].size()}});
    }
    return {{"schema","indago.benchmark-score.v1"},{"denominator",catalog.at("denominator")},{"passed",passed},{"pass_at_1_count",first},
      {"all_solved",passed==catalog.at("denominator").get<unsigned>()},{"attempts",rows},{"outcomes",outcomes},
      {"limitation","Score covers submitted attempts; operator must retain all attempts and enforce the declared clean-run protocol"}};
  }
  throw std::runtime_error("Unknown benchmark operation");
}
}
