#include "indago/service.hpp"
#include "indago/contracts.hpp"
#include "indago/xair.hpp"
#include "indago/runtime.hpp"
#include "indago/replay.hpp"
#include "indago/workbench.hpp"
#include "indago/harness.hpp"
#include "indago/lief.hpp"
#include "indago/wireshark.hpp"
#include "benchmark.hpp"
#include <charconv>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif

namespace {
using Json=nlohmann::json;
struct Args {
    std::vector<std::string> positional;
    std::map<std::string,std::string> options;
    Args(int argc,char** argv) {
        for(int i=1;i<argc;++i) {
            std::string arg=argv[i];
            if(arg.starts_with("--")) {
                if(arg=="--json") continue;
                if(arg=="--help"){positional={"help"};continue;}
                static const std::set<std::string> known{"workspace","project","name","file","id","artifact","offset","limit","backend","operation","address","view","timeout-ms","max-output-bytes","max-memory-bytes","max-items","target-id","request","profile","from","to","source","sink","target","function","mode","max-states","max-queries","max-paths","function-depth","symbolic-timeout-ms","max-taint-bytes","max-symbolic-bytes","kind","anchor","revision","search","subject","predicate","history","idempotency-key"};
                static const std::set<std::string> runtime_options{"session","pid","thread","size","static-address","rva","module","max-steps","max-events","lifetime-ms","observation","wait","signal","cwd","recipe","trace-bytes"};
                static const std::set<std::string> backend_options{"cursor","collection","expected-revision","scan-limit","format"};
                const bool worker_option = !positional.empty() && positional[0]=="__workbench" && (arg=="--action" || arg=="--runner");
                if(!known.contains(arg.substr(2))&&!runtime_options.contains(arg.substr(2))&&!backend_options.contains(arg.substr(2))&&!worker_option)throw std::runtime_error("unknown option: "+arg);
                if(i+1>=argc || std::string_view(argv[i+1]).starts_with("--")) throw std::runtime_error("missing value for "+arg);
                if(options.contains(arg.substr(2))) throw std::runtime_error("duplicate option: "+arg);
                options[arg.substr(2)]=argv[++i];
            } else positional.push_back(arg);
        }
    }
    std::string get(const std::string& key,std::string fallback={}) const {auto it=options.find(key);return it==options.end()?fallback:it->second;}
    std::uint64_t number(const std::string& key,std::uint64_t fallback) const {
        const auto text=get(key);if(text.empty())return fallback;std::uint64_t n{};auto p=std::from_chars(text.data(),text.data()+text.size(),n);if(p.ec!=std::errc{}||p.ptr!=text.data()+text.size())throw std::runtime_error("invalid integer: "+key);return n;
    }
};
Json read_json(const std::string& path) {if(indago::fs::file_size(path)>1024*1024)throw std::runtime_error("request file exceeds 1 MiB limit");std::ifstream input(path);if(!input)throw std::runtime_error("cannot open request file");Json value;input>>value;return value;}
void spawn(const indago::fs::path& executable,const indago::fs::path& workspace,const std::string& project,const std::string& job) {
#ifdef _WIN32
    auto quote=[](const std::wstring& text){std::wstring result=L"\"";unsigned slashes=0;for(auto ch:text){if(ch==L'\\'){++slashes;continue;}if(ch==L'\"'){result.append(slashes*2+1,L'\\');result+=ch;}else {result.append(slashes,L'\\');result+=ch;}slashes=0;}result.append(slashes*2,L'\\');return result+L"\"";};
    std::wstring command=quote(executable.wstring())+L" --workspace "+quote(workspace.wstring())+L" __worker --project "+quote(indago::fs::path(project).wstring())+L" --id "+quote(indago::fs::path(job).wstring());
    STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION info{};
    if(!CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW|CREATE_NEW_PROCESS_GROUP,nullptr,nullptr,&startup,&info))throw std::runtime_error("cannot submit native worker");
    CloseHandle(info.hThread);CloseHandle(info.hProcess);
#else
    auto child=fork();if(child<0)throw std::runtime_error("cannot submit worker");
    if(child==0){setsid();int sink=open("/dev/null",O_RDWR);dup2(sink,0);dup2(sink,1);dup2(sink,2);close(sink);execl(executable.c_str(),executable.c_str(),"--workspace",workspace.c_str(),"__worker","--project",project.c_str(),"--id",job.c_str(),nullptr);_exit(127);}
#endif
}
Json make_request(const Args& args) {
    Json request{{"schema","indago.action.v1"},{"project",args.get("project")},{"backend",args.get("backend","airece")},{"operation",args.get("operation","inspect")},{"address",args.get("address")},{"view",args.get("view","compact")},{"budget",{{"wall_ms",args.number("timeout-ms",120000)},{"output_bytes",args.number("max-output-bytes",2097152)},{"memory_bytes",args.number("max-memory-bytes",2147483648ULL)},{"max_items",args.number("max-items",2048)}}},{"arguments",Json::object()}};
    if(!args.get("target-id").empty())request["target_id"]=args.get("target-id");
    if(!args.get("idempotency-key").empty())request["idempotency_key"]=args.get("idempotency-key");
    static const std::set<std::string> forwarded{"profile","from","to","source","sink","target","function","mode","max-states","max-queries","max-paths","function-depth","symbolic-timeout-ms","max-taint-bytes","max-symbolic-bytes"};
    for(const auto& [key,value]:args.options) if(forwarded.contains(key))request["arguments"][key]=value;
    if(args.get("backend")=="ghidra") {
        for(const auto* key:{"cursor","collection","search"})if(args.options.contains(key))request["arguments"][key]=args.get(key);
        if(args.options.contains("expected-revision"))request["arguments"]["expected_revision"]=args.number("expected-revision",0);
        if(args.options.contains("scan-limit"))request["arguments"]["scan_limit"]=args.number("scan-limit",100000);
    }
    if((args.get("backend")=="ilspy"||args.get("backend")=="lief"||args.get("backend")=="wireshark")&&args.options.contains("offset"))request["arguments"]["offset"]=args.number("offset",0);
    if(args.get("backend")=="capa"&&args.options.contains("format"))request["arguments"]["format"]=args.get("format");
    return request;
}
void usage() {
    std::cout << "IndagoRev native static and dynamic workbench\n"
      "  indago benchmark freeze|prepare|grade|score --request FILE (operator-side, not harness tools)\n"
      "  indago runtime capabilities|payloads\n"
      "  indago runtime launch --project NAME --file FILE [--request runtime.json]\n"
      "  indago runtime io-run --request trusted-io-run.json\n"
      "  indago runtime attach --project NAME --pid PID\n"
      "  indago runtime record --project NAME --file ELF [--timeout-ms 10000 --trace-bytes 67108864]\n"
      "  indago runtime replay --project NAME --session RECORDING_RUN\n"
      "  indago runtime status|continue|pause|step|capture|detach --project NAME --session run_ID\n"
      "  indago runtime breakpoint --project NAME --session run_ID --static-address 0xVA\n"
      "  indago runtime memory --project NAME --session run_ID --address 0xVA --size 256\n"
      "  indago runtime trace --project NAME --session run_ID --max-steps 128\n"
      "  indago runtime observations|modules|threads|resolve|symbolic|cancel|terminate [options]\n"
      "  indago runtime reanalyze --project NAME --session RUN --observation OBS --backend xair|ghidra|both\n"
      "  indago runtime feedback --project NAME --session RUN --observation OBS --backend xair|ghidra\n"
      "  indago runtime instrument --project NAME --file FILE --backend frida --recipe io|code|modules|config|network\n"
      "  indago runtime instrument --project NAME --backend frida --pid PID --recipe config\n"
      "  indago runtime stack|crash|step-over|step-out|breakpoints|processes [session options]\n"
      "  indago runtime watchpoint|select-process|validate-witness [session options] --request runtime.json\n"
      "  indago runtime identities|lineage|recipes [options]\n"
      "  indago [--workspace DIR] project create --name NAME\n"
      "  indago target import --project NAME --file FILE\n"
      "  indago query --project NAME --backend airece|xair|sym|ghidra|ilspy|capa|floss|lief|wireshark --operation OP [--address 0xVA]\n"
      "  indago analyze --project NAME [--profile fast|balanced|exhaustive]\n"
      "  indago action run|submit --request action.json\n"
      "  indago job list|show|cancel --project NAME [--id job_ID]\n"
      "  indago functions --project NAME\n"
      "  indago function show --project NAME --id fn_ID\n"
      "  indago evidence list|show --project NAME [--id ev_ID]\n"
      "  indago capabilities\n"
      "  indago schema show --name action|result|evidence\n"
      "  indago index entities|relations|claims|revisions|rebuild --project NAME [--kind KIND] [--address 0xVA]\n"
      "  indago job recover|events --project NAME [--id job_ID]\n"
      "  indago workbench capabilities\n"
      "  indago harness capabilities|create|show|scope|read|audit|claim|renew|release|transfer|checkpoint|propose|run|actions|context|finish|cancel|events --request FILE\n"
      "  indago harness profile|recipes|explore|controller --request FILE\n"
      "  indago knowledge put|show|list|refresh|impact --project NAME --request FILE\n"
      "  indago system create|show|list|preflight --project NAME --request FILE\n"
      "  indago graph search|neighborhood|packet --project NAME --request FILE\n"
      "  indago coverage report --project NAME [--artifact SHA]\n"
      "  indago recognize scan|transform run|validate compare|validate transform --request FILE\n"
      "  indago batch create|run|show|cancel|events --request FILE\n"
      "  indago bundle export|import --request FILE\n"
      "  indago retention plan|quarantine --request FILE\n"
      "Results are JSON. Exit codes: 0 complete, 1 failed, 2 invalid, 3 partial, 130 cancelled.\n";
}
}
int indago_airece_main(int argc,char** argv);
int main(int argc,char** argv) {
#if INDAGO_HAS_XAIR
    if(argc>1 && std::string_view(argv[1])=="__airece") return indago_airece_main(argc-1,argv+1);
#endif
    try {
        if(argc==3&&std::string_view(argv[1])=="__rr_exec"){
            if(std::string_view(argv[2]).size()>524288)throw std::runtime_error("rr worker request exceeds budget");
            return indago::rr_exec_worker(Json::parse(argv[2]));
        }
        if(argc==3&&std::string_view(argv[1])=="__lief"){
            if(std::string_view(argv[2]).size()>16384)throw std::runtime_error("LIEF worker request exceeds 16 KiB");
            const auto result=indago::lief_worker(Json::parse(argv[2]));std::cout<<result.dump();return indago::result_exit_code(result.at("status").get<std::string>());
        }
        if(argc==3&&std::string_view(argv[1])=="__wireshark"){
            if(std::string_view(argv[2]).size()>16384)throw std::runtime_error("Offline packet request exceeds 16 KiB");
            const auto result=indago::wireshark_worker(Json::parse(argv[2]));std::cout<<result.dump();return indago::result_exit_code(result.at("status").get<std::string>());
        }
        if(argc==3&&std::string_view(argv[1])=="__xair"){
            const auto r=Json::parse(argv[2]);indago::TargetRecord t{r.at("id"),r.at("project"),r.at("sha256"),"",r.at("size").get<std::uintmax_t>(),r.at("path").get<std::string>()};
            if(indago::sha256_file(t.object_path)!=t.sha256)throw std::runtime_error("static worker artifact identity mismatch");
            indago::XairQuery q;q.operation=r.at("operation");q.max_items=r.at("max_items");q.max_output_bytes=r.at("output_bytes");q.analysis.wall_time_ms=r.at("wall_ms");q.analysis.memory_bytes=r.at("memory_bytes");q.analysis.profile=r.at("profile");
            if(r.contains("function"))q.function=r.at("function").get<std::uint64_t>();
            auto result=indago::query_xair(t,q);std::cout<<result.json;return indago::result_exit_code(result.status);
        }
        Args args(argc,argv);if(args.positional.empty()||args.positional[0]=="help"){usage();return 0;}
        indago::StaticService service(args.get("workspace",".indago"));auto& store=service.store();
        const auto cmd=args.positional[0];const auto sub=args.positional.size()>1?args.positional[1]:"";
        Json response;int code=0;
        if(cmd=="version") response={{"schema","indago.version.v2"},{"version",INDAGO_VERSION},{"implementation","C++20"},{"primary_executable","indago"},{"integrated_components",{"AIRECE","XAIR","XAIR_CFG","XAIR_SYM","Z3"}},{"external_workers",INDAGO_HAS_GHIDRA?Json::array():Json::array({"Ghidra/JDK"})},{"ghidra_bundled",INDAGO_HAS_GHIDRA!=0},{"ilspy_bundled",INDAGO_HAS_ILSPY!=0},{"enrichment_bundled",INDAGO_HAS_ENRICHMENT!=0}};
        else if(cmd=="capabilities") {response=service.capabilities();response["runtime"]=indago::runtime_capabilities();response["harness"]=indago::harness_capabilities();}
        else if(cmd=="benchmark") {
            const auto r=read_json(args.get("request"));
            response=sub=="certify"?indago::harness_certify(service,r):indago::benchmark::action(sub,r);
        }
        else if(cmd=="harness") {
            Json r=args.get("request").empty()?Json::object():read_json(args.get("request"));
            for(const auto* key:{"project","id"})if(!args.get(key).empty()){if(r.contains(key)&&r[key]!=args.get(key))throw std::runtime_error("conflicting harness request/CLI field");r[key]=args.get(key);}
            for(const auto* key:{"limit","offset"})if(args.options.contains(key)){auto value=args.number(key,0);if(r.contains(key)&&r[key]!=value)throw std::runtime_error("conflicting harness request/CLI paging field");r[key]=value;}
            response=indago::harness_action(service,sub,r);
            auto status=response.value("status",std::string{});
            if(response.value("partial",false)||status=="partial"||status=="waiting_for_job"||status=="budget_exhausted"||status=="capability_blocked"||status=="unsupported"||status=="environment_unavailable"||status=="contradictory")code=3;
            else if(status=="failed"||status=="timeout"||status=="interrupted"||status=="unavailable")code=1;else if(status=="invalid_request"||status=="not_found")code=2;else if(status=="cancelled")code=130;
        }
        else if(cmd=="__workbench") response=indago::harness_workbench_worker(service,args.get("project"),args.get("id"),args.get("action"),args.get("runner"));
        else if(cmd=="__runtime")return indago::runtime_worker(store,args.get("session"));
        else if(cmd=="runtime") {
            Json r=args.get("request").empty()?Json::object():read_json(args.get("request"));
            r["operation"]=sub;
            for(auto key:{"project","session","file","function","artifact","module","observation","kind","anchor","id","mode","cwd","sink","backend","recipe"})if(!args.get(key).empty())r[key]=args.get(key);
            for(auto key:{"pid","thread","size","address","rva","from","to","offset","limit"})if(!args.get(key).empty())r[key]=args.get(key);
            if(!args.get("static-address").empty())r["static_address"]=args.get("static-address");
            if(!args.get("timeout-ms").empty())r["timeout_ms"]=args.number("timeout-ms",5000);
            if(!args.get("max-steps").empty())r["max_steps"]=args.number("max-steps",128);
            if(!args.get("max-events").empty())r["max_events"]=args.number("max-events",1024);
            if(!args.get("trace-bytes").empty())r["trace_bytes"]=args.number("trace-bytes",67108864);
            if(!args.get("lifetime-ms").empty())r["lifetime_ms"]=args.number("lifetime-ms",1800000);
            if(!args.get("signal").empty())r["signal"]=std::stoi(args.get("signal"));
            if(!args.get("wait").empty()){if(args.get("wait")!="true"&&args.get("wait")!="false")throw std::runtime_error("wait must be true or false");r["wait"]=args.get("wait")=="true";}
            response=indago::runtime_command(store,argv[0],r);auto status=response.value("status",std::string("completed"));if(status=="failed")code=1;else if(status=="partial"||status=="pending")code=3;else if(status=="cancelled")code=130;
        }
        else if(cmd=="schema"&&sub=="show")response=indago::contract_schema(args.get("name"));
        else if(cmd=="index"){
            if(sub=="rebuild")response=store.reindex(args.get("project"));
            else{Json filter{{"category",sub},{"limit",args.number("limit",100)},{"offset",args.number("offset",0)},{"history",args.get("history")=="true"}};
                for(const auto* key:{"id","artifact","backend","revision","kind","anchor","name","address","search","source","target","subject","predicate"})if(!args.get(key).empty())filter[key]=args.get(key);
                response=store.index_query(args.get("project"),filter);}
        }
        else if(std::set<std::string>{"workbench","knowledge","system","graph","coverage","recognize","transform","validate","batch","bundle","retention"}.contains(cmd)){
            Json r=args.get("request").empty()?Json::object():read_json(args.get("request"));
            for(const auto* key:{"project","id","artifact","kind","search","anchor","address"})if(!args.get(key).empty()){if(r.contains(key)&&r[key]!=args.get(key))throw std::runtime_error(std::string("conflicting request/CLI field: ")+key);r[key]=args.get(key);}
            for(const auto* key:{"limit","offset"})if(args.options.contains(key))r[key]=args.number(key,0);
            response=indago::workbench_action(service,cmd,sub,r);if(response.value("partial",false))code=3;
            if(response.contains("status")){auto status=response["status"].get<std::string>();if(status=="partial"||status=="budget_exhausted"||status=="waiting_for_job"||status=="capability_blocked")code=3;else if(status=="cancelled")code=130;}
        }
        else if(cmd=="project"&&sub=="create"){auto result=store.create_project(args.get("name"));response=Json::parse(result.json);}
        else if(cmd=="project"&&sub=="show") response=store.project_info(args.get("project"));
        else if(cmd=="target"&&sub=="import") {auto target=store.import_target(args.get("project"),args.get("file"));response={{"schema","indago.target.v1"},{"id",target.id},{"artifact_sha256",target.sha256},{"name",target.display_name},{"size",target.size}};}
        else if(cmd=="functions") response=store.functions(args.get("project"),args.get("artifact"),args.number("offset",0),args.number("limit",100));
        else if(cmd=="function"&&sub=="show") response=store.function_views(args.get("project"),args.get("id"),args.number("offset",0),args.number("limit",100));
        else if(cmd=="evidence"&&(sub=="list"||sub=="show")) response=store.evidence(args.get("project"),sub=="show"?args.get("id"):"",args.number("offset",0),args.number("limit",100));
        else if(cmd=="job"&&(sub=="list"||sub=="show")) response=store.job_info(args.get("project"),sub=="show"?args.get("id"):"");
        else if(cmd=="job"&&sub=="cancel") {if(args.get("id").empty())throw std::runtime_error("job id required");response=store.cancel_job(args.get("project"),args.get("id"));}
        else if(cmd=="job"&&sub=="recover")response=store.recover_jobs(args.get("project"));
        else if(cmd=="job"&&sub=="events")response=store.job_events(args.get("project"),args.get("id"));
        else if(cmd=="query" || (cmd=="action"&&(sub=="run"||sub=="submit"))) {
            auto request=cmd=="action"?read_json(args.get("request")):make_request(args);auto job=service.prepare(request);
            if(cmd=="action"&&sub=="submit") {
                if(job["status"]=="queued")try{spawn(indago::fs::absolute(argv[0]),store.root(),request.at("project"),job.at("id"));}catch(const std::exception& error){auto t=store.target(request.at("project").get<std::string>(),job["request"]["target_id"].get<std::string>(),false);store.publish_result(t,job,job["request"]["backend"].get<std::string>(),{1,"failed",Json{{"status","failed"},{"diagnostic",error.what()}}.dump()});throw;}
                response={{"schema","indago.job.v1"},{"id",job["id"]},{"revision",job["revision"]},{"status",job["status"]}};
            }
            else {std::cerr<<"job "<<job["id"].get<std::string>()<<'\n';response=service.execute(job);code=indago::result_exit_code(response["status"].get<std::string>());}
        }
        else if(cmd=="__worker") {auto list=store.job_info(args.get("project"),args.get("id"));response=service.execute(list["jobs"][0]);return indago::result_exit_code(response["status"].get<std::string>());}
        else if(cmd=="analyze") {
            Json results=Json::array();const auto selected=args.get("backend","all");
            using Steps=std::vector<std::pair<std::string,std::string>>;
            Steps steps{{"xair","inventory"},{"airece","inspect"},{"airece","functions"},{"xair","cfg"},{"ghidra","import"},{"ghidra","functions"}};
            const std::map<std::string,Steps> additional{
                {"lief",{{"lief","inventory"},{"lief","sections"},{"lief","libraries"}}},
                {"ilspy",{{"ilspy","inventory"},{"ilspy","types"},{"ilspy","methods"}}},
                {"capa",{{"capa","capabilities"}}},{"floss",{{"floss","strings"}}},{"wireshark",{{"wireshark","packets"}}}};
            if(const auto found=additional.find(selected);found!=additional.end())steps=found->second;
            for(const auto& [backend,operation]:steps) {
                if(selected!="all"&&selected!=backend)continue;
                auto request=make_request(args);request["backend"]=backend;request["operation"]=operation;
                if(backend=="ghidra")request["arguments"]=Json::object();
                auto job=service.prepare(request);std::cerr<<"job "<<job["id"].get<std::string>()<<'\n';auto result=service.execute(job);
                const auto exit=indago::result_exit_code(result["status"].get<std::string>());if(exit!=0)code=(code==1||exit==1)?1:exit;
                result.erase("data");results.push_back(result);
            }
            if(results.empty())throw std::runtime_error("unknown analysis backend");response={{"schema","indago.analysis.v1"},{"status",code==0?"completed":code==3?"partial":"failed"},{"results",results}};
        }
        else throw std::runtime_error("unknown command; run indago help");
        std::cout<<response.dump()<<'\n';return code;
    } catch(const std::exception& error){const auto* workbench=dynamic_cast<const indago::WorkbenchError*>(&error);std::cout<<Json{{"schema","indago.error.v1"},{"status","invalid_request"},{"error_code",workbench?workbench->code:"invalid_request"},{"diagnostic",error.what()}}.dump()<<'\n';return 2;}
}
