#include "indago/service.hpp"
#include "indago/airece.hpp"
#include "indago/ghidra.hpp"
#include "indago/ilspy.hpp"
#include "indago/enrichment.hpp"
#include "indago/lief.hpp"
#include "indago/wireshark.hpp"
#include "indago/xair.hpp"
#include "indago/sym.hpp"
#include "indago/contracts.hpp"
#include "indago/workbench.hpp"
#include <atomic>
#include <charconv>
#include <set>
#include <thread>

namespace indago {
using Json=nlohmann::json;
int result_exit_code(std::string_view status) {
    if(status=="completed" || status=="complete") return 0;
    if(status=="partial") return 3;
    if(status=="cancelled" || status=="canceled") return 130;
    if(status=="invalid_request"||status=="not_found") return 2;
    return 1;
}
Json StaticService::capabilities() const {
    Json result{{"schema","indago.capabilities.v2"},{"implementation","C++20"},{"transport","JSON"},{"backends",Json::array()}};
    const auto airece=find_airece(); const auto ghidra=find_ghidra_headless();
    result["backends"].push_back({{"name","airece"},{"available",airece.has_value()},{"executable",airece?Json(airece->string()):Json(nullptr)},{"operations",{"inspect","functions","function","calls","xrefs","slice","path","flow","taint","evidence"}},{"views",{"compact","agent","pseudocode","disassembly","json"}},{"cancellation",true}});
    result["backends"].push_back({{"name","xair"},{"available",INDAGO_HAS_XAIR!=0},{"operations",{"inventory","semantic","cfg"}},{"integration","statically-linked"},{"cancellation",true}});
    result["backends"][0]["integration"]="statically-linked; same-executable worker";
    result["backends"].push_back({{"name","sym"},{"available",airece.has_value()},{"operations",{"solve_branch","source_to_sink","symbolic_slice","taint","path_condition"}},{"integration","statically-linked AIRECE/XAIR_SYM/Z3"},{"cancellation",true}});
    result["backends"].push_back({{"name","ghidra"},{"available",ghidra.has_value()},{"executable",ghidra?Json(ghidra->string()):Json(nullptr)},{"operations",{"import","inspect","functions","decompile","tokens","assembly","xrefs","calls","strings","imports","exports","types","variables","cfg","pcode","control_flow","analyze","session","flush","close","annotate","annotations"}},{"integration","persistent DecompInterface worker"},{"bundled",INDAGO_HAS_GHIDRA!=0},{"profiles",{"standard","inventory"}},{"cancellation",true}});
    result["backends"].push_back({{"name","ilspy"},{"available",INDAGO_HAS_ILSPY!=0},{"operations",{"inventory","types","methods","decompile","assembly"}},{"integration","bundled self-contained ILSpy worker"},{"cancellation",true},{"input_limit_bytes",16777216},{"dependency_resolution","disabled"}});
    result["backends"].push_back({{"name","capa"},{"available",INDAGO_HAS_ENRICHMENT!=0},{"operations",{"capabilities"}},{"integration","bundled upstream standalone worker"},{"formats",{"pe","elf","dotnet"}},{"cancellation",true},{"findings_are_leads",true}});
    result["backends"].push_back({{"name","floss"},{"available",INDAGO_HAS_ENRICHMENT!=0},{"operations",{"strings"}},{"integration","bundled upstream standalone worker"},{"modes",{"static","stack","tight","decoded","all"}},{"cancellation",true},{"language_specialization","disabled"}});
    result["backends"].push_back({{"name","lief"},{"available",INDAGO_HAS_LIEF!=0},{"operations",{"inventory","sections","resources","notes","libraries"}},{"integration","statically linked C++; same-executable worker"},{"cancellation",true},{"input_limit_bytes",16777216}});
    result["backends"].push_back({{"name","wireshark"},{"available",INDAGO_HAS_WIRESHARK!=0},{"operations",{"packets"}},{"integration","bundled offline TShark worker"},{"live_capture",false},{"input_limit_bytes",16777216},{"cancellation",true}});
    result["workbench"]=workbench_capabilities();return result;
}
Json StaticService::normalize(Json request) const {
    if(request.dump().size()>1024*1024)throw std::runtime_error("action exceeds 1 MiB limit");
    validate_contract("action",request);
    if(!request.is_object()) throw std::runtime_error("request must be a JSON object");
    if(request.value("schema",std::string("indago.action.v1"))!="indago.action.v1") throw std::runtime_error("unsupported action schema");
    const std::set<std::string> backends{"airece","xair","sym","ghidra","ilspy","capa","floss","lief","wireshark"};
    const auto backend=request.at("backend").get<std::string>();
    if(!backends.contains(backend)) throw std::runtime_error("unknown backend");
    const auto operation=request.at("operation").get<std::string>();
    if(operation.empty()) throw std::runtime_error("operation cannot be empty");
    const std::map<std::string,std::set<std::string>> operations{
        {"airece",{"inspect","functions","function","calls","xrefs","slice","path","flow","taint","evidence"}},
        {"xair",{"inventory","cfg","semantic"}},
        {"ilspy",{"inventory","types","methods","decompile","assembly"}},
        {"capa",{"capabilities"}},{"floss",{"strings"}},
        {"lief",{"inventory","sections","resources","notes","libraries"}},
        {"wireshark",{"packets"}},
        {"sym",{"solve_branch","source_to_sink","symbolic_slice","taint","path_condition"}},
        {"ghidra",{"import","inspect","functions","decompile","tokens","assembly","xrefs","calls","strings","imports","exports","types","variables","cfg","pcode","control_flow","analyze","session","flush","close","annotate","annotations"}}};
    if(!operations.at(backend).contains(operation))throw std::runtime_error("unsupported backend operation");
    request["address"]=request.value("address",std::string{});request["view"]=request.value("view",std::string("compact"));
    const auto addr=request["address"].get<std::string>();
    const bool needs_address=backend=="ghidra"&&std::set<std::string>{"decompile","tokens","assembly","xrefs","calls","variables","cfg","pcode","control_flow","annotate"}.contains(operation);
    if(needs_address&&addr.empty())throw std::runtime_error("operation requires a function address");
    if(!addr.empty()&&!(backend=="airece"&&operation=="evidence")){
        if(!addr.starts_with("0x")||addr.size()<3||addr.size()>18||addr.substr(2).find_first_not_of("0123456789abcdefABCDEF")!=std::string::npos)throw std::runtime_error("address requires a 64-bit hexadecimal value");
    }
    const auto project=request.at("project").get<std::string>();
    auto target=store_.target(project,request.value("target_id",std::string{}));
    if(request.contains("artifact_sha256") && request["artifact_sha256"]!=target.sha256) throw std::runtime_error("stale artifact identity");
    request["schema"]="indago.action.v1"; request["target_id"]=target.id; request["artifact_sha256"]=target.sha256;
    if(!request.contains("budget")) request["budget"]=Json::object();
    auto& budget=request["budget"]; if(!budget.is_object()) throw std::runtime_error("budget must be an object");
    for(auto [key,def,min,max]: {std::tuple{"wall_ms",120000ULL,1ULL,3600000ULL}, {"output_bytes",2097152ULL,4096ULL,67108864ULL}, {"memory_bytes",2147483648ULL,1048576ULL,2147483648ULL}, {"max_items",2048ULL,1ULL,100000ULL}}) {
        if(!budget.contains(key)) budget[key]=def;
        if(!budget[key].is_number_unsigned() && !budget[key].is_number_integer()) throw std::runtime_error(std::string("invalid budget ")+key);
        auto v=budget[key].get<std::int64_t>(); if(v<static_cast<std::int64_t>(min)||v>static_cast<std::int64_t>(max)) throw std::runtime_error(std::string("out-of-range budget ")+key);
    }
    if(!request.contains("arguments")) request["arguments"]=Json::object();
    if(!request["arguments"].is_object()) throw std::runtime_error("arguments must be an object");
    if(backend=="capa") {
        for(auto it=request["arguments"].begin();it!=request["arguments"].end();++it)if(it.key()!="format")throw std::runtime_error("Unknown capa argument");
        if(request["arguments"].contains("format")&&!std::set<Json>{"pe","elf","dotnet"}.contains(request["arguments"]["format"]))throw std::runtime_error("capa format must be pe, elf or dotnet");
        if(!addr.empty()&&request["arguments"].value("format",std::string{})=="dotnet")throw std::runtime_error("capa function restriction is currently native-address only");
    }
    if(backend=="floss") {
        for(auto it=request["arguments"].begin();it!=request["arguments"].end();++it)if(it.key()!="mode"&&it.key()!="minimum_length")throw std::runtime_error("Unknown FLOSS argument");
        if(!std::set<Json>{"static","stack","tight","decoded","all"}.contains(request["arguments"].value("mode",Json("static"))))throw std::runtime_error("Invalid FLOSS mode");
        const auto minimum=request["arguments"].value("minimum_length",Json(4));if(!minimum.is_number_integer()||minimum.get<std::int64_t>()<4||minimum.get<std::int64_t>()>256)throw std::runtime_error("FLOSS minimum_length must be 4..256");
        if(!addr.empty()&&request["arguments"].value("mode",std::string("static"))=="static")throw std::runtime_error("FLOSS function restriction does not apply to static strings");
    }
    if(backend=="wireshark") {
        for(auto it=request["arguments"].begin();it!=request["arguments"].end();++it)if(it.key()!="offset")throw std::runtime_error("Unknown offline packet argument");
        const auto offset=request["arguments"].value("offset",Json(0));
        if(!offset.is_number_integer()||offset.get<std::int64_t>()<0||offset.get<std::int64_t>()>4096)throw std::runtime_error("Offline packet offset must be 0..4096");
        if(!addr.empty())throw std::runtime_error("Offline packet query does not accept a program address");
    }
    if(backend=="lief") {
        for(auto it=request["arguments"].begin();it!=request["arguments"].end();++it)if(it.key()!="offset")throw std::runtime_error("Unknown LIEF argument");
        const auto offset=request["arguments"].value("offset",Json(0));
        if(!offset.is_number_integer()||offset.get<std::int64_t>()<0||offset.get<std::int64_t>()>65536)throw std::runtime_error("LIEF offset must be 0..65536");
        if(!addr.empty())throw std::runtime_error("LIEF metadata operations do not accept a function address");
        if(operation=="inventory"&&offset!=0)throw std::runtime_error("LIEF inventory does not accept a nonzero offset");
    }
    if(backend=="ilspy") {
        for(auto it=request["arguments"].begin();it!=request["arguments"].end();++it)if(it.key()!="offset")throw std::runtime_error("Unknown ILSpy argument");
        const auto offset=request["arguments"].value("offset",Json(0));
        if(!offset.is_number_integer()||offset.get<std::int64_t>()<0||offset.get<std::int64_t>()>1000000)throw std::runtime_error("Invalid ILSpy offset");
        const bool method_operation=operation=="decompile"||operation=="assembly";
        if(method_operation&&(addr.size()!=10||!addr.starts_with("0x06")))throw std::runtime_error("ILSpy method operation requires a MethodDef metadata token (0x06xxxxxx), not a native address");
        if(!method_operation&&!addr.empty())throw std::runtime_error("ILSpy address only applies to a method operation");
    }
    if(backend=="ghidra") {
        const std::set<std::string> allowed{"cursor","collection","search","profile","expected_revision","annotation","scan_limit"};
        for(auto it=request["arguments"].begin();it!=request["arguments"].end();++it)if(!allowed.contains(it.key()))throw std::runtime_error("unknown Ghidra argument: "+it.key());
        if(request["arguments"].dump().size()>32768)throw std::runtime_error("Ghidra arguments exceed 32KiB");
    }
    if(backend=="airece"&&operation=="flow") {
        for(const auto *key:{"source","target"}) {
            const auto &args=request.at("arguments");
            if(!args.contains(key)||!((args.at(key).is_string()&&!args.at(key).get_ref<const std::string&>().empty())||
                (args.at(key).is_array()&&!args.at(key).empty())))
                throw std::runtime_error("AIRECE flow requires arguments.source and arguments.target selectors, e.g. funcarg(0)@0xFUNCTION and reach@0xADDRESS; an address alone is insufficient");
        }
    }
    if(backend=="xair")for(auto it=request["arguments"].begin();it!=request["arguments"].end();++it)if(it.key()!="profile")throw std::runtime_error("unknown XAIR argument");
    if(backend=="xair"&&request["arguments"].contains("profile")&&!std::set<Json>{"fast","balanced","exhaustive"}.contains(request["arguments"]["profile"]))throw std::runtime_error("invalid XAIR profile");
    validate_contract("action",request);
    return request;
}
Json StaticService::prepare(Json request) const {
    request=normalize(std::move(request));
    return store_.start_job(store_.target(request.at("project").get<std::string>(),request.at("target_id").get<std::string>(),false),request);
}
Json StaticService::execute(const Json& submitted) const {
    auto prior=store_.job_info(submitted.at("request").at("project").get<std::string>(),submitted.at("id").get<std::string>())["jobs"][0];
    if(prior.contains("result")){auto response=prior["result"];const auto output=prior["request"]["budget"]["output_bytes"].get<std::size_t>();if(response.dump().size()>output){response.erase("data");response["data_omitted"]=true;}return response;}
    auto job=store_.claim_job(prior["request"]["project"].get<std::string>(),prior["id"].get<std::string>());
    const auto request=job.at("request"); const auto project=request.at("project").get<std::string>();
    const auto target=store_.target(project,request.at("target_id").get<std::string>(),false);
    std::atomic_bool lease_lost=false;
    std::jthread lease_worker([&](std::stop_token stop){while(!stop.stop_requested()){try{store_.heartbeat(job["id"].get<std::string>(),job["lease_token"].get<std::string>());}catch(...){lease_lost=true;return;}for(int i=0;i<50&&!stop.stop_requested();++i)std::this_thread::sleep_for(std::chrono::milliseconds(100));}});
    const auto backend=request.at("backend").get<std::string>(); const auto operation=request.at("operation").get<std::string>();
    const auto budget=request.at("budget"); const auto args=request.at("arguments");
    const auto wall=budget.at("wall_ms").get<std::uint64_t>(); const auto output=budget.at("output_bytes").get<std::size_t>();
    const auto cancel=store_.cancellation_path(job.at("id").get<std::string>());
    const auto address=request.value("address",std::string{});
    CommandResult result;
    try {
        if(sha256_file(target.object_path)!=target.sha256)throw std::runtime_error("artifact integrity check failed");
        if(fs::exists(cancel)) result={130,"cancelled",Json{{"status","cancelled"},{"diagnostic","cancelled before execution"}}.dump()};
        else if(backend=="airece") {
            AireceOptions options; options.operation=operation; options.view=request.value("view",std::string("compact")); options.address=address;
            options.wall_time_ms=wall; options.max_output_bytes=output; options.cancel_file=cancel;
            for(auto it=args.begin();it!=args.end();++it) {
                if(it.value().is_array()){if(it.key()!="source"&&it.key()!="target")throw std::runtime_error("only source/target selectors may repeat");for(const auto& v:it.value())options.repeated_arguments.emplace_back(it.key(),v.get<std::string>());}
                else options.arguments[it.key()]=it.value().is_string()?it.value().get<std::string>():it.value().dump();
            }
            options.arguments["max-memory-bytes"]=std::to_string(budget["memory_bytes"].get<std::uint64_t>());
            result=run_airece(target,options);
        } else if(backend=="ghidra") {
            GhidraOptions options; options.operation=operation; options.address=address; options.timeout_ms=wall; options.max_output_bytes=output;
            options.max_items=budget.at("max_items").get<std::uint64_t>(); options.cancel_file=cancel; options.arguments=args; result=query_ghidra(target,store_,options);
        } else if(backend=="capa"||backend=="floss") {
            result=query_enrichment(target,request,cancel);
        } else if(backend=="wireshark") {
            result=query_wireshark(target,request,cancel);
        } else if(backend=="lief") {
            result=query_lief(target,request,cancel);
        } else if(backend=="ilspy") {
            result=query_ilspy(target,request,cancel);
        } else if(backend=="xair") {
            XairQuery options; options.operation=operation; options.max_items=budget["max_items"]; options.max_output_bytes=output;
            options.analysis.wall_time_ms=wall; options.analysis.memory_bytes=budget["memory_bytes"]; options.analysis.profile=args.value("profile",std::string("balanced"));
            if(!address.empty()) { std::uint64_t n{}; auto text=std::string_view(address); if(!text.starts_with("0x")) throw std::runtime_error("address requires 0x hexadecimal notation"); text.remove_prefix(2); auto parsed=std::from_chars(text.data(),text.data()+text.size(),n,16); if(parsed.ec!=std::errc{}||parsed.ptr!=text.data()+text.size()) throw std::runtime_error("invalid address"); options.function=n; }
            const auto executable=find_airece();if(!executable)throw std::runtime_error("integrated XAIR worker unavailable");
            Json worker{{"id",target.id},{"project",target.project},{"sha256",target.sha256},{"size",target.size},{"path",target.object_path.string()},{"operation",operation},{"max_items",options.max_items},{"output_bytes",output},{"wall_ms",wall},{"memory_bytes",options.analysis.memory_bytes},{"profile",options.analysis.profile}};
            if(options.function)worker["function"]=*options.function;
            NativeProcessOptions process;process.wall_time_ms=wall;process.max_output_bytes=output;process.cancel_file=cancel;
            const auto native=run_native_process(*executable,{"__xair",worker.dump()},process);
            if(native.cancelled)result={130,"cancelled",Json{{"status","cancelled"},{"diagnostic","static worker cancelled"}}.dump()};
            else if(native.timed_out)result={1,"timeout",Json{{"status","timeout"},{"diagnostic","static worker wall budget exceeded"}}.dump()};
            else if(native.truncated)result={3,"partial",Json{{"status","partial"},{"diagnostic","static worker output exceeded budget"}}.dump()};
            else{auto parsed=Json::parse(native.output);result={native.exit_code,parsed.value("status",std::string("failed")),native.output};}
        } else if(backend=="sym") {
            SymOptions options; options.operation=operation; options.address=address; options.wall_time_ms=wall; options.max_output_bytes=output; options.cancel_file=cancel;
            options.function=args.value("function",std::string{}); options.source=args.value("source",std::string{}); options.sink=args.value("sink",args.value("target",std::string{}));
            auto number=[&](const char* key,std::uint64_t fallback) { if(!args.contains(key))return fallback; if(args[key].is_string())return static_cast<std::uint64_t>(std::stoull(args[key].get<std::string>()));return args[key].get<std::uint64_t>();};
            options.max_states=number("max-states",256); options.max_queries=number("max-queries",16); options.max_paths=number("max-paths",4); options.function_depth=number("function-depth",3); options.solver_time_ms=number("symbolic-timeout-ms",1000);
            result=query_sym(target,options);
        }
    } catch(const std::exception& error) {result={1,"failed",Json{{"status","failed"},{"diagnostic",error.what()}}.dump()};}
    if(result.status=="complete") result.status="completed";
    if(result.status=="canceled") result.status="cancelled";
    lease_worker.request_stop();lease_worker.join();
    if(lease_lost)throw std::runtime_error("job ownership lost; result not published");
    auto response=store_.publish_result(target,job,backend,result);
    if(response.dump().size()>output) {response.erase("data");response["data_omitted"]=true;response["diagnostics"].push_back("Native result retained in evidence; retrieve with evidence show.");}
    validate_contract("result",response);
    return response;
}
}
