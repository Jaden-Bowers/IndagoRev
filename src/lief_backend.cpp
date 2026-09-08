#include "indago/lief.hpp"
#include "indago/airece.hpp"
#include <algorithm>
namespace indago {
CommandResult query_lief(const TargetRecord& target,const nlohmann::json& request,const fs::path& cancel) {
    using J=nlohmann::json;
#if INDAGO_HAS_LIEF
    if(target.size>16*1024*1024)throw std::runtime_error("LIEF input exceeds 16 MiB");
    const auto executable=find_native_worker();if(!executable)throw std::runtime_error("Native LIEF worker unavailable");
    NativeProcessOptions options;options.cancel_file=cancel;
    options.wall_time_ms=std::min<std::uint64_t>(request.at("budget").at("wall_ms").get<std::uint64_t>(),60000);
    options.max_output_bytes=std::min<std::size_t>(request.at("budget").at("output_bytes").get<std::size_t>(),1048576);
    const J query{{"path",target.object_path.string()},{"sha256",target.sha256},{"operation",request.at("operation")},
        {"offset",request.at("arguments").value("offset",0)},{"limit",std::min<std::size_t>(request.at("budget").at("max_items").get<std::size_t>(),128)},
        {"output_bytes",options.max_output_bytes}};
    const auto native=run_native_process(*executable,{"__lief",query.dump()},options);
    J result{{"backend","lief"},{"artifact_sha256",target.sha256}};
    if(native.cancelled)result["status"]="cancelled";
    else if(native.timed_out)result["status"]="timeout";
    else if(native.truncated)result["status"]="partial";
    else if(native.output.empty()){result["status"]="failed";result["diagnostic"]="LIEF worker returned no document";}
    else {
        result=J::parse(native.output);const auto state=result.value("status",std::string{});
        if(result.value("backend",std::string{})!="lief"||(state!="completed"&&state!="partial"&&state!="failed")||
           (state!="failed"&&result.value("artifact_sha256",std::string{})!=target.sha256))throw std::runtime_error("LIEF worker response identity/status mismatch");
        if(native.exit_code!=0&&state!="failed"&&!(native.exit_code==3&&state=="partial"))throw std::runtime_error("LIEF worker exit status mismatch");
    }
    result["worker"]={{"isolated_process",true},{"security_sandbox",false},{"memory_limit_enforced",false},
        {"wall_ms",options.wall_time_ms},{"output_bytes",options.max_output_bytes},{"exit_code",native.exit_code},
        {"cancelled",native.cancelled},{"timed_out",native.timed_out},{"output_truncated",native.truncated}};
    const auto state=result.at("status").get<std::string>();
    return {state=="completed"?0:state=="partial"?3:state=="cancelled"?130:1,state,result.dump()};
#else
    (void)target;(void)request;(void)cancel;
    return {1,"failed",J{{"status","failed"},{"diagnostic","LIEF static SDK unavailable"}}.dump()};
#endif
}
}
