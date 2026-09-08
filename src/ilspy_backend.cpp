#include "indago/ilspy.hpp"
#include "indago/airece.hpp"
#include "indago/runtime.hpp"
#include <algorithm>

namespace indago {
CommandResult query_ilspy(const TargetRecord& target, const nlohmann::json& request,
                          const fs::path& cancel_file) {
    using Json=nlohmann::json;
#if INDAGO_HAS_ILSPY
    if(target.size>16*1024*1024)throw std::runtime_error("ILSpy input exceeds 16 MiB bound");
    const auto& budget=request.at("budget");
    NativeProcessOptions options;
    options.wall_time_ms=std::min<std::uint64_t>(budget.at("wall_ms").get<std::uint64_t>(),60000);
    options.max_output_bytes=std::min<std::size_t>(budget.at("output_bytes").get<std::size_t>(),1048576);
    options.cancel_file=cancel_file;
    const auto root=bundled_engines("ilspy")/"ilspy";
#ifdef _WIN32
    const auto executable=root/"indago_ilspy_worker.exe";
#else
    const auto executable=root/"indago_ilspy_worker";
#endif
    Json worker{{"path",target.object_path.string()},{"sha256",target.sha256},
        {"operation",request.at("operation")},{"token",request.value("address",std::string{})},
        {"limit",std::min<std::uint64_t>(budget.at("max_items").get<std::uint64_t>(),128)},
        {"offset",request.at("arguments").value("offset",0)},
        {"wall_ms",options.wall_time_ms},{"output_bytes",options.max_output_bytes}};
    const auto native=run_native_process(executable,{worker.dump()},options);
    Json result;
    if(native.cancelled)result={{"status","cancelled"},{"diagnostic","Managed worker cancelled"}};
    else if(native.timed_out)result={{"status","timeout"},{"diagnostic","Managed worker wall budget exceeded"}};
    else if(native.truncated)result={{"status","partial"},{"diagnostic","Managed worker output exceeded budget"}};
    else {
        result=Json::parse(native.output);
        const auto state=result.at("status").get<std::string>();
        if(result.value("backend",std::string{})!="ilspy" ||
           (state!="completed"&&state!="partial"&&state!="failed"&&state!="timeout") ||
           (result.contains("artifact_sha256")&&result["artifact_sha256"]!=target.sha256))
            throw std::runtime_error("Invalid managed worker response");
        if((state=="completed"||state=="partial")&&!result.contains("artifact_sha256"))
            throw std::runtime_error("Managed worker result lacks artifact identity");
    }
    result["worker"]={{"isolated_process",true},{"security_sandbox",false},
        {"wall_ms",options.wall_time_ms},{"output_bytes",options.max_output_bytes},
        {"memory_policy","bounded input; no OS memory quota"},{"exit_code",native.exit_code}};
    const auto state=result.at("status").get<std::string>();
    return {state=="completed"?0:state=="partial"?3:state=="cancelled"?130:1,state,result.dump()};
#else
    (void)target;(void)request;(void)cancel_file;
    return {1,"failed",Json{{"status","failed"},{"diagnostic","Bundled ILSpy worker unavailable; run tools/build-ilspy.ps1 and rebuild"}}.dump()};
#endif
}
}
