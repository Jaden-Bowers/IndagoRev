#include "indago/ilspy.hpp"
#include "indago/airece.hpp"
#include "indago/runtime.hpp"
#include <algorithm>
#include "isolated_worker.hpp"

namespace indago {
CommandResult query_ilspy(const TargetRecord& target, const nlohmann::json& request,
                          const fs::path& cancel_file, const std::vector<TargetRecord>& dependencies, const TargetRecord* pdb, const fs::path& private_output) {
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
    worker["dependencies"]=Json::array();
    if(!private_output.empty())worker["output_path"]=private_output.string();
    if(request.at("arguments").contains("entry"))worker["entry"]=request.at("arguments").at("entry");
    if(pdb)worker["pdb"]={{"path",pdb->object_path.string()},{"sha256",pdb->sha256}};
    for(const auto &d:dependencies)worker["dependencies"].push_back({{"path",d.object_path.string()},{"sha256",d.sha256}});
    NativeProcessResult native;
#ifdef __linux__
    std::vector<std::string> sandbox{"-i","/usr/bin/bwrap","--unshare-all","--unshare-user","--disable-userns","--die-with-parent","--new-session","--cap-drop","ALL","--clearenv",
      "--setenv","DOTNET_SYSTEM_GLOBALIZATION_INVARIANT","1","--setenv","DOTNET_EnableDiagnostics","0","--setenv","DOTNET_GCHeapHardLimit","0x10000000",
      "--setenv","HOME","/tmp","--setenv","TMPDIR","/tmp","--setenv","LC_ALL","C",
      "--ro-bind",root.string(),"/worker","--ro-bind","/usr/lib","/usr/lib","--ro-bind","/lib","/lib","--ro-bind","/lib64","/lib64",
      "--proc","/proc","--dev","/dev","--size","67108864","--tmpfs","/tmp","--dir","/input"};
    auto bind=[&](const fs::path& path,const std::string& alias){sandbox.insert(sandbox.end(),{"--ro-bind",path.string(),alias});};
    bind(target.object_path,"/input/target");worker["path"]="/input/target";
    for(std::size_t i=0;i<dependencies.size();++i){auto alias="/input/dependency"+std::to_string(i);bind(dependencies[i].object_path,alias);worker["dependencies"][i]["path"]=alias;}
    if(pdb){bind(pdb->object_path,"/input/pdb");worker["pdb"]["path"]="/input/pdb";}
    if(!private_output.empty()){
      worker["output_path"]="@receipt";worker["output_bytes"]=3145728;options.max_output_bytes=3145728;
    }
    sandbox.insert(sandbox.end(),{"--remount-ro","/","--chdir","/tmp","/worker/indago_ilspy_worker",worker.dump()});
    native=run_resource_scope(sandbox,options,805306368,64);
#else
    // Native Windows remains an explicitly unsandboxed parser profile.
    // Enforce committed-memory bounds without claiming filesystem isolation.
    options.process_memory_bytes=805306368;
    native=run_native_process(executable,{worker.dump()},options);
#endif
    Json result;
    if(native.cancelled)result={{"status","cancelled"},{"diagnostic","Managed worker cancelled"}};
    else if(native.timed_out)result={{"status","timeout"},{"diagnostic","Managed worker wall budget exceeded"}};
    else if(native.truncated)result={{"status","partial"},{"diagnostic","Managed worker output exceeded budget"}};
    else if(native.output.empty()||!native.output_complete)result={{"status","failed"},{"diagnostic","Managed worker unavailable, incomplete, or isolation setup failed"},{"worker_diagnostic",native.error.substr(0,1024)}};
    else {
        result=Json::parse(native.output);
        if(result.contains("private_content_hex")){
            const auto h=result.at("private_content_hex").get<std::string>();
            if(private_output.empty()||h.size()>2097152||h.size()%2||h.find_first_not_of("0123456789abcdef")!=h.npos||fs::exists(private_output))
                throw std::runtime_error("invalid private parser output");
            std::string bytes;bytes.reserve(h.size()/2);for(std::size_t i=0;i<h.size();i+=2)bytes+=static_cast<char>(std::stoul(h.substr(i,2),nullptr,16));
            if(sha256_text(bytes)!=result.at("content_sha256").get<std::string>())throw std::runtime_error("parser output hash mismatch");
            atomic_write(private_output,bytes);result.erase("private_content_hex");
        }
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
#ifdef __linux__
    result["worker"]["security_sandbox"]=true;
    result["worker"]["profile"]="linux-parser-bwrap-cgroup-v1";
    result["worker"]["memory_policy"]="768 MiB aggregate cgroup; swap disabled; 64 tasks; read-only scoped inputs; private output";
    result["worker"]["network"]=false;
#else
    result["worker"]["memory_policy"]="768 MiB per-process committed memory; no filesystem sandbox";
#endif
    const auto state=result.at("status").get<std::string>();
    return {state=="completed"?0:state=="partial"?3:state=="cancelled"?130:1,state,result.dump()};
#else
    (void)target;(void)request;(void)cancel_file;
    return {1,"failed",Json{{"status","failed"},{"diagnostic","Bundled ILSpy worker unavailable; run tools/build-ilspy.ps1 and rebuild"}}.dump()};
#endif
}
}
