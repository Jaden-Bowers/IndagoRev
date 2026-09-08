#include "indago/replay.hpp"
#include "indago/airece.hpp"
#include "rr_trace.hpp"
#include <chrono>
#include <fstream>
#ifndef _WIN32
#include <sys/resource.h>
#include <unistd.h>
#endif
namespace indago {
using J=RuntimeJson;
int rr_exec_worker(const J& request) {
#if defined(__linux__) && INDAGO_HAS_RR
    const auto engine=bundled_engines("replay")/"replay/bin/rr";
    auto operation=request.at("phase").get<std::string>();
    const fs::path trace=request.at("trace").get<std::string>(),scratch=request.at("scratch").get<std::string>();
    replay::unlinked_path(trace);replay::unlinked_path(scratch);
    std::vector<std::string> args{engine.string()};
    if(operation=="record") {
        const fs::path file=request.at("file").get<std::string>();
        if(!file.is_absolute()||sha256_file(file)!=request.at("artifact_sha256").get<std::string>())throw std::runtime_error("rr launch image identity changed");
        args.insert(args.end(),{"record","-o",trace.string(),file.string()});
        for(const auto& a:request.value("argv",J::array()))args.push_back(a.get<std::string>());
        fs::current_path(request.value("cwd",file.parent_path().string()));
    } else if(operation=="replay")args.insert(args.end(),{"replay","-a",trace.string()});
    else if(operation=="pack"||operation=="traceinfo")args.insert(args.end(),{operation,trace.string()});
    else throw std::runtime_error("Unsupported private rr phase");
    // These settings apply only to rr and its tracees. They are resource guards,
    // not a sandbox. Do not leak build-time library paths or alter kernel policy.
    if(setenv("RR_TMPDIR",scratch.c_str(),1)||setenv("_RR_TRACE_DIR",scratch.c_str(),1))throw std::runtime_error("Cannot configure private rr scratch");
    struct rlimit core{0,0},file_limit{67108864,67108864};
    if(setrlimit(RLIMIT_CORE,&core)||setrlimit(RLIMIT_FSIZE,&file_limit))throw std::runtime_error("Cannot apply rr file/core limits");
    std::vector<char*> argv;for(auto& a:args)argv.push_back(a.data());argv.push_back(nullptr);
    execv(engine.c_str(),argv.data());throw std::runtime_error("Cannot execute bundled rr");
#else
    (void)request;throw std::runtime_error("rr requires a Linux build with the replay payload");
#endif
}
J run_rr_session(const fs::path& directory,const J& request,const std::function<bool()>& cancelled,const std::function<void(const J&)>& phase) {
    J result{{"backend","rr"},{"engine_version","5.9.0"},{"status","failed"},{"replay_ready",false},{"phases",J::array()},
        {"scope","bounded Linux user-space rr record/pack or autopilot replay; not universal coverage, a sandbox, or interactive reverse debugging"},
        {"limits",{{"max_files",1024},{"max_file_bytes",67108864},{"output_bytes_per_stream_per_phase",32768},{"trace_budget_enforcement","100ms polling; not an OS aggregate disk quota"}}}};
#if defined(__linux__) && INDAGO_HAS_RR
    std::string guard_failure;
    try {
        const auto wall=request.value("timeout_ms",std::uint64_t(10000)),budget=request.value("trace_bytes",std::uint64_t(67108864));
        if(!wall||wall>60000||budget<1048576||budget>134217728)throw std::runtime_error("Invalid replay bounds");
        result["limits"]["wall_ms"]=wall;result["limits"]["trace_bytes"]=budget;
        replay::unlinked_path(directory);fs::create_directories(directory);
        const bool recording=request.at("operation")=="record";
        const fs::path trace=recording?directory/"trace":fs::path(request.at("recorded_trace_directory").get<std::string>());
        if(recording&&fs::exists(trace))throw std::runtime_error("Refusing to overwrite an existing rr trace");
        if(fs::space(directory).available<21474836480ULL+budget)throw std::runtime_error("Replay storage floor requires 20 GiB plus trace budget");
        // Native Linux scratch is required: rr shared-memory resizing failed on
        // this host's /mnt/c filesystem. The persistent trace may remain there.
        char pattern[]="/tmp/indago-rr-XXXXXX";auto temp=mkdtemp(pattern);
        if(!temp)throw std::runtime_error("Cannot create native rr scratch");
        struct Scratch {fs::path path;~Scratch(){std::error_code e;fs::remove_all(path,e);}} scratch{temp};
        const auto worker=find_native_worker();if(!worker)throw std::runtime_error("Native rr launcher unavailable");
        const auto started=std::chrono::steady_clock::now();auto last_scan=started-std::chrono::seconds(1);
        auto elapsed=[&]{return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();};
        auto stop=[&] {
            try {if(cancelled())return true;}catch(const std::exception& e){guard_failure=e.what();return true;}
            if(!guard_failure.empty())return true;
            if(std::chrono::steady_clock::now()-last_scan>=std::chrono::milliseconds(100)) {
                last_scan=std::chrono::steady_clock::now();
                try {replay::trace_manifest(trace,budget,false);if(fs::space(directory).available<21474836480ULL)throw std::runtime_error("Replay storage floor reached");}
                catch(const std::exception& e){guard_failure=e.what();return true;}
            }
            return false;
        };
        auto run=[&](const std::string& name) {
            if(stop()){result["status"]=guard_failure.empty()?"cancelled":"partial";return false;}
            if(elapsed()>=static_cast<std::int64_t>(wall)){result["status"]="partial";result["timed_out"]=true;return false;}
            phase({{"phase",name},{"trace_directory",trace.string()}});
            J command{{"phase",name},{"trace",trace.string()},{"scratch",scratch.path.string()}};
            if(name=="record")for(const auto* key:{"file","artifact_sha256","cwd","argv"})if(request.contains(key))command[key]=request.at(key);
            const auto remaining=static_cast<std::int64_t>(wall)-elapsed();
            if(remaining<=0){result["status"]="partial";result["timed_out"]=true;return false;}
            NativeProcessOptions options;options.wall_time_ms=static_cast<std::uint64_t>(remaining);options.max_output_bytes=32768;options.should_cancel=stop;
            auto native=run_native_process(*worker,{"__rr_exec",command.dump()},options);
            J item{{"phase",name},{"native_exit_code",native.exit_code},{"timed_out",native.timed_out},{"cancelled",native.cancelled},{"output_truncated",native.truncated},
                {"stdout",native.output},{"stderr",native.error}};
            result["phases"].push_back(item);
            if(native.timed_out||!guard_failure.empty())result["status"]="partial";
            else if(native.cancelled)result["status"]="cancelled";
            else if(native.exit_code!=0)result["status"]="failed";
            else return true;
            return false;
        };
        if(!recording) {
            const auto manifest=replay::trace_manifest(trace,budget,true);
            if(manifest!=request.at("recorded_trace_manifest"))throw std::runtime_error("Recorded trace identity mismatch before replay");
            result["source_recording_session"]=request.at("recorded_session");result["trace_manifest_sha256"]=manifest.at("sha256");
        }
        bool ok=recording?run("record")&&run("pack")&&run("traceinfo"):run("replay");
        if(ok) {
            const auto manifest=replay::trace_manifest(trace,budget,true);
            if(recording) {
                const auto& native=result.at("phases").back();
                const auto info=J::parse(native.at("stdout").get<std::string>(),nullptr,false);
                if(native.at("output_truncated")==true||!info.is_object())throw std::runtime_error("rr traceinfo did not produce bounded complete JSON");
                result["native_traceinfo"]=info;result["trace_manifest"]=manifest;result["trace_directory"]=trace.string();
                result["replay_ready"]=true;
                atomic_write(directory/"trace-manifest.json",manifest.dump(2));
            } else if(manifest!=request.at("recorded_trace_manifest"))throw std::runtime_error("Recorded trace changed during replay");
            result["status"]="completed";
            for(const auto& p:result["phases"])if(p.at("output_truncated")==true){result["status"]="partial";result["output_incomplete"]=true;}
        }
        if(!guard_failure.empty())result["diagnostic"]=guard_failure;
        result["elapsed_ms"]=elapsed();
    } catch(const std::exception& e){result["status"]="failed";result["replay_ready"]=false;result["diagnostic"]=e.what();}
#else
    (void)directory;(void)request;(void)cancelled;(void)phase;
    result["diagnostic"]="rr requires a Linux build with the replay payload";
#endif
    return result;
}
}
