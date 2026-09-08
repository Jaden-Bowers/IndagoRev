#include "indago/core.hpp"
#include "indago/ghidra.hpp"
#include "indago/runtime.hpp"
#include <nlohmann/json.hpp>
#include <thread>
#include <chrono>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#endif

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace indago {
namespace {

std::string shell_quote(const fs::path& path) {
    const auto value = path.string();
#ifndef _WIN32
    std::string result="'";for(char c:value)result+=c=='\''?"'\\''":std::string(1,c);return result+"'";
#else
    if (value.find_first_of("\"%!\r\n") != std::string::npos) throw std::runtime_error("path contains unsupported shell characters");
    return "\"" + value + "\"";
#endif
}

std::string read_all(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

} // namespace

std::optional<fs::path> find_ghidra_headless() {
#if INDAGO_HAS_GHIDRA
    const auto root=bundled_engines("ghidra")/"ghidra"/"distribution"/"support";
#ifdef _WIN32
    return root/"analyzeHeadless.bat";
#else
    return root/"analyzeHeadless";
#endif
#endif
    if (const char* configured = std::getenv("INDAGO_GHIDRA_HEADLESS")) {
        fs::path value(configured);
        if (fs::is_regular_file(value)) return fs::absolute(value);
    }
    if (const char* home = std::getenv("GHIDRA_HOME")) {
#ifdef _WIN32
        fs::path value = fs::path(home) / "support" / "analyzeHeadless.bat";
#else
        fs::path value = fs::path(home) / "support" / "analyzeHeadless";
#endif
        if (fs::is_regular_file(value)) return fs::absolute(value);
    }
    const fs::path known = fs::path(INDAGO_SOURCE_ROOT).parent_path() / "IR" / "kb" /
        "ghidra_12.1.2_PUBLIC" / "support";
#ifdef _WIN32
    const auto executable = known / "analyzeHeadless.bat";
#else
    const auto executable = known / "analyzeHeadless";
#endif
    if (fs::is_regular_file(executable)) return fs::absolute(executable);
    return std::nullopt;
}

namespace {
fs::path ghidra_scripts(){
#if INDAGO_HAS_GHIDRA
    return bundled_engines("ghidra")/"ghidra"/"scripts";
#endif
    if(const auto* configured=std::getenv("INDAGO_GHIDRA_SCRIPTS")){fs::path dir=configured;if(fs::is_regular_file(dir/"IndagoSession.java"))return fs::absolute(dir);throw std::runtime_error("INDAGO_GHIDRA_SCRIPTS lacks IndagoSession.java");}
    fs::path executable;
#ifdef _WIN32
    std::wstring path(32768,L'\0');auto n=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));if(n&&n<path.size()){path.resize(n);executable=path;}
#else
    std::error_code ec;executable=fs::read_symlink("/proc/self/exe",ec);
#endif
    for(const auto& dir:{executable.parent_path()/".."/"workers"/"ghidra"/"scripts",fs::path(INDAGO_SOURCE_ROOT)/"workers"/"ghidra"/"scripts"})if(fs::is_regular_file(dir/"IndagoSession.java"))return fs::absolute(dir).lexically_normal();
    throw std::runtime_error("Ghidra worker script not installed");
}
bool session_alive(const fs::path& ready) {
    if (!fs::exists(ready)) return false;
    unsigned long pid=0; std::ifstream(ready) >> pid; if (!pid) return false;
#ifdef _WIN32
    HANDLE process=OpenProcess(SYNCHRONIZE,FALSE,pid);
    if(!process)return false; bool alive=WaitForSingleObject(process,0)==WAIT_TIMEOUT;CloseHandle(process);return alive;
#else
    return kill(static_cast<pid_t>(pid),0)==0;
#endif
}
struct Startup {
#ifdef _WIN32
    HANDLE job{}, process{};
    ~Startup(){if(job)CloseHandle(job);if(process)CloseHandle(process);}
    void stop(){if(job)TerminateJobObject(job,1);}
    bool exited(){return process && WaitForSingleObject(process,0)!=WAIT_TIMEOUT;}
#else
    pid_t pid{};bool finished{};
    void stop(){if(pid>0)kill(-pid,SIGKILL);}
    bool exited(){if(finished)return true;if(pid<=0)return false;int status{};if(waitpid(pid,&status,WNOHANG)==pid){pid=0;finished=true;}return finished;}
#endif
};
void launch_session(const fs::path& executable,const fs::path& project,const fs::path& object,const fs::path& mailbox,std::uint64_t seconds,Startup& startup,const std::string& profile) {
    auto scripts=ghidra_scripts();
    std::ostringstream c;
#if INDAGO_HAS_GHIDRA
    auto private_root=executable.parent_path().parent_path().parent_path();
#ifdef _WIN32
    auto java=private_root/"java"/"bin"/"java.exe";
#else
    auto java=private_root/"java"/"bin"/"java";
#endif
    c<<shell_quote(java)<<" -Djava.system.class.loader=ghidra.GhidraClassLoader -Dfile.encoding=UTF-8 -Djava.awt.headless=true --enable-native-access=ALL-UNNAMED -Xmx2G -cp "<<shell_quote(private_root/"distribution"/"Ghidra"/"Framework"/"Utility"/"lib"/"Utility.jar")<<" ghidra.Ghidra ghidra.app.util.headless.AnalyzeHeadless ";
#elif defined(_WIN32)
    c << "cmd.exe /d /c call " << shell_quote(executable) << ' ';
#else
    c << shell_quote(executable) << ' ';
#endif
    const auto launcher=c.str();
    // A killed import can leave only the project shell. Retry import only when
    // a previous native startup explicitly reported this exact Program absent.
    // No -overwrite is used, so an existing saved Program is never replaced.
    const auto missing_program="Requested project program file(s) not found: "+object.filename().string();
    const bool retry_import=fs::exists(mailbox/"needs-import")||
        read_all(mailbox/"worker.log").find(missing_program)!=std::string::npos;
    const bool reopen=fs::exists(project/"indago.gpr")&&!retry_import;
    c << shell_quote(project) << " indago " << (reopen?"-process ":"-import ") << shell_quote(reopen?object.filename():object);
    // ELF PIE images otherwise receive Ghidra's synthetic default base. Use
    // the loader's own option so native Ghidra and file-VA/RVA locations agree.
    try {
        auto image=runtime_image(object);
        if(image["format"]=="ELF") {
            auto base=UINT64_MAX;
            for(const auto& segment:image["segments"]) base=std::min(base,runtime_number(segment["va"]));
            // Ghidra's ELF preferred base is the lowest load VA, not its
            // page-aligned runtime mapping. They differ for captured regions.
            c<<" -loader-imagebase "<<hex_address(base);
        }
    }catch(const std::exception&){}
    c << " -analysisTimeoutPerFile " << seconds;
    if(reopen||profile=="inventory")c<<" -noanalysis";
    if(!reopen) {
        // An imported Program is transient/read-only until headless saves it.
        // Finish import first, then open the saved Program for the persistent worker.
        const auto import_command=c.str();c.str("");c.clear();
        c<<import_command<<" && "<<launcher<<shell_quote(project)<<" indago -process "<<shell_quote(object.filename())<<" -noanalysis";
    }
    c << " -scriptPath " << shell_quote(scripts) << " -postScript IndagoSession.java " << shell_quote(mailbox);
#ifdef _WIN32
    std::string command=reopen?c.str():"cmd.exe /d /s /c \""+c.str()+"\"";STARTUPINFOEXA si{};si.StartupInfo.cb=sizeof(si);PROCESS_INFORMATION pi{};
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};
    HANDLE log=CreateFileW((mailbox/"worker.log").c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,&security,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(log==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot open Ghidra log");
    HANDLE input=CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&security,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    si.StartupInfo.dwFlags=STARTF_USESTDHANDLES;si.StartupInfo.hStdOutput=log;si.StartupInfo.hStdError=log;si.StartupInfo.hStdInput=input;
    SIZE_T attributeSize=0;InitializeProcThreadAttributeList(nullptr,1,0,&attributeSize);
    std::vector<unsigned char> attributes(attributeSize);si.lpAttributeList=reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
    HANDLE inherited[]{log,input};
    if(!InitializeProcThreadAttributeList(si.lpAttributeList,1,0,&attributeSize)||!UpdateProcThreadAttribute(si.lpAttributeList,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited,sizeof(inherited),nullptr,nullptr)){CloseHandle(log);CloseHandle(input);throw std::runtime_error("Cannot restrict Ghidra handle inheritance");}
    startup.job=CreateJobObjectA(nullptr,nullptr);
    if(!startup.job)throw std::runtime_error("Cannot create Ghidra job");
    bool created=CreateProcessA(nullptr,command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|CREATE_NEW_PROCESS_GROUP|CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT,nullptr,nullptr,&si.StartupInfo,&pi)!=0;DeleteProcThreadAttributeList(si.lpAttributeList);CloseHandle(log);CloseHandle(input);
    if(!created)throw std::runtime_error("Cannot launch Ghidra session: "+std::to_string(GetLastError()));
    startup.process=pi.hProcess;
    if(!AssignProcessToJobObject(startup.job,pi.hProcess)){TerminateProcess(pi.hProcess,1);CloseHandle(pi.hThread);throw std::runtime_error("Cannot assign Ghidra process job");}
    ResumeThread(pi.hThread);CloseHandle(pi.hThread);
#else
    pid_t pid=fork();if(pid<0)throw std::runtime_error("Cannot fork Ghidra session");
    if(pid==0){
        setsid();
        // Redirect the shell itself, not just its Java child. Otherwise a
        // persistent session holds command-substitution/pipeline stdout open.
        int sink=open("/dev/null",O_RDONLY);
        int log=open((mailbox/"worker.log").c_str(),O_WRONLY|O_CREAT|O_TRUNC,0600);
        if(sink<0||log<0)_exit(127);
        dup2(sink,STDIN_FILENO);dup2(log,STDOUT_FILENO);dup2(log,STDERR_FILENO);
        if(sink>2)close(sink);if(log>2)close(log);
        execl("/bin/sh","sh","-c",c.str().c_str(),nullptr);_exit(127);
    }
    startup.pid=pid;
#endif
}
}
CommandResult query_ghidra(const TargetRecord& target,const ProjectStore& store,const GhidraOptions& options) {
    using nlohmann::json;
    auto failure=[](std::string status,std::string diagnostic){return CommandResult{1,status,json{{"schema","indago.ghidra-result.v2"},{"backend","ghidra"},{"status",status},{"diagnostic",diagnostic}}.dump()};};
    auto executable=find_ghidra_headless();if(!executable)return failure("unavailable","Set GHIDRA_HOME or INDAGO_GHIDRA_HEADLESS");
    if(options.max_output_bytes<512||options.max_output_bytes>64*1024*1024||options.max_items<1||options.max_items>100000||options.timeout_ms<1||options.timeout_ms>3600000)return failure("failed","Invalid bounds (output 512..67108864, items 1..100000, timeout_ms 1..3600000)");
    const auto script=ghidra_scripts()/"IndagoSession.java";
    const auto properties=executable->parent_path().parent_path()/"Ghidra"/"application.properties";
    const auto profile=options.arguments.value("profile",std::string("standard"));
    if(profile!="standard"&&profile!="inventory")return failure("failed","profile must be standard or inventory");
    std::string scripts_hash;std::vector<fs::path> script_paths;
    for(const auto& entry:fs::directory_iterator(script.parent_path()))if(entry.path().extension()==".java")script_paths.push_back(entry.path());
    std::sort(script_paths.begin(),script_paths.end());for(const auto& path:script_paths)scripts_hash+=path.filename().string()+sha256_file(path);
    const auto identity=sha256_text(scripts_hash+executable->string()).substr(0,16)+"-"+sha256_file(fs::exists(properties)?properties:*executable).substr(0,12)+"-file-base-v3-"+profile;
    // Keep mailbox filenames below legacy Windows path limits; full identity
    // is still carried in each request and result.
    auto dir=fs::absolute(store.root()/"workers"/("gh-"+sha256_text(target.sha256+identity).substr(0,32)));fs::create_directories(dir/"project");
    auto project_dir=dir/"project";
    // Ghidra disallows dot-prefixed components in its project path, including
    // the CLI's default .indago and Linux .cache. Keep only disposable engine
    // project state in a clean temporary path; evidence stays in the workspace.
    for(const auto& part:project_dir)if(part.string().starts_with(".")){
        project_dir=fs::temp_directory_path()/"indago-ghidra-projects"/sha256_text(dir.string());break;
    }
    // TMPDIR itself may be under .cache. Do not repeat the invalid relocation.
#ifndef _WIN32
    for(const auto& part:project_dir)if(part.string().starts_with(".")){
        project_dir=fs::path("/tmp")/"indago-ghidra-projects"/sha256_text(dir.string());break;
    }
#endif
    fs::create_directories(project_dir);
    auto deadline=std::chrono::steady_clock::now()+std::chrono::milliseconds(options.timeout_ms);
    auto cancelled=[&]{return !options.cancel_file.empty()&&fs::exists(options.cancel_file);};
    // Directory creation is an interprocess startup lock. Existing live workers serve many CLI clients.
    if(!session_alive(dir/"ready")) {
        // Recover only a dead startup owner's exact marker and empty lock directory.
        std::error_code lock_ec;
        auto lock=dir/"starting",owner_file=lock/"owner";
        if(fs::exists(lock)) {
            bool stale=fs::exists(owner_file)?!session_alive(owner_file):fs::file_time_type::clock::now()-fs::last_write_time(lock)>std::chrono::seconds(60);
            if(stale){fs::remove(owner_file,lock_ec);fs::remove(lock,lock_ec);}
        }
        Startup startup;std::error_code ec;bool owner=fs::create_directory(dir/"starting",ec);
        if(owner){
#ifdef _WIN32
            atomic_write(owner_file,std::to_string(GetCurrentProcessId()));
#else
            atomic_write(owner_file,std::to_string(getpid()));
#endif
            try{fs::remove(dir/"ready",ec);fs::remove(dir/"stop",ec);launch_session(*executable,project_dir,target.object_path,dir,std::max<std::uint64_t>(1,options.timeout_ms/1000),startup,profile);}catch(...){fs::remove(owner_file,ec);fs::remove(dir/"starting",ec);throw;}}
        while(!session_alive(dir/"ready")) {
            if(cancelled()){if(owner){startup.stop();fs::remove(owner_file,ec);fs::remove(dir/"starting",ec);}return failure("cancelled","Cancelled Ghidra import process tree");}
            if((owner&&startup.exited())||std::chrono::steady_clock::now()>=deadline){bool failed=owner&&startup.exited();if(owner){startup.stop();fs::remove(owner_file,ec);fs::remove(dir/"starting",ec);}auto log=read_all(dir/"worker.log");if(owner&&log.find("Requested project program file(s) not found: "+target.object_path.filename().string())!=std::string::npos)atomic_write(dir/"needs-import",target.sha256);if(log.size()>8192)log=log.substr(log.size()-8192);return failure(failed?"failed":"timeout","Ghidra session did not become ready: "+log);}
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }if(owner){fs::remove(dir/"needs-import",ec);fs::remove(owner_file,ec);fs::remove(dir/"starting",ec);}
    }
    const auto id=make_id("request");auto response=dir/(id+".response");
    auto remaining=std::chrono::duration_cast<std::chrono::milliseconds>(deadline-std::chrono::steady_clock::now()).count();
    if(remaining<=0)return failure("timeout","Budget exhausted during import");
    atomic_write(dir/(id+".request"),json{{"operation",options.operation},{"address",options.address},{"arguments",options.arguments},{"session_key",identity},{"max_items",options.max_items},{"max_output_bytes",std::max<std::uint64_t>(512,options.max_output_bytes>2048?options.max_output_bytes-2048:512)},{"timeout_ms",remaining}}.dump());
    while(!fs::exists(response)) {
        if(cancelled()||std::chrono::steady_clock::now()>=deadline){atomic_write(dir/(id+".cancel"),"cancel");return failure(cancelled()?"cancelled":"timeout","Ghidra request cancellation signalled");}
        if(!session_alive(dir/"ready"))return failure("failed","Ghidra session exited");
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }
    if(fs::file_size(response)>options.max_output_bytes)return failure("failed","Worker exceeded output bound");
    auto raw=read_all(response);auto result=json::parse(raw);std::string status=result.value("status","failed");
    if(result.contains("program")&&result["program"].value("executable_sha256",std::string{})!=target.sha256)return failure("failed","Ghidra Program SHA-256 does not match imported target");
    if(options.max_output_bytes>=1024){result["provenance"]={{"script_sha256",sha256_file(script)},{"engine_properties_sha256",sha256_file(fs::exists(properties)?properties:*executable)},{"session_key",identity},{"loader_policy","file-preferred-imagebase.v2: minimum ELF load VA"}};raw=result.dump();}
    std::error_code ec;fs::remove(response,ec);fs::remove(dir/(id+".cancel"),ec);
    return {status=="completed"?0:status=="partial"?3:1,status,raw};
}
CommandResult analyze_ghidra(const TargetRecord& target,const ProjectStore& store,std::uint64_t seconds) {
    GhidraOptions options;options.timeout_ms=seconds*1000;return query_ghidra(target,store,options);
}
} // namespace indago
