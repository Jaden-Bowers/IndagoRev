#include "indago/airece.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <set>
#include <stdexcept>
#include <thread>
#include <charconv>
#include <mutex>
#include <sstream>
#include <nlohmann/json.hpp>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#endif

namespace indago {
namespace {
using Json = nlohmann::json;
std::string dump(const Json& value) {
    return value.dump(-1, ' ', false, Json::error_handler_t::replace);
}
std::uint64_t unsigned_option(const std::string& value) {
    std::uint64_t number{};
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), number);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() || number == 0)
        throw std::runtime_error("AIRECE resource limits must be positive decimal integers");
    return number;
}
Json structured_text(const std::string& operation, const std::string& output) {
    Json result = Json::object();
    std::istringstream lines(output);
    std::string line;
    if (operation == "functions") {
        result["functions"] = Json::array();
        while (std::getline(lines, line)) {
            std::istringstream fields(line); std::string address, name, field;
            if (!(fields >> address >> name) || !address.starts_with("0x")) continue;
            Json function{{"address", address}, {"entry", address}, {"name", name}};
            while (fields >> field) {
                auto separator = field.find('='); if (separator == std::string::npos) continue;
                auto key = field.substr(0, separator), value = field.substr(separator + 1);
                if (key == "blocks" || key == "calls") {
                    std::uint64_t number{}; auto parsed = std::from_chars(value.data(), value.data()+value.size(),number);
                    if (parsed.ec == std::errc{}) function[key] = number;
                } else function[key] = value;
            }
            result["functions"].push_back(std::move(function));
        }
    } else if (operation == "inspect") {
        std::string section;
        while (std::getline(lines, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            auto separator = line.find(':'); if (separator == std::string::npos) continue;
            auto start = line.find_first_not_of(' '); if (start == std::string::npos) continue;
            auto key = line.substr(start, separator - start);
            auto value_at = line.find_first_not_of(' ', separator + 1);
            if (value_at == std::string::npos) { section = key; continue; }
            auto value = line.substr(value_at);
            Json parsed = value;
            if (key == "segments" || key == "symbols" || key == "functions" || key == "blocks" || key == "edges" || key == "calls" || key == "skipped" || key == "unresolved-indirects") {
                std::uint64_t number{}; const auto converted = std::from_chars(value.data(), value.data()+value.size(),number);
                if (converted.ec == std::errc{}) parsed = number;
            }
            if (key == "arch") key = "architecture";
            if (key == "image-base") key = "image_base";
            if (start > 0 && section == "cfg" && (key == "blocks" || key == "edges" || key == "calls")) result["cfg"][key] = parsed;
            else result[key] = parsed;
        }
    }
    return result;
}

std::uint64_t remaining_ms(const NativeProcessOptions& requested, std::chrono::steady_clock::time_point started) {
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now()-started).count();
    return static_cast<std::uint64_t>(elapsed) >= requested.wall_time_ms ? 0 : requested.wall_time_ms-static_cast<std::uint64_t>(elapsed);
}
Json provenance(const fs::path& executable, const NativeProcessOptions& requested,
                std::chrono::steady_clock::time_point started, bool embedded) {
    // Cache by content digest, so replacing a worker cannot inherit stale provenance.
    const auto digest = sha256_file(executable);
    static std::mutex mutex;
    static std::map<std::string, std::string> versions;
    std::lock_guard<std::mutex> lock(mutex);
    auto found = versions.find(digest);
    std::string diagnostic;
    const auto available_ms = remaining_ms(requested,started);
    if (found == versions.end() && available_ms > 0) {
        NativeProcessOptions options = requested;
        options.wall_time_ms = std::min<std::uint64_t>(available_ms, 2000);
        options.max_output_bytes = 4096;
        auto version = run_native_process(executable, embedded ? std::vector<std::string>{"__airece","--version"} : std::vector<std::string>{"--version"}, options);
        if (version.exit_code == 0 && !version.truncated) found = versions.emplace(digest, version.output).first;
        else diagnostic = version.timed_out ? "version probe exhausted its deadline" : version.cancelled ? "version probe cancelled" : "version probe failed or exceeded output bound";
    }
    if (found == versions.end() && diagnostic.empty()) diagnostic = "operation deadline exhausted before version probe";
    Json result{{"executable", executable.string()}, {"executable_sha256", digest},
        {"version", found == versions.end() ? "unavailable" : found->second}};
    if (!diagnostic.empty()) result["diagnostic"] = diagnostic;
    return result;
}

std::string bounded_envelope(Json& envelope, std::size_t limit, std::string& status) {
    auto serialized = dump(envelope);
    if (serialized.size() <= limit) return serialized;
    envelope["truncated"] = true;
    if (status == "complete") status = "partial";
    envelope["status"] = status;
    envelope["omitted"] = Json::array();
    // Parsed semantics and raw text duplicate information. Prefer parsed semantics.
    if (envelope.contains("native") && envelope.contains("native_output")) {
        envelope.erase("native_output"); envelope["omitted"].push_back("native_output");
    }
    serialized = dump(envelope); if (serialized.size() <= limit) return serialized;
    if (envelope.contains("native")) {
        // Never return a modified object masquerading as the complete native result.
        envelope.erase("native"); envelope["omitted"].push_back("native");
    }
    for (const auto* field : {"native_output", "native_diagnostics"}) {
        if (!envelope.contains(field)) continue;
        const auto original = envelope[field].get<std::string>();
        envelope["omitted"].push_back(field);
        std::size_t low=0, high=original.size();
        while (low < high) {
            auto mid = low + (high-low+1)/2; envelope[field] = original.substr(0,mid);
            if (dump(envelope).size() <= limit) low = mid; else high = mid-1;
        }
        envelope[field] = original.substr(0,low);
        serialized = dump(envelope); if (serialized.size() <= limit) return serialized;
    }
    if (envelope.contains("provenance")) {
        envelope["provenance"].erase("executable");
        envelope["provenance"]["version"] = envelope["provenance"]["version"].get<std::string>().substr(0,80);
        envelope["omitted"].push_back("provenance_detail");
    }
    serialized = dump(envelope); if (serialized.size() <= limit) return serialized;
    // Extreme input metadata also cannot exceed the caller's envelope budget.
    Json minimum{{"schema","indago.airece.v1"},{"backend","airece"},{"status",status},
        {"truncated",true},{"native_exit_code",envelope["native_exit_code"]},
        {"omitted",Json::array({"payload","metadata"})}, {"provenance",{{"executable_sha256",envelope["provenance"]["executable_sha256"]},
        {"version",envelope["provenance"]["version"]}}}};
    return dump(minimum);
}

void append_bounded(std::string& target, const char* bytes, std::size_t size,
                    std::size_t limit, bool& truncated) {
    const auto keep = std::min(size, limit - std::min(limit, target.size()));
    target.append(bytes, keep);
    truncated |= keep != size;
}
bool cancelled(const NativeProcessOptions& o) {
    if (o.should_cancel && o.should_cancel()) return true;
    std::error_code ec;
    return !o.cancel_file.empty() && fs::exists(o.cancel_file, ec);
}
#ifdef _WIN32
struct Handle {
    HANDLE h{};
    ~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};
std::wstring argument(const std::wstring& s) {
    std::wstring result = L"\"";
    unsigned slashes = 0;
    for (wchar_t c : s) {
        if (c == L'\\') { ++slashes; continue; }
        result.append(c == L'"' ? slashes * 2 + 1 : slashes, L'\\');
        result += c; slashes = 0;
    }
    result.append(slashes * 2, L'\\');
    return result + L'"';
}
std::wstring utf16(const std::string& s) {
    int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (!size && !s.empty()) throw std::runtime_error("Invalid UTF-8 worker argument");
    std::wstring out(size, L' ');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), size);
    return out;
}
#endif
}

NativeProcessResult run_native_process(const fs::path& executable,
        const std::vector<std::string>& arguments, const NativeProcessOptions& options) {
    NativeProcessResult result;
    if (!options.wall_time_ms || !options.max_output_bytes) throw std::runtime_error("Worker bounds must be positive");
    if (cancelled(options)) { result.cancelled = true; return result; }
    const auto started = std::chrono::steady_clock::now();
#ifdef _WIN32
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    Handle reader, writer, err_reader, err_writer, job;
    if (!CreatePipe(&reader.h, &writer.h, &security, 0) ||
        !CreatePipe(&err_reader.h, &err_writer.h, &security, 0)) throw std::runtime_error("Cannot create worker pipes");
    SetHandleInformation(reader.h, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(err_reader.h, HANDLE_FLAG_INHERIT, 0);
    job.h = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job.h || !SetInformationJobObject(job.h, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
        throw std::runtime_error("Cannot configure worker process tree");
    std::wstring command = argument(executable.wstring());
    for (const auto& value : arguments) command += L" " + argument(utf16(value));
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = writer.h; startup.hStdError = err_writer.h;
    Handle null_input; null_input.h = CreateFileW(options.stdin_file.empty()?L"NUL":options.stdin_file.c_str(), GENERIC_READ,
        FILE_SHARE_READ, &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if(null_input.h==INVALID_HANDLE_VALUE)throw std::runtime_error("Cannot open worker stdin");
    startup.hStdInput = null_input.h;
    PROCESS_INFORMATION info{};
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, options.working_directory.empty()?nullptr:options.working_directory.c_str(), &startup, &info))
        throw std::runtime_error("Cannot start worker: " + std::to_string(GetLastError()));
    Handle process{info.hProcess}, thread{info.hThread};
    if (!AssignProcessToJobObject(job.h, process.h)) {
        TerminateProcess(process.h, 1); throw std::runtime_error("Cannot isolate worker process tree");
    }
    ResumeThread(thread.h);
    CloseHandle(writer.h); writer.h = nullptr;
    CloseHandle(err_writer.h); err_writer.h = nullptr;
    auto drain = [&](HANDLE pipe, std::string& out) {
        char buffer[8192]; DWORD available{}, count{};
        // Bound each drain too: continuously writing workers cannot starve cancellation.
        for (unsigned n = 0; n < 16 && PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr) && available; ++n) {
            if (!ReadFile(pipe, buffer, std::min<DWORD>(available, sizeof(buffer)), &count, nullptr) || !count) break;
            append_bounded(out, buffer, count, options.max_output_bytes, result.truncated);
        }
    };
    for (;;) {
        drain(reader.h, result.output); drain(err_reader.h, result.error);
        if (WaitForSingleObject(process.h, 5) == WAIT_OBJECT_0) break;
        result.cancelled = cancelled(options);
        result.timed_out = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count() >= options.wall_time_ms;
        if (result.cancelled || result.timed_out) { TerminateJobObject(job.h, 124); WaitForSingleObject(process.h, 5000); break; }
    }
    drain(reader.h, result.output); drain(err_reader.h, result.error);
    auto eof=[](HANDLE pipe){DWORD available{};return !PeekNamedPipe(pipe,nullptr,0,nullptr,&available,nullptr)&&GetLastError()==ERROR_BROKEN_PIPE;};
    result.output_complete=eof(reader.h)&&eof(err_reader.h);
    DWORD code{}; GetExitCodeProcess(process.h, &code); result.exit_code = static_cast<int>(code);
#else
    int out[2], err[2];
    if (pipe(out) || pipe(err)) throw std::runtime_error("Cannot create worker pipes");
    const auto parent_pid = getpid();
    const pid_t pid = fork();
    if (pid == 0) {
#ifdef __linux__
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent_pid) _exit(126);
#endif
        setpgid(0, 0); dup2(out[1], STDOUT_FILENO); dup2(err[1], STDERR_FILENO);
        const int input=open(options.stdin_file.empty()?"/dev/null":options.stdin_file.c_str(),O_RDONLY);
        if(input<0||dup2(input,STDIN_FILENO)<0)_exit(126);
        close(input);
        if(!options.working_directory.empty()&&chdir(options.working_directory.c_str())!=0)_exit(126);
        close(out[0]); close(out[1]); close(err[0]); close(err[1]);
        std::string exe = executable.string();
        std::vector<char*> argv{exe.data()};
        for (const auto& a : arguments) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr); execv(exe.c_str(), argv.data()); _exit(127);
    }
    close(out[1]); close(err[1]);
    if (pid < 0) { close(out[0]); close(err[0]); throw std::runtime_error("Cannot fork worker"); }
    setpgid(pid, pid); fcntl(out[0], F_SETFL, O_NONBLOCK); fcntl(err[0], F_SETFL, O_NONBLOCK);
    auto drain = [&](int fd, std::string& target) {
        char buffer[8192];
        for (unsigned n = 0; n < 16; ++n) {
            auto count = read(fd, buffer, sizeof(buffer)); if (count <= 0) return count==0;
            append_bounded(target, buffer, static_cast<std::size_t>(count), options.max_output_bytes, result.truncated);
        }
        return false;
    };
    int status{};
    for (;;) {
        drain(out[0], result.output); drain(err[0], result.error);
        if (waitpid(pid, &status, WNOHANG) == pid) break;
        result.cancelled = cancelled(options);
        result.timed_out = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count() >= options.wall_time_ms;
        if (result.cancelled || result.timed_out) { kill(-pid, SIGKILL); waitpid(pid, &status, 0); break; }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    const bool output_eof=drain(out[0], result.output),error_eof=drain(err[0], result.error);
    result.output_complete=output_eof&&error_eof;
    close(out[0]); close(err[0]);
    kill(-pid, SIGKILL);
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
#endif
    return result;
}

std::optional<fs::path> find_airece() {
#if !INDAGO_HAS_XAIR
    return std::nullopt;
#else
    return find_native_worker();
#endif
}
std::optional<fs::path> find_native_worker() {
#ifdef _WIN32
    constexpr auto name = "indago.exe";
#else
    constexpr auto name = "indago";
#endif
    std::vector<fs::path> roots;
#ifdef _WIN32
    std::wstring executable_path(32768,L'\0');
    const auto length=GetModuleFileNameW(nullptr,executable_path.data(),static_cast<DWORD>(executable_path.size()));
    if (length && length < executable_path.size()) { executable_path.resize(length); roots.push_back(fs::path(executable_path).parent_path()); }
#else
    std::error_code executable_error;
    const auto executable_path=fs::read_symlink("/proc/self/exe",executable_error);
    if (!executable_error) roots.push_back(executable_path.parent_path());
#endif
    for (auto root : roots) {
        for (const auto& candidate : {root / name})
            if (fs::is_regular_file(candidate)) return fs::absolute(candidate);
    }
    return std::nullopt;
}

CommandResult run_airece(const TargetRecord& target, const AireceOptions& options) {
    const auto started = std::chrono::steady_clock::now();
    static const std::set<std::string> operations{"inspect", "functions", "function", "calls", "xrefs", "slice", "path", "flow", "taint", "evidence"};
    static const std::set<std::string> views{"compact", "agent", "pseudocode", "disassembly", "json"};
    if (!operations.contains(options.operation) || !views.contains(options.view)) throw std::runtime_error("Unsupported AIRECE operation or view");
    if (options.max_output_bytes < 1024) throw std::runtime_error("AIRECE JSON envelope requires max_output_bytes >= 1024");
    std::map<std::string,std::uint64_t> ceilings{
        {"max-wall-time-ms",options.wall_time_ms}, {"max-functions",4096}, {"max-blocks",65536},
        {"max-edges",262144}, {"max-ir-values",1000000}, {"max-input-bytes",256ULL*1024*1024},
        {"max-memory-bytes",2ULL*1024*1024*1024}, {"max-bytes",options.max_output_bytes},
        {"max-statements",512}, {"max-calls",512}, {"max-evidence",512}, {"max-expression-depth",64},
        {"max-expression-nodes",65536}, {"max-expression-tokens",65536}, {"max-expression-characters",65536},
        {"max-queries",4096}, {"max-states",65536}, {"max-paths",4096}, {"max-taint-bytes",1048576},
        {"max-symbolic-bytes",1048576}, {"symbolic-timeout-ms",std::min<std::uint64_t>(options.wall_time_ms,30000)}};
    static const std::set<std::string> selectors{"source","target","from","to"};
    static const std::set<std::string> flags{"no-ir","no-indirects","no-inline-loads","no-inline-single-use","symbolic","taint","calls"};
    for (const auto& [key,value] : options.arguments) {
        if (auto bound = ceilings.find(key); bound != ceilings.end()) {
            if (unsigned_option(value) > bound->second) throw std::runtime_error("AIRECE option exceeds worker bound: " + key);
        } else if (selectors.contains(key)) {
            if (value.empty()) throw std::runtime_error("Empty AIRECE selector: " + key);
        } else if (flags.contains(key)) {
            if (!value.empty()) throw std::runtime_error("AIRECE flag does not take a value: " + key);
        } else if (key == "profile") {
            if (value != "fast" && value != "balanced" && value != "exhaustive") throw std::runtime_error("Invalid AIRECE profile");
        } else if (key == "mode") {
            if (value != "taint" && value != "taint-symbolic" && value != "symbolic") throw std::runtime_error("Invalid AIRECE flow mode");
        } else if (key == "function-depth" || key == "offset") {
            std::uint64_t number{}; auto parsed=std::from_chars(value.data(),value.data()+value.size(),number);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data()+value.size() || number > (key == "function-depth" ? 16ULL : 1000000ULL))
                throw std::runtime_error("Invalid bounded AIRECE option: " + key);
        } else throw std::runtime_error("Unknown AIRECE option: " + key);
    }
    for (const auto& [key,value] : options.repeated_arguments)
        if (options.operation != "flow" || (key != "source" && key != "target") || value.empty())
            throw std::runtime_error("Only flow source/target selectors may repeat");
    auto exe = options.executable.empty() ? find_airece() : std::optional<fs::path>(options.executable);
    if (!exe) return {1, "unavailable", "{\"backend\":\"airece\",\"status\":\"unavailable\",\"error\":\"Integrated indago analysis executable unavailable\"}"};
    std::vector<std::string> args{options.operation == "function" ? "fn" : options.operation, target.object_path.string()};
    if (!options.address.empty()) args.push_back(options.address);
    if (options.operation == "function") {
        args.insert(args.end(), {"--view", options.view == "pseudocode" ? "pseudo" : options.view,
            "--max-bytes", std::to_string(options.max_output_bytes), "--max-statements", "512", "--max-evidence", "512"});
    }
    if (options.operation == "flow") args.push_back("--json");
    args.insert(args.end(), {"--max-wall-time-ms", std::to_string(options.wall_time_ms), "--max-functions", "4096", "--max-blocks", "65536", "--max-edges", "262144", "--max-ir-values", "1000000", "--max-input-bytes", "268435456", "--max-memory-bytes", "2147483648"});
    for (const auto& [key, value] : options.arguments) {
        if (key.empty() || key.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-") != std::string::npos)
            throw std::runtime_error("Invalid AIRECE option name");
        args.push_back("--" + key); if (!value.empty()) args.push_back(value);
    }
    for (const auto& [key,value] : options.repeated_arguments) args.insert(args.end(),{"--" + key,value});
    const bool embedded = options.executable.empty();
    if(embedded) args.insert(args.begin(),"__airece");
    const auto worker_provenance = provenance(*exe, options, started, embedded);
    NativeProcessResult native;
    NativeProcessOptions remaining = options;
    remaining.wall_time_ms = remaining_ms(options,started);
    if (cancelled(options)) native.cancelled=true;
    else if (remaining.wall_time_ms == 0) {
        native.timed_out=true; native.error="Operation deadline exhausted during worker provenance collection";
    } else native = run_native_process(*exe,args,remaining);
    std::string status = native.cancelled ? "cancelled" : native.timed_out ? "timeout" :
        native.exit_code != 0 && native.exit_code != 3 ? "failed" : native.truncated || native.exit_code == 3 ? "partial" : "complete";
    const bool json_native = options.operation == "flow" || (options.operation == "function" && (options.view == "agent" || options.view == "json"));
    nlohmann::json envelope{{"schema", "indago.airece.v1"}, {"backend", "airece"},
        {"operation", options.operation}, {"view", options.view}, {"status", status},
        {"target_id", target.id}, {"target_sha256", target.sha256},
        {"native_exit_code", native.exit_code}, {"truncated", native.truncated},
        {"native_format", json_native ? "json" : "text"}, {"native_output", native.output},
        {"native_diagnostics", native.error},
        {"provenance",worker_provenance},
        {"locations", nlohmann::json::array({{{"target_id", target.id}, {"artifact_sha256",target.sha256}, {"address_space","program"}, {"address", options.address}}})},
        {"semantics", "backend-native; verdicts and source mappings retained verbatim"}};
    if (json_native && !native.truncated) {
        auto parsed = nlohmann::json::parse(native.output, nullptr, false);
        if (!parsed.is_discarded() && parsed.is_object()) envelope["native"] = std::move(parsed);
        else if (!native.cancelled && !native.timed_out) {
            status = "failed"; envelope["status"] = status; envelope["protocol_error"] = "Worker returned invalid native JSON";
        }
    } else if (options.operation == "inspect" || options.operation == "functions") {
        envelope["native"] = structured_text(options.operation,native.output);
    }
    auto serialized = bounded_envelope(envelope,options.max_output_bytes,status);
    return {status == "complete" ? 0 : status == "partial" ? 3 : 1, status,std::move(serialized)};
}
}
