#include "analysis_helper.hpp"
#include "harness_artifact_read.hpp"
#include "harness_calculation.hpp"
#include "indago/airece.hpp"
#include "indago/runtime.hpp"
#include "isolated_worker.hpp"
#include <iostream>
#ifdef __linux__
#include <cstddef>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#if INDAGO_HAS_XAIR
#include <z3.h>
#endif
#endif

namespace indago {
using namespace wb;
namespace {
constexpr std::size_t output_limit = 4096;
bool plain_name(const std::string &name) {
  return !name.empty() && name.size() <= 64 &&
    name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") == name.npos;
}
J pin_page(J page) { page.erase("hex"); return page; }
std::string hex_bytes(const std::string &bytes) {
  const char *digits = "0123456789abcdef";
  std::string out;
  for (unsigned char c : bytes) {
    out += digits[c >> 4];
    out += digits[c & 15];
  }
  return out;
}
std::string unhex(const std::string &hex) {
  if (hex.size() % 2 || hex.find_first_not_of("0123456789abcdef") != hex.npos)
    throw std::runtime_error("invalid helper hex");
  std::string bytes;
  for (std::size_t i = 0; i < hex.size(); i += 2)
    bytes += static_cast<char>(std::stoul(hex.substr(i, 2), nullptr, 16));
  return bytes;
}
J receipt(const NativeProcessResult &r) {
  return {{"exit_code", r.exit_code},
          {"timed_out", r.timed_out},
          {"cancelled", r.cancelled},
          {"truncated", r.truncated},
          {"output_complete", r.output_complete},
          {"stdout_hex", hex_bytes(r.output)},
          {"stderr_hex", hex_bytes(r.error)},
          {"stdout_sha256", sha256_text(r.output)},
          {"stderr_sha256", sha256_text(r.error)}};
}
bool good(const J &r) {
  return r.at("exit_code") == 0 && !r.at("timed_out").get<bool>() &&
         !r.at("cancelled").get<bool>() && !r.at("truncated").get<bool>() &&
         r.at("output_complete").get<bool>();
}
void write_file(const fs::path &path, const std::string &bytes) {
  std::ofstream f(path, std::ios::binary | std::ios::trunc);
  f.write(bytes.data(), bytes.size());
  if (!f)
    throw std::runtime_error("helper staging write failed");
}
#ifdef __linux__
std::string python_library_pin() {
  const auto version=fs::canonical("/usr/bin/python3").filename();
  const auto root=fs::path("/usr/lib")/version;
  if(!fs::is_directory(root))throw std::runtime_error("Python standard library unavailable");
  std::map<std::string,std::string> manifest;
  std::uint64_t total=0;
  for(const auto &entry:fs::recursive_directory_iterator(root)) {
    if(fs::is_symlink(entry.symlink_status())) {
      const auto link=fs::read_symlink(entry.path()).generic_string();
      // Site customization is disabled by -S and its /etc target is not mounted.
      if(entry.path().filename()=="sitecustomize.py") {manifest.emplace(entry.path().lexically_relative(root).generic_string(),"disabled-site-link:"+link);continue;}
      if(!fs::exists(entry.path())||!fs::canonical(entry.path()).generic_string().starts_with("/usr/lib/"))
        throw std::runtime_error("Python library link leaves admitted library root");
      manifest.emplace(entry.path().lexically_relative(root).generic_string()+":link",link);
    }
    if(!entry.is_regular_file())continue;
    total+=entry.file_size();
    if(total>134217728||manifest.size()>=8192)throw std::runtime_error("Python library pin budget exceeded");
    manifest.emplace(entry.path().lexically_relative(root).generic_string(),sha256_file(entry.path()));
  }
  return sha256_text(J(manifest).dump());
}
void limit(int resource, rlim_t amount) {
  rlimit r{amount, amount};
  if (setrlimit(resource, &r))
    throw std::runtime_error("helper resource isolation failed");
}
void execution_filter() {
  // One process only. Namespace isolation supplies the filesystem boundary;
  // seccomp prevents process multiplication and dangerous kernel interfaces.
  std::vector<sock_filter> code{
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)};
  for (int call : {SYS_clone,
                   SYS_clone3,
                   SYS_fork,
                   SYS_vfork,
                   SYS_socket,
                   SYS_socketpair,
                   SYS_ptrace,
                   SYS_process_vm_readv,
                   SYS_process_vm_writev,
                   SYS_mount,
                   SYS_umount2,
                   SYS_unshare,
                   SYS_setns,
                   SYS_bpf,
                   SYS_perf_event_open,
                   SYS_keyctl,
                   SYS_add_key,
                   SYS_request_key,
                   SYS_userfaultfd,
                   SYS_io_uring_setup,
                   SYS_kill,
                   SYS_tkill,
                   SYS_tgkill,
                   SYS_pidfd_open,
                   SYS_pidfd_getfd,
                   SYS_pidfd_send_signal,
                   SYS_setsid,
                   SYS_setpgid}) {
    code.push_back(
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, static_cast<unsigned>(call), 0, 1));
    code.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM));
  }
  code.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
  sock_fprog program{static_cast<unsigned short>(code.size()), code.data()};
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program))
    throw std::runtime_error("helper syscall isolation failed");
}
std::vector<std::string> sandbox_args(const fs::path &source,
                                      const fs::path &input,
                                      const fs::path &engine,
                                      const std::string &language) {
  auto args = std::vector<std::string>{"-i",
          "PATH=/usr/bin:/bin",
          "LC_ALL=C",
          "TZ=UTC",
          "/usr/bin/bwrap",
          "--unshare-user",
          "--unshare-pid",
          "--unshare-net",
          "--unshare-ipc",
          "--unshare-uts",
          "--disable-userns",
          "--die-with-parent",
          "--new-session",
          "--cap-drop",
          "ALL",
          "--clearenv",
          "--setenv",
          "PATH",
          "/usr/bin:/bin",
          "--setenv",
          "LC_ALL",
          "C",
          "--setenv",
          "TZ",
          "UTC",
          "--setenv",
          "HOME",
          "/tmp",
          "--setenv",
          "SOURCE_DATE_EPOCH",
          "0",
          "--dir",
          "/usr",
          "--ro-bind",
          "/usr/bin",
          "/usr/bin",
          "--ro-bind",
          "/usr/lib",
          "/usr/lib",
          "--ro-bind-try",
          "/usr/libexec",
          "/usr/libexec",
          "--ro-bind",
          "/usr/include",
          "/usr/include",
          "--ro-bind",
          "/lib",
          "/lib",
          "--ro-bind",
          "/lib64",
          "/lib64",
          "--symlink",
          "usr/bin",
          "/bin",
          "--dir",
          "/dev",
          "--dev-bind",
          "/dev/null",
          "/dev/null",
          "--size",
          "67108864",
          "--tmpfs",
          "/tmp",
          "--dir",
          "/input",
          "--ro-bind",
          source.string(),
          "/input/source",
          "--ro-bind",
          input.string(),
          "/input/input.bin",
          "--ro-bind",
          (source.parent_path() / "files").string(),
          "/input/files",
          "--ro-bind",
          (source.parent_path() / "outputs.json").string(),
          "/input/outputs.json",
          "--ro-bind",
          engine.string(),
          "/helper-engine",
          "--remount-ro",
          "/",
          "--chdir",
          "/tmp",
          "/helper-engine",
          "__helper-stage",
          language};
  if (language == "unicorn-x86") {
    const auto worker = bundled_engines("runtime") / "emulation" / "indago_emulation_worker";
    if (!fs::exists(worker)) throw std::runtime_error("bundled emulation worker unavailable");
    args.insert(std::find(args.begin(),args.end(),"--remount-ro"), {"--ro-bind",worker.string(),"/emulation-worker"});
  }
  return args;
}
#if INDAGO_HAS_XAIR
thread_local bool solver_error = false;
void z3_error(Z3_context, Z3_error_code) { solver_error = true; }
#endif
#endif
} // namespace
J helper_capabilities() {
  bool available = false;
  bool python_available=false,emulation_available=false;
#ifdef __linux__
  available = fs::exists("/usr/bin/bwrap") && fs::exists("/usr/bin/gcc") &&
              fs::exists("/usr/bin/g++") && fs::exists("/usr/bin/prlimit") &&
              fs::exists("/usr/bin/systemd-run") && fs::exists("/usr/bin/systemctl");
  python_available=available&&fs::exists("/usr/bin/python3");
#if INDAGO_HAS_EMULATION
  emulation_available=available;
#endif
#endif
  return {{"schema", "indago.helper-capabilities.v1"},
          {"platform", "linux-x86_64 namespaces; use Linux CLI in WSL"},
          {"dependencies_present", available},
          {"isolation_probe_required", true},
          {"languages", {"c17", "c++20", "smt2", "python3", "unicorn-x86"}},
          {"language_dependencies_present",{{"python3",python_available},{"unicorn-x86",emulation_available}}},
          {"aggregate_memory_bytes",805306368},
          {"aggregate_tasks",32},
          {"source_bytes", 16384},
          {"input_bytes", 262144},
          {"aggregate_input_bytes", 1048576},
          {"file_output_bytes", 4096},
          {"output_bytes", output_limit},
          {"scratch_bytes", 67108864},
          {"execution_address_space_bytes", 268435456},
          {"compiler_address_space_bytes", 805306368},
          {"stage_address_space_policy", "engine image bytes plus 768 MiB"},
          {"stage_wall_ms", 7000},
          {"compiler_wall_ms", 3000},
          {"execution_wall_ms", 1200},
          {"compiler_cpu_seconds", 3},
          {"stage_cpu_seconds", 5},
          {"file_size_bytes", 16777216},
          {"solver_effort", 1000000},
          {"generated_processes", 1},
          {"network", false},
          {"host_fallback", false},
          {"target_execution", false},
          {"execution_scope", "confined helper code may interpret/emulate supplied bytes; no original host-target launch authority"},
          {"proof_policy",
           "helper output is a candidate; no solve or acceptance proof"}};
}
J normalize_helper(const ProjectStore &store, const J &component,
                   const J &args, const J &components) {
  keys(args, {"project", "scope", "language", "source_code", "input",
              "validation", "sealed", "inputs", "output_files"});
  const auto language = args.at("language").get<std::string>();
  if (!std::set<std::string>{"c17", "c++20", "smt2", "python3", "unicorn-x86"}.contains(language))
    throw std::runtime_error("unsupported helper language");
  auto code = args.at("source_code").get<std::string>();
  if (code.empty() || code.size() > 16384 || code.find('\0') != code.npos)
    throw std::runtime_error("helper source requires 1..16384 non-NUL bytes");
  auto input = args.at("input");
  keys(input, {"offset", "address", "max_bytes", "raw_sha256", "generated_hex"});
  J page;
  if(input.contains("generated_hex")) {
    if(input.size()!=1)throw std::runtime_error("generated input cannot claim an original location");
    const auto h=input.at("generated_hex").get<std::string>();
    if(h.size()>8192||h.size()%2||h.find_first_not_of("0123456789abcdef")!=h.npos)throw std::runtime_error("generated helper input must be <=4096 bytes of lowercase hex");
    page={{"hex",h},{"length",h.size()/2},{"slice_sha256",sha256_text(unhex(h))},
      {"artifact_sha256",component.at("artifact_sha256")},{"origin","experimental_stimulus"}};
  } else {
    input["project"] = args.at("project");
    page = harness_artifact_page(store, component, input, 262144);
  }
  auto validation = args.value("validation", J{{"kind", "none"}});
  keys(validation, {"kind", "expected", "program", "output_file"});
  const auto kind = validation.at("kind").get<std::string>();
  J sealed{{"input", pin_page(page)},
           {"source_sha256", sha256_text(code)},
           {"target_id", component.at("target_id")}};
  sealed["inputs"] = J::array();
  const auto extra = args.value("inputs", J::array());
  if (!extra.is_array() || extra.size() > 4) throw std::runtime_error("helper allows four extra inputs");
  std::size_t total = page.at("length").get<std::size_t>();
  std::set<std::string> names;
  for (const auto &entry : extra) {
    keys(entry, {"name", "target_id", "offset", "max_bytes", "raw_sha256"});
    const auto name = entry.at("name").get<std::string>();
    if (!plain_name(name) || !names.insert(name).second) throw std::runtime_error("invalid or duplicate input name");
    J selected;
    for (const auto &c : components) if (c.at("target_id") == entry.at("target_id")) selected = c;
    if (selected.is_null()) throw std::runtime_error("helper input is outside investigation scope");
    auto request = entry; request.erase("name"); request.erase("target_id"); request["project"] = args.at("project");
    auto p = harness_artifact_page(store, selected, request, 262144);
    total += p.at("length").get<std::size_t>();
    if (total > 1048576) throw std::runtime_error("helper aggregate input exceeds 1 MiB");
    sealed["inputs"].push_back({{"name", name}, {"target_id", selected.at("target_id")}, {"page", pin_page(p)}});
  }
  const auto outputs = args.value("output_files", J::array());
  if (!outputs.is_array() || outputs.size() > 4) throw std::runtime_error("helper allows four output files");
  names.clear();
  for (const auto &name : outputs)
    if (!name.is_string() || !plain_name(name.get<std::string>()) || !names.insert(name.get<std::string>()).second)
      throw std::runtime_error("invalid or duplicate output name");
#ifdef __linux__
  if (language == "python3") {
    if (!fs::exists("/usr/bin/python3"))
      throw std::runtime_error("operator-managed Python interpreter unavailable");
    sealed["interpreter_sha256"] = sha256_file("/usr/bin/python3");
    sealed["stdlib_sha256"] = python_library_pin();
  }
#endif
  if (kind == "artifact_bytes") {
    keys(validation, {"kind", "expected", "output_file"});
    if(validation.contains("output_file")&&std::find(outputs.begin(),outputs.end(),validation.at("output_file"))==outputs.end())
      throw std::runtime_error("validation output file was not requested");
    auto expected = validation.at("expected");
    keys(expected, {"offset", "address", "max_bytes", "raw_sha256"});
    expected["project"] = args.at("project");
    sealed["expected"] = harness_artifact_page(store, component, expected,4096);
  } else if (kind == "calculation") {
    keys(validation, {"kind", "program"});
    auto program = validation.at("program");
    keys(program, {"iterations", "variables", "body", "emit"});
    InvestigationCalculation calc;
    sealed["expected"] = calc.run(program, page.at("hex"));
    sealed["validation_program_sha256"] = sha256_text(program.dump());
  } else if (kind != "none" || validation.size() != 1)
    throw std::runtime_error("unsupported helper validation");
  if (args.contains("sealed") && args.at("sealed") != sealed)
    throw std::runtime_error("helper source/validation pins changed");
  J normalized = args;
  normalized["sealed"] = sealed;
  normalized["validation"] = validation;
  return normalized;
}
J execute_helper(const ProjectStore &store, const J &args) {
  const auto started = now_ms();
  const auto language = args.at("language").get<std::string>();
  J body{
      {"schema", "indago.helper-run.v1"},
      {"request_sha256", sha256_text(args.dump())},
      {"source_code", args.at("source_code")},
      {"source_sha256", args.at("sealed").at("source_sha256")},
      {"language", language},
      {"input", args.at("sealed").at("input")},
      {"inputs", args.at("sealed").at("inputs")},
      {"validation_request", args.at("validation")},
      {"status", "capability_blocked"},
      {"runs", J::array()},
      {"validation_passed", false},
      {"repeatable_observed", false},
      {"verified_solve", false},
      {"behavior_verified", false},
      {"limits", helper_capabilities()},
      {"trust",
       "Untrusted helper candidate, not target semantics or accepted input"}};
#ifdef __linux__
  if (helper_capabilities().at("dependencies_present").get<bool>()) {
    const auto engine = find_native_worker();
    if (!engine)
      throw std::runtime_error("helper engine unavailable");
    // Only these two immutable files are exposed, never the project database,
    // controller profile, environment, receipts directory or target executable.
    const auto dir =
        fs::absolute(store.root()) / "helper-staging" / make_id("helper");
    fs::create_directories(dir);
    struct Cleanup {
      fs::path path;
      ~Cleanup() {
        std::error_code ec;
        fs::remove_all(path, ec);
      }
    } cleanup{dir};
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace);
    write_file(dir / "source", args.at("source_code").get<std::string>());
    auto materialize = [&](const J &id, const J &pin, const fs::path &destination) {
      const auto target = store.target(args.at("project").get<std::string>(), id.get<std::string>(), true);
      const J selected{{"target_id", id}, {"artifact_sha256", pin.at("artifact_sha256")}};
      const auto page = harness_artifact_page(store, selected,
        {{"project", args.at("project")}, {"offset", pin.at("offset")}, {"max_bytes", pin.at("length")}}, 262144);
      if (page.at("slice_sha256") != pin.at("slice_sha256") || page.at("length") != pin.at("length"))
        throw std::runtime_error("helper input changed before staging");
      write_file(destination, unhex(page.at("hex")));
    };
    if(args.at("input").contains("generated_hex")) {
      const auto data=unhex(args.at("input").at("generated_hex"));
if(sha256_text(data)!=args.at("sealed").at("input").at("slice_sha256").get<std::string>())throw std::runtime_error("generated input pin changed");
      write_file(dir / "input",data);
    } else materialize(args.at("sealed").at("target_id"), args.at("sealed").at("input"), dir / "input");
    fs::create_directory(dir / "files");
    for (const auto &entry : args.at("sealed").at("inputs"))
      materialize(entry.at("target_id"), entry.at("page"), dir / "files" / entry.at("name").get<std::string>());
    write_file(dir / "outputs.json", args.value("output_files", J::array()).dump());
    NativeProcessOptions options;
    options.wall_time_ms = 7000;
    options.max_output_bytes = 49152;
    body["stages"] = J::array();
    auto version = run_native_process(
        "/usr/bin/env", {"-i", "/usr/bin/bwrap", "--version"}, options);
    body["environment"] = {
        {"bwrap_version", version.output.substr(0, 256)},
        {"bwrap_sha256", sha256_file("/usr/bin/bwrap")},
        {"rootfs_policy",
         "read-only root, /usr/bin, /usr/lib, /usr/include and libraries; only "
         "/tmp writable (64 MiB); no /proc, /etc, /home, /usr/local, /mnt, "
         "host workspace or network"}};
    if (fs::exists("/var/lib/dpkg/status"))
      body["environment"]["package_database_sha256"] =
          sha256_file("/var/lib/dpkg/status");
    for (int pass = 0; pass < 2; ++pass) {
      const auto child = run_resource_scope(
          sandbox_args(dir / "source", dir / "input", *engine, language),
          options);
      J stage{{"supervisor", receipt(child)}};
      if (child.exit_code != 0 || child.timed_out || child.truncated ||
          !child.output_complete) {
        body["status"] =
            child.timed_out ? "timeout" : "isolation_or_worker_failed";
        // A failed stage may contain arbitrary bytes, retained as bounded hex.
        stage["supervisor"]["stdout_hex"] =
            hex_bytes(child.output.substr(0, 4096));
        stage["supervisor"]["stderr_hex"] =
            hex_bytes(child.error.substr(0, 4096));
        body["stages"].push_back(stage);
        break;
      }
      auto result = J::parse(child.output);
      if (language == "python3" &&
          (result.at("dependencies").at("interpreter_sha256") != args.at("sealed").at("interpreter_sha256") ||
           result.at("dependencies").at("stdlib_sha256") != args.at("sealed").at("stdlib_sha256")))
        throw std::runtime_error("Python interpreter changed since proposal");
      stage["supervisor"].erase("stdout_hex");
      stage["result"] = result;
      body["stages"].push_back(stage);
      body["status"] = result.at("status");
      if (result.at("runs").size() != 1)
        break;
      body["runs"].push_back(result.at("runs")[0]);
      // Scratch and compiler state are discarded with this namespace. The
      // second observation must start from another fresh compilation/root.
    }
    {
      const auto &runs = body.at("runs");
      const bool repeat =
          runs.size() == 2 && good(runs[0]) && good(runs[1]) &&
          runs[0].at("stdout_hex") == runs[1].at("stdout_hex") &&
          body["stages"][0]["result"]["compiled_sha256"] ==
              body["stages"][1]["result"]["compiled_sha256"] &&
          body["stages"][0]["result"]["dependencies"] ==
              body["stages"][1]["result"]["dependencies"] &&
          body["stages"][0]["result"].value("files", J::array()) ==
              body["stages"][1]["result"].value("files", J::array());
      body["repeatable_observed"] = repeat;
      if (repeat) {
        body["output_sha256"] = runs[0].at("stdout_sha256");
        body["output_hex"] = runs[0].at("stdout_hex");
        body["files"] = body["stages"][0]["result"].value("files", J::array());
        if (args.at("sealed").contains("expected")) {
          auto actual=runs[0].at("stdout_hex");
          if(args.at("validation").contains("output_file")){
            actual=nullptr;for(const auto &file:body.at("files"))if(file.at("name")==args.at("validation").at("output_file"))actual=file.at("hex");
          }
          body["validation_passed"] =
              actual ==
              args.at("sealed").at("expected").at("hex");
        }
      }
      if (runs.size() == 2 && good(runs[0]) && good(runs[1]) && !repeat)
        body["status"] = "nonrepeatable";
      body["validation_scope"] =
          args.at("validation").at("kind") == "none"
              ? "No output reference supplied; unvalidated helper output"
          : args.at("validation").at("kind") == "artifact_bytes"
              ? "Exact equality with a pinned original artifact slice; not "
                "target acceptance"
              : "Finite model-declared transformation cross-check only; not "
                "target-semantic equivalence";
      if (args.at("sealed").contains("expected"))
        body["validation_reference"] = args.at("sealed").at("expected");
    }
  }
#endif
  if(language=="unicorn-x86" && body.value("repeatable_observed",false)) {
    auto emulation=J::parse(unhex(body.at("output_hex").get<std::string>()));
    if(emulation.value("schema",std::string{})!="indago.bounded-emulation.v1")
      throw std::runtime_error("emulation response schema mismatch");
    body["emulation"]=emulation;
  }
  std::string diagnostic;
  if(!body.at("runs").empty())diagnostic=unhex(body.at("runs").back().value("stderr_hex",std::string{}));
  else if(body.contains("stages")&&!body.at("stages").empty()){
    const auto &stage=body.at("stages").back();
    diagnostic=unhex(stage.at("supervisor").value("stderr_hex",std::string{}));
    if(stage.contains("result")&&stage.at("result").contains("compile")&&!stage.at("result").at("compile").is_null())
      diagnostic=unhex(stage.at("result").at("compile").value("stderr_hex",std::string{}));
  }
  diagnostic.resize(std::min<std::size_t>(diagnostic.size(),512));
  for(char &c:diagnostic)if((static_cast<unsigned char>(c)<32&&c!='\n'&&c!='\t')||static_cast<unsigned char>(c)>126)c='?';
  body["untrusted_diagnostic_preview"]=diagnostic;
  const auto original =
      store.target(args.at("project").get<std::string>(),
                   args.at("sealed").at("target_id").get<std::string>(), true);
  body["source_current_at_publication"] =
      sha256_file(original.object_path) ==
      args.at("sealed").at("input").at("artifact_sha256").get<std::string>();
  J dependencies=J::array({{{"type","artifact"},{"id",args.at("scope").at("artifact_sha256")},{"pin",args.at("scope").at("artifact_sha256")}}});
  for(const auto &entry:args.at("sealed").at("inputs")){
    const auto target=store.target(args.at("project").get<std::string>(),entry.at("target_id").get<std::string>(),true);
    const auto sha=entry.at("page").at("artifact_sha256").get<std::string>();
    if(sha256_file(target.object_path)!=sha)body["source_current_at_publication"]=false;
    dependencies.push_back({{"type","artifact"},{"id",sha},{"pin",sha}});
  }
  if (!body.at("source_current_at_publication").get<bool>()) {
    body["validation_passed"] = false;
    body["status"] = "source_changed";
  }
  body["elapsed_ms"] = now_ms() - started;
  return knowledge_put(
      store,
      {{"project", args.at("project")},
       {"kind", "product"},
       {"title", "Bounded analysis helper"},
       {"state", "unknown"},
       {"scope", args.at("scope")},
       {"body", body},
       {"dependencies",dependencies},
       {"author", "native-helper"}},
      true);
}
int helper_worker(int argc, char **argv) {
#ifdef __linux__
  try {
    // Bubblewrap does not promise to sanitize every inherited application FD.
    // Drop all non-stdio descriptors before the compiler or solver can run.
    // An unsupported close_range kernel fails closed, never weakens isolation.
    if (syscall(SYS_close_range, 3u, ~0u, 0u) != 0)
      throw std::runtime_error("helper descriptor isolation unavailable");
    if (argc != 3 || !fs::exists("/helper-engine") ||
        !fs::exists("/input/source") || fs::exists("/etc/passwd"))
      throw std::runtime_error("helper internal stage requires isolated root");
    const std::string mode = argv[1], language = argv[2];
    if (prctl(PR_SET_DUMPABLE, 0) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
      throw std::runtime_error("helper process privacy failed");
    limit(RLIMIT_CORE, 0);
    limit(RLIMIT_NOFILE, 64);
    limit(RLIMIT_FSIZE, 16777216);
    // The single executable may contain a large read-only tool bundle. Allow
    // that mapping for the trusted stage/SMT engine, not for compiled helpers.
    limit(RLIMIT_AS, fs::file_size("/helper-engine") + 805306368);
    limit(RLIMIT_CPU, 5);
    if (mode == "__helper-exec") {
      execution_filter();
      if (language == "smt2") {
#if INDAGO_HAS_XAIR
        auto source = read("/input/source", 16384);
        Z3_config cfg = Z3_mk_config();
        // Use deterministic solver effort plus the parent's wall deadline;
        // Z3's timeout watchdog would need a thread, which this profile denies.
        Z3_set_param_value(cfg, "rlimit", "1000000");
        auto ctx = Z3_mk_context(cfg);
        Z3_del_config(cfg);
        Z3_set_error_handler(ctx, z3_error);
        const char *result = Z3_eval_smtlib2_string(ctx, source.c_str());
        if (result)
          std::cout << result;
        const bool failed = solver_error;
        Z3_del_context(ctx);
        return failed ? 2 : 0;
#else
        return 2;
#endif
      }
      limit(RLIMIT_AS, 268435456);
      if (language == "unicorn-x86") {
        execl("/emulation-worker", "/emulation-worker", "/input/source", "/input/input.bin", static_cast<char *>(nullptr));
        return 126;
      }
      if (language == "python3") {
        // Isolated mode ignores user site packages and PYTHON* environment;
        // seccomp and the namespace remain the actual security boundary.
        execl("/usr/bin/python3", "/usr/bin/python3", "-I", "-S", "-B",
              "/input/source", static_cast<char *>(nullptr));
        return 126;
      }
      execl("/tmp/program", "/tmp/program", static_cast<char *>(nullptr));
      return 126;
    }
    if (mode != "__helper-stage")
      return 2;
    fs::create_directory("/tmp/output");
    J out{{"status", "failed"},
          {"runs", J::array()},
          {"compile", nullptr},
          {"compiled_sha256", nullptr},
          {"dependencies",
           {{"policy", "linux-helper-v1"},
            {"engine_sha256", sha256_file("/helper-engine")}}}};
    NativeProcessOptions options;
    options.wall_time_ms = 3000;
    options.max_output_bytes = output_limit;
    if (language == "c17" || language == "c++20") {
      const auto compiler = language == "c17" ? "/usr/bin/gcc" : "/usr/bin/g++";
      const auto version = run_native_process(compiler, {"--version"}, options);
      out["dependencies"]["compiler_version"] = version.output.substr(0, 1024);
      out["dependencies"]["compiler_sha256"] = sha256_file(compiler);
      auto compiled = run_native_process(
          "/usr/bin/prlimit",
          {"--as=805306368", "--cpu=3", "--", compiler, "-x",
           language == "c17" ? "c" : "c++",
           language == "c17" ? "-std=c17" : "-std=c++20", "-O0",
           "-frandom-seed=0", "/input/source", "-o", "/tmp/program"},
          options);
      out["compile"] = receipt(compiled);
      if (!good(out["compile"])) {
        out["status"] = "compile_failed";
        std::cout << out.dump();
        return 0;
      }
      out["compiled_sha256"] = sha256_file("/tmp/program");
    } else if (language == "python3") {
      const auto version = run_native_process(
          "/usr/bin/python3", {"-I", "-S", "-B", "--version"}, options);
      if (!good(receipt(version)))
        throw std::runtime_error("Python interpreter unavailable");
      out["dependencies"]["interpreter_version"] = version.output.substr(0, 256);
      out["dependencies"]["interpreter_sha256"] = sha256_file("/usr/bin/python3");
      out["dependencies"]["stdlib_sha256"] = python_library_pin();
      out["dependencies"]["python_profile"] = "isolated-no-site-no-bytecode";
      out["compiled_sha256"] = sha256_file("/input/source");
    } else if (language == "unicorn-x86") {
      out["dependencies"]["emulation_sha256"] = sha256_file("/emulation-worker");
      out["compiled_sha256"] = sha256_file("/input/source");
    } else if (language != "smt2")
      return 2;
#if INDAGO_HAS_XAIR
    out["dependencies"]["z3_version"] = Z3_get_full_version();
#endif
    options.wall_time_ms = 1200;
    options.stdin_file = "/input/input.bin";
    out["runs"].push_back(receipt(run_native_process(
        "/helper-engine", {"__helper-exec", language}, options)));
    out["status"] = good(out["runs"][0]) ? "executed" : "execution_failed";
    out["files"] = J::array();
    if (good(out["runs"][0])) {
      const auto outputs = J::parse(read("/input/outputs.json", 1024));
      std::size_t remaining = 4096;
      for (const auto &entry : outputs) {
        const auto name = entry.get<std::string>();
        if (!plain_name(name)) throw std::runtime_error("invalid private output manifest");
        // Neither symlinks, devices, FIFOs nor hardlinks are published.
        int directory = open("/tmp/output", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if(directory<0)throw std::runtime_error("unsafe output directory");
        int fd = openat(directory, name.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        close(directory);
        if (fd < 0) throw std::runtime_error("missing or unsafe helper output");
        struct stat st{};
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 || st.st_size < 0 ||
            static_cast<std::uint64_t>(st.st_size) > remaining) {
          close(fd); throw std::runtime_error("helper output exceeds bounds or is unsafe");
        }
        std::string data(static_cast<std::size_t>(st.st_size), '\0');
        std::size_t done = 0;
        while (done < data.size()) {
          const auto count = ::read(fd, data.data() + done, data.size() - done);
          if (count <= 0) { close(fd); throw std::runtime_error("helper output read failed"); }
          done += static_cast<std::size_t>(count);
        }
        close(fd); remaining -= data.size();
        out["files"].push_back({{"name", name}, {"hex", hex_bytes(data)}, {"sha256", sha256_text(data)}, {"size", data.size()}});
      }
    }
    std::cout << out.dump();
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what();
    return 126;
  }
#else
  (void)argc;
  (void)argv;
  return 126;
#endif
}
} // namespace indago
