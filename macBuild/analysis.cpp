#include "analysis.hpp"
#include <chrono>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <spawn.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace macbuild {
namespace {
std::string Text(const fs::path& path, std::size_t limit = 16 * 1024 * 1024) {
  auto bytes = ReadBytes(path, limit);
  return {bytes.begin(), bytes.end()};
}
// posix_spawn receives an argument array, never a shell command. Spaces, quotes
// and shell punctuation in a selected filename remain ordinary filename bytes.
void Run(const std::vector<std::string>& arguments, const fs::path& log,
         const std::atomic_bool& cancel, unsigned seconds) {
  if (cancel) throw std::runtime_error("Analysis cancelled.");
  std::vector<char*> argv;
  for (const auto& item : arguments) argv.push_back(const_cast<char*>(item.c_str()));
  argv.push_back(nullptr);
  posix_spawn_file_actions_t actions;
  posix_spawnattr_t attributes;
  posix_spawn_file_actions_init(&actions);
  posix_spawnattr_init(&attributes);
  // A fresh group also contains Ghidra's native decompiler subprocess.
  posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETPGROUP);
  posix_spawnattr_setpgroup(&attributes, 0);
  posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
  posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, log.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
  posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO, STDERR_FILENO);
  // Keep Java's environment predictable; do not inherit JAVA_TOOL_OPTIONS.
  char path[] = "PATH=/usr/bin:/bin:/usr/sbin:/sbin";
  char locale[] = "LANG=en_US.UTF-8";
  char* environment[] = {path, locale, nullptr};
  pid_t pid = 0;
  const auto error = posix_spawn(&pid, argv[0], &actions, &attributes, argv.data(), environment);
  posix_spawn_file_actions_destroy(&actions);
  posix_spawnattr_destroy(&attributes);
  if (error) throw std::runtime_error("Could not launch Java: " + std::string(strerror(error)));
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
  int status = 0;
  std::string failure;
  for (;;) {
    const auto result = waitpid(pid, &status, WNOHANG);
    if (result == pid) break;
    if (result < 0 && errno == EINTR) continue;
    if (result < 0) { failure = "Could not observe analysis process."; break; }
    std::error_code ec;
    const auto size = fs::file_size(log, ec);
    if (cancel) failure = "Analysis cancelled.";
    else if (std::chrono::steady_clock::now() >= deadline) failure = "Analysis timed out.";
    else if (!ec && size > 4 * 1024 * 1024) failure = "Analysis log exceeded its limit.";
    if (!failure.empty()) break;
    std::this_thread::sleep_for(std::chrono::milliseconds(40));
  }
  // Also stop any decompiler left behind after Java exits unexpectedly.
  kill(-pid, SIGKILL);
  if (!failure.empty()) {
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    throw std::runtime_error(failure + " Log: " + log.string());
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    throw std::runtime_error("Ghidra failed. Read " + log.string());
}
} // namespace

Tools DefaultTools() {
  const fs::path root = INDAGO_MAC_ROOT;
  return {root / "out/macBuild/deps/ghidra_12.0.3_PUBLIC",
          root / "out/macBuild/deps/jdk-21.0.12.1+1/Contents/Home/bin/java",
          root / "macBuild/ghidra"};
}

Json Capabilities() {
  const auto tools = DefaultTools();
  const bool available = access(tools.java.c_str(), X_OK) == 0 &&
      access((tools.ghidra / "Ghidra/Features/Decompiler/os/mac_arm_64/decompile").c_str(), X_OK) == 0 &&
      fs::exists(tools.scripts / "MacExport.java");
  return {{"edition", "macOS ARM64"}, {"formats", {"Mach-O arm64", "universal arm64 slice"}},
      {"import", true}, {"static_analysis", available}, {"backend", "Ghidra 12.0.3"},
      {"availability_is_qualification", false}, {"execution", false}, {"x64_targets", false}};
}

Json Analyze(const Project& original, const Tools& tools, const std::atomic_bool& cancel,
             unsigned timeoutSeconds) {
  const auto p = LoadProject(original.directory);
  const auto utility = tools.ghidra / "Ghidra/Framework/Utility/lib/Utility.jar";
  const auto decompiler = tools.ghidra / "Ghidra/Features/Decompiler/os/mac_arm_64/decompile";
  const auto script = tools.scripts / "MacExport.java";
  if (!fs::exists(utility) || access(tools.java.c_str(), X_OK) || access(decompiler.c_str(), X_OK))
    throw std::runtime_error("Analysis tools missing. Run macBuild/setup.sh first.");
  Arm64Slice(ReadBytes(tools.java));
  Arm64Slice(ReadBytes(decompiler));
  const auto scriptHash = Sha256(ReadBytes(script));
  const auto propertiesHash = Sha256(ReadBytes(tools.ghidra / "Ghidra/application.properties"));
  auto runName = (p.directory / "run-XXXXXX").string();
  if (!mkdtemp(runName.data())) throw std::runtime_error("Could not create analysis directory.");
  const fs::path run = runName;
  fs::create_directories(run / "home");
  fs::create_directories(run / "projects");
  fs::create_directories(run / "tmp");
  const auto output = run / "export.json";
  Run({tools.java.string(), "-Xmx2G", "-Djava.system.class.loader=ghidra.GhidraClassLoader",
       "-Dfile.encoding=UTF-8", "-Djava.awt.headless=true", "--enable-native-access=ALL-UNNAMED",
       "-Duser.home=" + (run / "home").string(), "-Djava.io.tmpdir=" + (run / "tmp").string(),
       "-cp", utility.string(), "ghidra.Ghidra", "ghidra.app.util.headless.AnalyzeHeadless",
       (run / "projects").string(), "analysis", "-import", (p.directory / "arm64.macho").string(),
       "-analysisTimeoutPerFile", "60", "-max-cpu", "2", "-scriptPath", tools.scripts.string(),
       "-postScript", "MacExport.java", output.string(), "-deleteProject",
       "-log", (run / "ghidra.log").string(), "-scriptlog", (run / "script.log").string()},
      run / "worker.log", cancel, timeoutSeconds);
  if (cancel) throw std::runtime_error("Analysis cancelled; previous evidence retained.");
  auto report = Json::parse(Text(output));
  if (report.at("schema") != "indago.mac-analysis.v1" || report.at("architecture") != "AARCH64" ||
      report.at("input_sha256") != p.metadata.at("slice_sha256"))
    throw std::runtime_error("Ghidra output does not match this ARM64 input.");
  report["original_sha256"] = p.metadata.at("sha256");
  report["slice_offset"] = p.metadata.at("slice_offset");
  report["script_sha256"] = scriptHash;
  report["ghidra_properties_sha256"] = propertiesHash;
  report["target_executed"] = false;
  const auto document = report.dump(2);
  const auto hash = Sha256(Bytes(document.begin(), document.end()));
  WriteAtomic(p.directory / ("analysis-" + hash + ".json"), document);
  WriteAtomic(p.directory / "latest.json", Json{{"sha256", hash}}.dump());
  // Native projects and compilation caches are disposable; reports stay intact.
  fs::remove_all(run / "home");
  fs::remove_all(run / "tmp");
  return report;
}

Json LoadAnalysis(const Project& p) {
  auto pointer = Json::parse(Text(p.directory / "latest.json", 1024));
  const auto hash = pointer.at("sha256").get<std::string>();
  if (hash.size() != 64 || hash.find_first_not_of("0123456789abcdef") != std::string::npos)
    throw std::runtime_error("Invalid evidence identifier.");
  const auto bytes = ReadBytes(p.directory / ("analysis-" + hash + ".json"), 16 * 1024 * 1024);
  if (Sha256(bytes) != hash) throw std::runtime_error("Evidence integrity check failed.");
  auto result = Json::parse(bytes);
  if (result.at("original_sha256") != p.metadata.at("sha256") ||
      result.at("input_sha256") != p.metadata.at("slice_sha256"))
    throw std::runtime_error("Evidence belongs to a different input.");
  return result;
}
} // namespace macbuild
