#include "guest.hpp"
#include "indago/runtime.hpp"
#include "isolated_worker.hpp"
#include "workbench_db.hpp"
#include <future>
#include <thread>
#ifdef __linux__
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif
namespace indago {
using namespace wb;
namespace {
J pin_file(const J &v, std::uint64_t limit) {
  keys(v, {"path", "sha256"});
  const auto path = fs::canonical(v.at("path").get<std::string>());
  if (!fs::is_regular_file(path) || fs::file_size(path) > limit)
    throw std::runtime_error("guest asset exceeds profile bound");
  const auto sha = sha256_file(path);
  if (v.at("sha256") != sha)
    throw std::runtime_error("guest asset identity mismatch");
  return {{"path", path.string()}, {"sha256", sha}, {"bytes", fs::file_size(path)}};
}
std::string library_pin(const fs::path &root) {
  J files = J::object();
  unsigned count = 0;
  std::uint64_t size = 0;
  for (const auto &e : fs::directory_iterator(root)) {
    if (!fs::is_regular_file(e.symlink_status()) || ++count > 128 ||
        (size += e.file_size()) > 268435456)
      throw std::runtime_error("QEMU library payload bound/type mismatch");
    files[e.path().filename().string()] = sha256_file(e.path());
  }
  return sha256_text(files.dump());
}
void verify(const J &p) {
  for (const auto &key :
       {"image", "qemu", "qemu_img", "bios", "rom", "transfer", "host_package_database"})
    if (p.contains(key) && sha256_file(p.at(key).at("path").get<std::string>()) !=
                               p.at(key).at("sha256").get<std::string>())
      throw std::runtime_error("guest profile asset changed");
  if (p.contains("libraries") &&
      library_pin(p.at("libraries").at("path").get<std::string>()) !=
          p.at("libraries").at("sha256").get<std::string>())
    throw std::runtime_error("guest tool libraries changed");
}
J load_profile(const fs::path &root, const J &id) {
  identifier(id.get<std::string>());
  auto p = J::parse(read(root / (id.get<std::string>() + ".json"), 32768));
  auto copy = p;
  copy.erase("profile_sha256");
  if (sha256_text(copy.dump()) != p.at("profile_sha256").get<std::string>())
    throw std::runtime_error("guest profile integrity failure");
  verify(p);
  return p;
}
#ifdef __linux__
class Qmp {
  int fd = -1;
  std::string pending;
  unsigned sequence = 0;
  J receive() {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (true) {
      const auto end = pending.find('\n');
      if (end != pending.npos) {
        auto line = pending.substr(0, end);
        pending.erase(0, end + 1);
        return J::parse(line);
      }
      if (pending.size() > 65536 || std::chrono::steady_clock::now() > deadline)
        throw std::runtime_error("bounded QMP receive failed");
      pollfd p{fd, POLLIN, 0};
      if (poll(&p, 1, 100) > 0) {
        char buf[4096];
        auto n = recv(fd, buf, sizeof(buf), 0);
        if (n <= 0)
          throw std::runtime_error("QMP disconnected");
        pending.append(buf, n);
      }
    }
  }

public:
  explicit Qmp(const fs::path &path) {
    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
      throw std::runtime_error("QMP socket failed");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    const auto name = path.string();
    if (name.size() >= sizeof(address.sun_path)) {
      close(fd);
      fd = -1;
      throw std::runtime_error("QMP socket path too long");
    }
    std::copy(name.begin(), name.end(), address.sun_path);
    bool ready = false;
    for (unsigned i = 0; i < 100; ++i) {
      if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0) {
        ready = true;
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (!ready) {
      close(fd);
      fd = -1;
      throw std::runtime_error("QEMU did not expose QMP within 5 seconds");
    }
    try {
      auto hello = receive();
      if (!hello.contains("QMP"))
        throw std::runtime_error("invalid QMP greeting");
      call("qmp_capabilities");
    } catch (...) {
      close(fd);
      fd = -1;
      throw;
    }
  }
  ~Qmp() {
    if (fd >= 0)
      close(fd);
  }
  J call(const std::string &command, J args = J::object()) {
    const auto id = ++sequence;
    const auto data =
        J{{"execute", command}, {"arguments", args}, {"id", id}}.dump() + "\n";
    std::size_t pos = 0;
    while (pos < data.size()) {
      auto n = send(fd, data.data() + pos, data.size() - pos, MSG_NOSIGNAL);
      if (n <= 0)
        throw std::runtime_error("QMP send failed");
      pos += n;
    }
    for (unsigned i = 0; i < 64; ++i) {
      auto result = receive();
      if (result.value("id", 0U) == id) {
        if (result.contains("error"))
          throw std::runtime_error("QMP native error: " + result.at("error").dump());
        return result.at("return");
      }
    }
    throw std::runtime_error("QMP event bound exceeded");
  }
};
J run_guest(const ProjectStore &store, const fs::path &root, const J &profile,
            const J &request) {
  keys(request, {"profile", "actions", "previous", "project", "mode"});
  const auto mode = request.value("mode", std::string("normal"));
  if (!std::set<std::string>{"normal", "record", "replay"}.contains(mode))
    throw std::runtime_error("unsupported replay mode");
  if (mode != "normal" && profile.at("accelerator") != "tcg")
    throw std::runtime_error(
        "record/replay requires the explicit trusted TCG icount profile");
  auto actions = request.value(
      "actions", J::array({{{"operation", "observe"}, {"duration_ms", 250}}}));
  if (!actions.is_array() || actions.empty() || actions.size() > 8)
    throw std::runtime_error("guest actions require 1..8 steps");
  unsigned total = 0, snapshots = 0;
  bool snapshot = false;
  for (const auto &a : actions) {
    keys(a, {"operation", "duration_ms"});
    const auto op = a.at("operation").get<std::string>();
    if (!std::set<std::string>{"observe", "pause", "resume", "warm_reset", "snapshot",
                               "restore", "registers"}
             .contains(op))
      throw std::runtime_error("guest operation not allowed");
    total += static_cast<unsigned>(bound(a, "duration_ms", 100, 1000));
    if (op == "snapshot") {
      snapshot = true;
      if (++snapshots > 1)
        throw std::runtime_error("one bounded checkpoint per run");
    }
    if (op == "restore" && !snapshot)
      throw std::runtime_error("no checkpoint in this run");
  }
  if (total > 5000)
    throw std::runtime_error("guest observation budget exceeds 5 seconds");
  // Retain at most four bounded runs; do not silently delete user evidence.
  unsigned retained = 0;
  for (const auto &e : fs::directory_iterator(root))
    if (e.is_directory() && fs::exists(e.path() / "overlay.qcow2"))
      ++retained;
  if (retained >= 4)
    throw std::runtime_error("guest retention quota reached; explicitly prune a run");
  verify(profile);
  const auto id = make_id("guest_run");
  const auto dir = root / id;
  fs::create_directory(dir);
  char temporary[] = "/tmp/indago-guest-XXXXXX";
  if (!mkdtemp(temporary))
    throw std::runtime_error("private guest staging failed");
  const fs::path temp = temporary;
  struct Cleanup {
    fs::path p;
    ~Cleanup() {
      std::error_code e;
      fs::remove_all(p, e);
    }
  } cleanup{temp};
  atomic_write(temp / ".indago-owner", id);
  J result{{"schema", "indago.guest-run.v1"},
           {"id", id},
           {"profile", profile.at("id")},
           {"profile_sha256", profile.at("profile_sha256")},
           {"status", "starting"},
           {"events", J::array()},
           {"base_sha256", profile.at("image").at("sha256")},
           {"network", "no NIC; isolated namespace"},
           {"verified_solve", false},
           {"overlay_epoch", make_id("epoch")},
           {"qemu_is_universal_sandbox", false}};
  const auto journal = dir / "receipt.json";
  auto persist = [&] { atomic_write(journal, result.dump()); };
  persist();
  result["resource_unit"] = "indago-" + id;
  result["deadline_ms"] = now_ms() + 30000;
  result["private_staging"] = temp.string();
  persist();
  NativeProcessOptions create;
  create.wall_time_ms = 3000;
  create.max_output_bytes = 4096;
  // No attacker-controlled qcow backing chains: admitted base format is raw.
  auto made = run_native_process(
      profile.at("qemu_img").at("path").get<std::string>(),
      {"create", "-u", "-f", "qcow2", "-F", "raw", "-b", "/input/base.raw",
       (temp / "overlay.qcow2").string(),
       std::to_string(profile.at("image").at("bytes").get<std::uint64_t>())},
      create);
  if (made.exit_code != 0) {
    result["status"] = "failed";
    result["diagnostic"] = made.error;
    persist();
    return result;
  }
  result["fresh_overlay_sha256"] = sha256_file(temp / "overlay.qcow2");
  std::vector<std::string> command{"-i",
                                   "/usr/bin/bwrap",
                                   "--unshare-all",
                                   "--unshare-user",
                                   "--disable-userns",
                                   "--die-with-parent",
                                   "--new-session",
                                   "--cap-drop",
                                   "ALL",
                                   "--clearenv",
                                   "--setenv",
                                   "HOME",
                                   "/tmp",
                                   "--setenv",
                                   "LC_ALL",
                                   "C",
                                   "--ro-bind",
                                   "/usr/lib",
                                   "/usr/lib",
                                   "--ro-bind",
                                   "/lib",
                                   "/lib",
                                   "--ro-bind",
                                   "/lib64",
                                   "/lib64",
                                   "--proc",
                                   "/proc",
                                   "--dev",
                                   "/dev",
                                   "--size",
                                   "16777216",
                                   "--tmpfs",
                                   "/tmp",
                                   "--bind",
                                   temp.string(),
                                   "/run/work",
                                   "--ro-bind",
                                   profile.at("image").at("path").get<std::string>(),
                                   "/input/base.raw",
                                   "--ro-bind",
                                   profile.at("bios").at("path").get<std::string>(),
                                   "/input/bios.bin",
                                   "--ro-bind",
                                   profile.at("qemu").at("path").get<std::string>(),
                                   "/qemu",
                                   "--ro-bind",
                                   "/usr/bin/prlimit",
                                   "/prlimit"};
  if (profile.at("accelerator") == "kvm")
    command.insert(command.end(), {"--dev-bind", "/dev/kvm", "/dev/kvm"});
  if (profile.contains("libraries"))
    command.insert(command.end(),
                   {"--ro-bind", profile.at("libraries").at("path").get<std::string>(),
                    "/qemu-libs", "--setenv", "LD_LIBRARY_PATH", "/qemu-libs"});
  command.insert(command.end(),
                 {"--ro-bind", profile.at("rom").at("path").get<std::string>(),
                  "/input/kvmvapic.bin"});
  if (profile.contains("transfer"))
    command.insert(command.end(),
                   {"--ro-bind", profile.at("transfer").at("path").get<std::string>(),
                    "/input/transfer.raw"});
  command.insert(
      command.end(),
      {"--remount-ro",
       "/",
       "--chdir",
       "/run/work",
       "/prlimit",
       "--fsize=134217728",
       "--",
       "/qemu",
       "-machine",
       profile.at("machine").get<std::string>(),
       "-accel",
       profile.at("accelerator").get<std::string>(),
       "-cpu",
       "qemu64",
       "-m",
       "32",
       "-smp",
       "1",
       "-nodefaults",
       "-no-user-config",
       "-display",
       "none",
       "-vga",
       "none",
       "-nic",
       "none",
       "-bios",
       "/input/bios.bin",
       "-drive",
       "file=/run/work/overlay.qcow2,format=qcow2,if=ide",
       "-serial",
       "file:/run/work/serial.log",
       "-qmp",
       "unix:/run/work/qmp.sock,server=on,wait=off",
       "-gdb",
       "unix:/run/work/gdb.sock,server=on,wait=off",
       "-S",
       "-sandbox",
       "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"});
  result["mode"] = mode;
  command.insert(command.end(), {"-L", "/input"});
  if (profile.contains("transfer")) {
    if (mode != "normal")
      throw std::runtime_error("transfer disk not qualified for replay profile");
    command.insert(command.end(),
                   {"-fw_cfg", "name=opt/indago/transfer,file=/input/transfer.raw"});
    result["transfer"] = profile.at("transfer");
    result["transfer"]["direction"] =
        "read-only fw_cfg file opt/indago/transfer; no guest host-folder sharing";
  }
  if (mode != "normal") {
    for (const auto &a : actions)
      if (a.at("operation") != "observe")
        throw std::runtime_error("icount profile currently admits observation only");
    const auto drive = std::find(command.begin(), command.end(),
                                 "file=/run/work/overlay.qcow2,format=qcow2,if=ide");
    *drive = "file=/run/work/overlay.qcow2,format=qcow2,if=none,id=disk";
    command.insert(command.end(),
                   {"-drive", "driver=blkreplay,if=none,image=disk,id=replaydisk",
                    "-device", "ide-hd,drive=replaydisk", "-icount",
                    "shift=3,rr=" + mode + ",rrfile=/run/work/replay.bin"});
    if (mode == "replay") {
      identifier(request.at("previous").get<std::string>());
      const auto old = root / request.at("previous").get<std::string>();
      const auto receipt = J::parse(read(old / "receipt.json", 65536));
      if (receipt.at("mode") != "record" || receipt.at("status") != "completed" ||
          receipt.at("profile_sha256") != profile.at("profile_sha256") ||
          !receipt.value("stopped_verified", false) ||
          sha256_file(old / "replay.bin") !=
              receipt.at("replay_sha256").get<std::string>())
        throw std::runtime_error(
            "replay needs an intact completed same-profile recording");
      fs::copy_file(old / "replay.bin", temp / "replay.bin");
    }
  }
  NativeProcessOptions options;
  options.wall_time_ms = 20000;
  options.max_output_bytes = 8192;
  options.cancel_file = dir / "cancel";
  options.should_cancel = [&] {
    std::error_code ec;
    std::uintmax_t bytes = 0;
    unsigned entries = 0;
    for (fs::recursive_directory_iterator
             i(temp, fs::directory_options::skip_permission_denied, ec),
         end;
         i != end && !ec; i.increment(ec)) {
      if (++entries > 64)
        return true;
      if (i->is_regular_file(ec))
        bytes += i->file_size(ec);
      if (bytes > 134217728)
        return true;
    }
    return bool(ec);
  };
  const auto resource_unit = result.at("resource_unit").get<std::string>();
  auto worker = std::async(std::launch::async, [&] {
    return run_resource_scope(command, options, 536870912, 32, resource_unit);
  });
  try {
    Qmp qmp(temp / "qmp.sock");
    result["events"].push_back(
        {{"operation", "start"}, {"state", qmp.call("query-status")}});
    qmp.call("cont");
    for (const auto &action : actions) {
      if (fs::exists(options.cancel_file))
        throw std::runtime_error("guest cancellation requested");
      const auto op = action.at("operation").get<std::string>();
      J event{{"operation", op}};
      if (op == "pause")
        qmp.call("stop");
      else if (op == "resume")
        qmp.call("cont");
      else if (op == "warm_reset") {
        qmp.call("system_reset");
        event["disk_reset"] = false;
      } else if (op == "snapshot" || op == "restore") {
        qmp.call("stop");
        const auto answer =
            qmp.call("human-monitor-command",
                     {{"command-line",
                       op == "snapshot" ? "savevm checkpoint" : "loadvm checkpoint"}});
        event["native_response"] = answer;
        if (answer.is_string() && !answer.get<std::string>().empty())
          throw std::runtime_error("checkpoint failed: " + answer.get<std::string>());
        qmp.call("cont");
      } else if (op == "registers") {
        qmp.call("stop");
        const auto gdb = bundled_engines() / "gdb/bin/gdb";
        if (!fs::exists(gdb))
          throw std::runtime_error("bundled GDB unavailable");
        NativeProcessOptions debug;
        debug.wall_time_ms = 3000;
        debug.max_output_bytes = 8192;
        const auto observation = run_readonly_parser(
            gdb,
            {"-nx", "-nh", "--batch", "-iex", "set auto-load off", "-iex",
             "set debuginfod enabled off", "-ex", "set architecture i386:x86-64", "-ex",
             "target remote " + (temp / "gdb.sock").string(), "-ex", "info registers",
             "-ex", "detach"},
            {temp / "gdb.sock"}, debug, gdb.parent_path().parent_path());
        event["debugger"] = {
            {"status", observation.exit_code == 0 ? "completed" : "partial"},
            {"output", observation.output},
            {"error", observation.error},
            {"engine_sha256", sha256_file(gdb)}};
        qmp.call("cont");
      }
      std::this_thread::sleep_for(
          std::chrono::milliseconds(bound(action, "duration_ms", 100, 1000)));
      event["state"] = qmp.call("query-status");
      result["events"].push_back(event);
      persist();
    }
    qmp.call("stop");
    result["events"].push_back(
        {{"operation", "stop"}, {"state", qmp.call("query-status")}});
    qmp.call("quit");
    result["status"] = "completed";
  } catch (const std::exception &e) {
    result["status"] = "partial";
    result["diagnostic"] = std::string(e.what());
    atomic_write(options.cancel_file, "cancel");
  }
  const auto exited = worker.get();
  result["process"] = {{"exit_code", exited.exit_code},
                       {"timed_out", exited.timed_out},
                       {"cancelled", exited.cancelled},
                       {"output_complete", exited.output_complete},
                       {"error", exited.error}};
  // The resource launcher checks terminal cgroup state separately from success.
  // A cancelled/failed run can be confirmed stopped without becoming successful.
  result["stopped_verified"] = exited.output_complete;
  if (!exited.output_complete || exited.timed_out || exited.cancelled ||
      exited.exit_code != 0)
    result["status"] = "partial";
  result["base_unchanged"] =
      sha256_file(profile.at("image").at("path").get<std::string>()) ==
      profile.at("image").at("sha256").get<std::string>();
  if (!result.at("base_unchanged").get<bool>())
    result["status"] = "partial";
  auto safe_output = [&](const char *name) {
    const auto file = temp / name;
    return result.at("stopped_verified").get<bool>() &&
           fs::is_regular_file(fs::symlink_status(file)) &&
           fs::hard_link_count(file) == 1;
  };
  if (safe_output("serial.log")) {
    const auto size = fs::file_size(temp / "serial.log");
    std::ifstream f(temp / "serial.log", std::ios::binary);
    std::string data(std::min<std::uintmax_t>(size, 4096), '\0');
    f.read(data.data(), data.size());
    atomic_write(dir / "serial.bin", data);
    result["serial"] = {{"sha256", sha256_text(data)},
                        {"bytes", data.size()},
                        {"partial", size > 4096 || result.at("status") != "completed"}};
  }
  if (safe_output("overlay.qcow2") &&
      fs::file_size(temp / "overlay.qcow2") <= 134217728) {
    fs::copy_file(temp / "overlay.qcow2", dir / "overlay.qcow2");
    result["overlay_sha256"] = sha256_file(dir / "overlay.qcow2");
    result["overlay_bytes"] = fs::file_size(dir / "overlay.qcow2");
  }
  if (safe_output("replay.bin") && fs::file_size(temp / "replay.bin") <= 16777216) {
    fs::copy_file(temp / "replay.bin", dir / "replay.bin");
    result["replay_sha256"] = sha256_file(dir / "replay.bin");
  }
  if (request.contains("previous")) {
    identifier(request.at("previous").get<std::string>());
    const auto before = J::parse(
        read(root / request.at("previous").get<std::string>() / "receipt.json", 65536));
    if (before.at("profile_sha256") != profile.at("profile_sha256"))
      throw std::runtime_error("cold reset profile differs");
    const bool output_agreement =
        before.contains("serial") && result.contains("serial") &&
        !before.at("serial").value("partial", true) &&
        !result.at("serial").value("partial", true) &&
        before.at("serial").at("sha256") == result.at("serial").at("sha256");
    result["cold_reset"] = {
        {"previous", request.at("previous")},
        {"fresh_overlay", true},
        {"prior_overlay_not_reused",
         before.at("overlay_epoch") != result.at("overlay_epoch")},
        {"base_unchanged", result.at("base_unchanged")},
        {"boot_output_agreement", output_agreement},
        {"scope", "fresh disk overlay and new process; guest application state beyond "
                  "selected observations is not certified"}};
  }
  try {
    verify(profile);
    result["assets_current_at_publication"] = true;
  } catch (const std::exception &e) {
    result["assets_current_at_publication"] = false;
    result["status"] = "partial";
    result["diagnostic"] = e.what();
  }
  persist();
  return result;
}
#endif
} // namespace
J guest_action(const ProjectStore &store, const std::string &op, const J &r) {
  const auto root = fs::absolute(store.root()) / "guests";
  fs::create_directories(root);
  if (op == "capabilities")
    return {{"schema", "indago.guest-capabilities.v1"},
            {"profile", "bounded Linux QEMU x86 raw boot disks"},
            {"operations",
             {"create", "run", "reset", "show", "list", "cancel", "reconcile", "export",
              "prune"}},
            {"network", "none"},
            {"guest_images_embedded", false},
            {"universal_sandbox", false},
            {"record_replay", "trusted TCG icount shift=3, blkreplay disk, no network; "
                              "observation-only profile"},
            {"limits",
             {{"image_bytes", 16777216},
              {"memory_mib", 32},
              {"overlay_bytes", 134217728},
              {"retained_runs", 4},
              {"wall_ms", 20000}}}};
  if (op == "create") {
    keys(r, {"image", "qemu", "qemu_img", "bios", "rom", "transfer", "machine",
             "accelerator", "trusted_guest"});
    if (!r.value("trusted_guest", false))
      throw std::runtime_error(
          "this development profile requires an explicitly assessed trusted guest");
    if (r.at("machine") != "pc-i440fx-10.2" ||
        !std::set<std::string>{"kvm", "tcg"}.contains(
            r.at("accelerator").get<std::string>()))
      throw std::runtime_error("unsupported pinned machine/accelerator profile");
    auto p = r;
    p["id"] = make_id("guest");
    p["schema"] = "indago.guest-profile.v1";
    auto tool = [&](const char *key, const char *relative, std::uint64_t size) {
      if (r.contains(key))
        return pin_file(r.at(key), size);
      const auto path = bundled_engines() / "qemu" / relative;
      if (!fs::exists(path))
        throw std::runtime_error("optional bundled QEMU unavailable; stage tools or "
                                 "explicitly pin operator tools");
      return pin_file({{"path", path.string()}, {"sha256", sha256_file(path)}}, size);
    };
    p["image"] = pin_file(r.at("image"), 16777216);
    p["qemu"] = tool("qemu", "bin/qemu-system-x86_64", 134217728);
    p["qemu_img"] = tool("qemu_img", "bin/qemu-img", 134217728);
    p["bios"] = tool("bios", "firmware/bios-256k.bin", 1048576);
    p["rom"] = tool("rom", "firmware/kvmvapic.bin", 1048576);
    if (r.contains("transfer"))
      p["transfer"] = pin_file(r.at("transfer"), 1048576);
    const auto libs =
        fs::path(p.at("qemu").at("path").get<std::string>()).parent_path().parent_path() /
        "lib";
    if (fs::exists(libs) && fs::exists(libs.parent_path() / "files.sha256"))
      p["libraries"] = {{"path", libs.string()}, {"sha256", library_pin(libs)}};
#ifdef __linux__
    p["host_package_database"] = {{"path", "/var/lib/dpkg/status"},
                                  {"sha256", sha256_file("/var/lib/dpkg/status")}};
#endif
    p["image_format"] = "raw";
    p["fixed_configuration"] = {
        {"cpu", "qemu64"},
        {"memory_mib", 32},
        {"vcpus", 1},
        {"network", "none"},
        {"firmware_boot", "IDE raw base through disposable qcow2"},
        {"rtc", "QEMU default; record/replay retains nondeterministic events, ordinary "
                "runs are not deterministic clock virtualization"},
        {"qmp", "private Unix socket; whitelist only"}};
    p["profile_sha256"] = sha256_text(p.dump());
    atomic_write(root / (p.at("id").get<std::string>() + ".json"), p.dump());
    return p;
  }
  if (op == "run" || op == "reset") {
#ifdef __linux__
    if (op == "reset" && !r.contains("previous"))
      throw std::runtime_error("cold reset requires previous run");
    return run_guest(store, root, load_profile(root, r.at("profile")), r);
#else
    return {{"status", "capability_blocked"},
            {"diagnostic", "Use the Linux CLI in WSL; no Windows host fallback"}};
#endif
  }
  if (op == "list") {
    keys(r, {});
    J rows = J::array();
    for (const auto &e : fs::directory_iterator(root))
      if (e.is_directory() && fs::exists(e.path() / "receipt.json") && rows.size() < 64) {
        const auto record = J::parse(read(e.path() / "receipt.json", 65536));
        rows.push_back({{"id", record.at("id")},
                        {"status", record.at("status")},
                        {"stopped_verified", record.value("stopped_verified", false)}});
      }
    return {{"runs", rows}, {"partial", rows.size() == 64}};
  }
  keys(r, op == "export" ? std::initializer_list<const char *>{"id", "project"}
                         : std::initializer_list<const char *>{"id"});
  const auto id = r.at("id").get<std::string>();
  identifier(id);
  const auto path = root / id;
  if (op == "show") {
    if (fs::exists(path / "receipt.json"))
      return J::parse(read(path / "receipt.json", 65536));
    return load_profile(root, r.at("id"));
  }
  if (!fs::exists(path / "receipt.json"))
    throw std::runtime_error("unknown guest run");
  if (op == "export") {
    const auto receipt = J::parse(read(path / "receipt.json", 65536));
    const auto file = path / "serial.bin";
    if (!receipt.value("stopped_verified", false) ||
        !fs::is_regular_file(fs::symlink_status(file)) ||
        sha256_file(file) != receipt.at("serial").at("sha256").get<std::string>())
      throw std::runtime_error("guest output is unavailable or changed");
    const auto target = store.import_target(r.at("project").get<std::string>(), file);
    const J lineage{{"schema", "indago.guest-output-lineage.v1"},
                    {"guest_run", id},
                    {"profile_sha256", receipt.at("profile_sha256")},
                    {"parent_artifact_sha256", receipt.at("base_sha256")},
                    {"output_artifact_sha256", target.sha256},
                    {"channel", "serial"},
                    {"partial", receipt.at("serial").at("partial")},
                    {"semantic_equivalence", false}};
    store.record_derivation(target, lineage);
    return {{"target_id", target.id},
            {"artifact_sha256", target.sha256},
            {"lineage", lineage}};
  }
  if (op == "cancel") {
    atomic_write(path / "cancel", "cancel");
    return {
        {"id", id}, {"status", "cancellation_requested"}, {"stopped_verified", false}};
  }
  if (op == "reconcile") {
#ifdef __linux__
    auto receipt = J::parse(read(path / "receipt.json", 65536));
    if (receipt.value("stopped_verified", false))
      return receipt;
    if (now_ms() <= receipt.at("deadline_ms").get<std::int64_t>())
      return {{"id", id},
              {"status", "still_within_worker_deadline"},
              {"stopped_verified", false}};
    const auto unit = "indago-" + id;
    if (receipt.at("resource_unit") != unit)
      throw std::runtime_error("guest resource unit mismatch");
    NativeProcessOptions options;
    options.wall_time_ms = 2000;
    options.max_output_bytes = 1024;
    const auto state = run_native_process(
        "/usr/bin/systemctl",
        {"--user", "show", "--property=ActiveState", "--value", unit + ".service"},
        options);
    const bool stopped = !state.timed_out && !state.cancelled &&
                         (state.output == "inactive\n" || state.output == "failed\n" ||
                          (state.exit_code != 0 &&
                           state.error.find("could not be found") != std::string::npos));
    if (!stopped)
      return {{"id", id}, {"status", "cleanup_uncertain"}, {"stopped_verified", false}};
    receipt["status"] = "interrupted";
    receipt["stopped_verified"] = true;
    receipt["outcome_unknown"] = true;
    receipt["reconciled_at_ms"] = now_ms();
    atomic_write(path / "receipt.json", receipt.dump());
    return receipt;
#else
    throw std::runtime_error("guest reconciliation requires Linux worker host");
#endif
  }
  if (op == "prune") {
    const auto receipt = J::parse(read(path / "receipt.json", 65536));
    if (!receipt.value("stopped_verified", false))
      throw std::runtime_error("cannot prune a run without verified stop");
    bool staging_removed = false;
#ifdef __linux__
    const fs::path staging = receipt.value("private_staging", std::string{});
    if (!staging.empty() && fs::exists(staging)) {
      const auto name = staging.filename().string();
      if (fs::is_symlink(staging) || !fs::is_directory(staging) || name.size() != 19 ||
          name.rfind("indago-guest-", 0) != 0 ||
          fs::canonical(staging).parent_path() != fs::canonical("/tmp") ||
          !fs::is_regular_file(fs::symlink_status(staging / ".indago-owner")) ||
          fs::hard_link_count(staging / ".indago-owner") != 1 ||
          read(staging / ".indago-owner", 128) != id)
        throw std::runtime_error("private guest staging identity is not safe to prune");
      NativeProcessOptions check;
      check.wall_time_ms = 2000;
      check.max_output_bytes = 1024;
      const auto state = run_native_process("/usr/bin/systemctl",
                                            {"--user", "show", "--property=ActiveState",
                                             "--value", "indago-" + id + ".service"},
                                            check);
      if (state.timed_out || state.cancelled ||
          !(state.output == "inactive\n" || state.output == "failed\n" ||
            (state.exit_code != 0 &&
             state.error.find("could not be found") != std::string::npos)))
        throw std::runtime_error("guest unit termination is not confirmed");
      fs::remove_all(fs::canonical(staging));
      staging_removed = true;
    }
#endif
    std::uintmax_t removed = 0;
    for (const char *name : {"overlay.qcow2", "serial.bin", "replay.bin"})
      if (fs::exists(path / name)) {
        removed += fs::file_size(path / name);
        fs::remove(path / name);
      }
    return {{"id", id},
            {"removed_bytes", removed},
            {"private_staging_removed", staging_removed},
            {"receipt_retained", true},
            {"recoverable", false}};
  }
  throw std::runtime_error("unknown guest operation");
}
} // namespace indago
