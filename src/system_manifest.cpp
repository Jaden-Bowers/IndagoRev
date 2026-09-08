#include "workbench_db.hpp"
#include <algorithm>
#include <cctype>

namespace indago::wb {
namespace {
std::string field(const J &r, const char *key, std::size_t maximum = 1024) {
  auto s = r.at(key).get<std::string>();
  if (s.empty() || s.size() > maximum || s.find('\0') != s.npos)
    throw std::runtime_error(std::string("invalid manifest field: ") + key);
  return s;
}
void array(const J &r, std::size_t maximum) {
  if (!r.is_array() || r.size() > maximum)
    throw std::runtime_error("manifest list exceeds its bound");
}
std::string guest_path(std::string path, bool windows) {
  std::replace(path.begin(), path.end(), '\\', '/');
  if (path.empty() || path.size() > 512 || path.front() == '/' ||
      path.back() == '/')
    throw std::runtime_error("guest path must be a bounded relative path");
  for (unsigned char c : path)
    if (c < 32 || c == 127 || (windows && c >= 128) ||
        std::string_view(":<>\"|?*").find(c) != std::string_view::npos)
      throw std::runtime_error("invalid guest path character");
  for (std::size_t start = 0; start < path.size();) {
    auto end = path.find('/', start);
    if (end == path.npos)
      end = path.size();
    auto part = path.substr(start, end - start);
    if (part.empty() || part == "." || part == ".." || part.back() == '.' ||
        part.back() == ' ')
      throw std::runtime_error("guest path contains unsafe segment");
    if (windows) {
      auto stem = part.substr(0, part.find('.'));
      for (auto &c : stem)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
      if (std::set<std::string>{"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
              .contains(stem) ||
          (stem.size() == 4 &&
           (stem.starts_with("COM") || stem.starts_with("LPT")) &&
           stem[3] >= '1' && stem[3] <= '9'))
        throw std::runtime_error(
            "guest path contains a reserved Windows device name");
    }
    start = end + 1;
  }
  return path;
}
J canonical_manifest(const ProjectStore &store, const std::string &p,
                     const J &input) {
  keys(input, {"os", "architecture", "components", "launches", "environment",
               "requirements", "isolation", "network", "reset", "limits"});
  const auto os = field(input, "os", 16),
             architecture = field(input, "architecture", 16);
  if (!std::set<std::string>{"windows", "linux"}.contains(os) ||
      !std::set<std::string>{"x86", "x64", "mixed"}.contains(architecture))
    throw std::runtime_error("manifest supports Windows/Linux x86/x64 only");
  if (input.value("isolation", std::string("vm")) != "vm" ||
      input.value("reset", std::string("snapshot")) != "snapshot")
    throw std::runtime_error("manifest requires a disposable VM snapshot; "
                             "host/WSL execution is not granted");
  auto network = input.value("network", std::string("disconnected"));
  if (network != "disconnected" && network != "simulated")
    throw std::runtime_error("manifest does not grant external networking");
  const auto &source = input.at("components");
  array(source, 32);
  if (source.empty())
    throw std::runtime_error("manifest needs at least one imported component");
  J components = J::array();
  std::set<std::string> names, paths;
  for (const auto &c : source) {
    keys(c, {"name", "target_id", "artifact_sha256", "role", "path"});
    auto name = field(c, "name", 64);
    identifier(name);
    if (!names.insert(name).second)
      throw std::runtime_error("duplicate component name");
    auto t = store.target(p, field(c, "target_id", 128), false);
    if (c.contains("artifact_sha256") && c.at("artifact_sha256") != t.sha256)
      throw std::runtime_error("component target/hash mismatch");
    auto role = field(c, "role", 16);
    if (!std::set<std::string>{"program", "service", "library", "driver",
                               "data"}
             .contains(role))
      throw std::runtime_error("unsupported component role");
    auto path = guest_path(field(c, "path", 512), os == "windows"), key = path;
    if (os == "windows")
      for (auto &ch : key)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    for (const auto &existing : paths)
      if (key.starts_with(existing + "/") || existing.starts_with(key + "/"))
        throw std::runtime_error(
            "guest component paths overlap a file and directory");
    if (!paths.insert(key).second)
      throw std::runtime_error("duplicate guest component path");
    components.push_back({{"name", name},
                          {"target_id", t.id},
                          {"artifact_sha256", t.sha256},
                          {"bytes", t.size},
                          {"role", role},
                          {"path", path}});
  }
  auto launches = input.value("launches", J::array());
  array(launches, 32);
  std::map<std::string, J> launches_by_name;
  for (auto &launch : launches) {
    keys(launch, {"name", "component", "argv", "depends_on", "readiness",
                  "stdin_component"});
    auto name = field(launch, "name", 64);
    identifier(name);
    auto component = field(launch, "component", 64);
    if (!names.contains(component))
      throw std::runtime_error("launch references unknown component");
    for (const auto &c : components)
      if (c.at("name") == component &&
          (c.at("role") == "library" || c.at("role") == "data"))
        throw std::runtime_error(
            "launch requires a program, service or driver component");
    auto argv = launch.value("argv", J::array());
    array(argv, 32);
    for (const auto &arg : argv)
      if (!arg.is_string() ||
          arg.get_ref<const std::string &>().size() > 1024 ||
          arg.get_ref<const std::string &>().find('\0') != std::string::npos)
        throw std::runtime_error("invalid literal launch argument");
    launch["argv"] = argv;
    auto depends = launch.value("depends_on", J::array());
    array(depends, 32);
    std::set<std::string> dependencies;
    for (const auto &d : depends)
      if (!d.is_string() || !dependencies.insert(d.get<std::string>()).second)
        throw std::runtime_error("duplicate or invalid launch dependency");
    launch["depends_on"] = depends;
    auto readiness = launch.value("readiness", std::string("process_started"));
    if (!std::set<std::string>{"process_started", "service_ready",
                               "operator_signal"}
             .contains(readiness))
      throw std::runtime_error("unsupported readiness obligation");
    launch["readiness"] = readiness;
    if (launch.contains("stdin_component") &&
        !names.contains(field(launch, "stdin_component", 64)))
      throw std::runtime_error("stdin references unknown component");
    if (!launches_by_name.emplace(name, launch).second)
      throw std::runtime_error("duplicate launch name");
  }
  J order = J::array();
  std::set<std::string> scheduled;
  while (scheduled.size() < launches_by_name.size()) {
    bool progress = false;
    for (const auto &[name, launch] : launches_by_name) {
      if (scheduled.contains(name))
        continue;
      bool ready = true;
      for (const auto &d : launch.at("depends_on")) {
        if (!launches_by_name.contains(d.get<std::string>()))
          throw std::runtime_error("unknown launch dependency");
        ready &= scheduled.contains(d.get<std::string>());
      }
      if (ready) {
        scheduled.insert(name);
        order.push_back(name);
        progress = true;
      }
    }
    if (!progress)
      throw std::runtime_error("cyclic launch dependencies");
  }
  auto environment = input.value("environment", J::object());
  if (!environment.is_object() || environment.size() > 32)
    throw std::runtime_error("environment exceeds 32 entries");
  std::set<std::string> environment_names;
  for (auto it = environment.begin(); it != environment.end(); ++it) {
    identifier(it.key());
    auto name = it.key();
    if (os == "windows")
      for (auto &c : name)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    if (!environment_names.insert(name).second)
      throw std::runtime_error("duplicate case-folded environment variable");
    keys(it.value(), {"value", "secret_ref"});
    if (it.value().contains("value") == it.value().contains("secret_ref"))
      throw std::runtime_error("environment requires exactly one literal value "
                               "or unresolved secret_ref");
    if (it.value().contains("value")) {
      const auto value = it.value().at("value").get<std::string>();
      if (value.size() > 1024 || value.find('\0') != value.npos)
        throw std::runtime_error("invalid literal environment value");
    } else
      field(it.value(), "secret_ref", 1024);
  }
  auto requirements = input.value("requirements", J::array());
  array(requirements, 64);
  for (const auto &r : requirements) {
    keys(r, {"kind", "name", "version"});
    field(r, "name", 256);
    if (!std::set<std::string>{"runtime", "service", "device", "secret",
                               "endpoint", "kernel_profile"}
             .contains(field(r, "kind", 32)))
      throw std::runtime_error("unsupported environment requirement kind");
    if (r.contains("version"))
      field(r, "version", 128);
  }
  auto limits = input.value("limits", J::object());
  keys(limits, {"wall_ms", "capture_bytes", "events", "memory_bytes"});
  limits = {
      {"wall_ms", bound(limits, "wall_ms", 60000, 600000)},
      {"capture_bytes", bound(limits, "capture_bytes", 16777216, 536870912)},
      {"events", bound(limits, "events", 10000, 1000000)},
      {"memory_bytes",
       bound(limits, "memory_bytes", 2147483648ULL, 8589934592ULL)}};
  for (const auto &limit : limits)
    if (limit == 0)
      throw std::runtime_error("manifest limits must be positive");
  J manifest{{"schema", "indago.system-manifest.v1"},
             {"os", os},
             {"architecture", architecture},
             {"components", components},
             {"launches", launches},
             {"launch_order", order},
             {"environment", environment},
             {"requirements", requirements},
             {"isolation", "vm"},
             {"network", network},
             {"reset", "snapshot"},
             {"limits", limits}};
  manifest["sha256"] = sha256_text(manifest.dump());
  return manifest;
}
} // namespace
J system_manifest(const ProjectStore &store, const std::string &op,
                  const J &r) {
  const auto p = project(store, r);
  if (op == "create") {
    keys(r, {"project", "title", "manifest"});
    if (r.at("manifest").dump().size() > 65536)
      throw std::runtime_error("system manifest exceeds 64 KiB");
    auto manifest = canonical_manifest(store, p, r.at("manifest"));
    J deps = J::array();
    for (const auto &c : manifest.at("components"))
      deps.push_back({{"type", "artifact"}, {"id", c.at("artifact_sha256")}});
    return knowledge_put(
        store,
        {{"project", p},
         {"kind", "system_manifest"},
         {"title", r.value("title", std::string("Target system manifest"))},
         {"state", "derived"},
         {"scope",
          {{"artifact_sha256",
            manifest.at("components")[0].at("artifact_sha256")}}},
         {"body", manifest},
         {"dependencies", deps},
         {"assumptions", J::array({"Operator declarations; not lab attestation "
                                   "or execution authority"})}},
        true);
  }
  if (op == "list") {
    keys(r, {"project", "limit", "offset"});
    auto q = r;
    q["kind"] = "system_manifest";
    return knowledge(store, "list", q);
  }
  keys(r, {"project", "id", "max_bytes"});
  if (op != "show" && op != "preflight")
    throw std::runtime_error("unknown system manifest operation");
  auto record =
      knowledge(store, "show", {{"project", p}, {"id", field(r, "id", 128)}});
  if (record.at("kind") != "system_manifest")
    throw std::runtime_error("record is not a system manifest");
  auto manifest = record.at("body");
  const auto digest = manifest.at("sha256");
  manifest.erase("sha256");
  if (digest != sha256_text(manifest.dump()))
    throw std::runtime_error("system manifest digest mismatch");
  if (op == "show")
    return record;
  auto remaining = bound(r, "max_bytes", 16777216, 67108864);
  const auto budget = remaining;
  J artifacts = J::array();
  bool partial = false;
  std::map<std::string, std::string> integrity;
  for (const auto &c : manifest.at("components")) {
    std::string status;
    try {
      auto t = store.target(p, c.at("target_id").get<std::string>(), false);
      if (c.at("artifact_sha256") != t.sha256 || c.at("bytes") != t.size)
        throw std::runtime_error("identity mismatch");
      if (integrity.contains(t.sha256))
        status = integrity.at(t.sha256);
      else if (t.size > remaining) {
        status = "not_checked_byte_budget";
        partial = true;
      } else {
        remaining -= t.size;
        const auto bytes = read(t.object_path, t.size);
        status = bytes.size() == t.size && sha256_text(bytes) == t.sha256
                     ? "verified"
                     : "integrity_mismatch";
        integrity[t.sha256] = status;
      }
    } catch (...) {
      status = "unavailable_or_identity_mismatch";
    }
    if (status != "verified")
      partial = true;
    artifacts.push_back({{"component", c.at("name")},
                         {"artifact_sha256", c.at("artifact_sha256")},
                         {"integrity", status}});
  }
  J gaps =
      J::array({"No disposable lab provider allocation/attestation is bound to "
                "this manifest",
                "Guest snapshot identity and verified reset are unavailable",
                "Network isolation has not been enforced outside a guest",
                "Guest architecture, runtimes, privileges and declared "
                "requirements are not attested"});
  if (manifest.at("launches").empty())
    gaps.push_back("No launch entry points declared");
  if (partial)
    gaps.push_back(
        "One or more component integrity checks are incomplete or failed");
  return {{"schema", "indago.system-preflight.v1"},
          {"status", "capability_blocked"},
          {"manifest_id", record.at("id")},
          {"manifest_sha256", digest},
          {"ready_for_execution", false},
          {"target_execution", false},
          {"partial", partial},
          {"hashed_bytes", budget - remaining},
          {"artifacts", artifacts},
          {"launch_order", manifest.at("launch_order")},
          {"gaps", gaps}};
}
} // namespace indago::wb
