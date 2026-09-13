#pragma once
#include "indago/core.hpp"
#include <set>
namespace indago {
inline nlohmann::json stage_runtime_inputs(const fs::path &directory,
                                           nlohmann::json r) {
  using J = nlohmann::json;
  auto decode = [](const J &v) {
    const auto s = v.get<std::string>();
    std::string out;
    if (s.size() > 8192 || s.size() % 2 ||
        s.find_first_not_of("0123456789abcdef") != s.npos)
      throw std::runtime_error("invalid bounded runtime input");
    for (std::size_t i = 0; i < s.size(); i += 2)
      out += static_cast<char>(std::stoul(s.substr(i, 2), nullptr, 16));
    return out;
  };
  const auto files = r.value("files", J::object()),
             env = r.value("environment", J::object());
  if (!files.is_object() || files.size() > 4 || !env.is_object() ||
      env.size() > 16)
    throw std::runtime_error("runtime input manifest bounds");
  for (auto it = env.begin(); it != env.end(); ++it) {
    const auto v = it.value().get<std::string>();
    if (it.key().empty() || it.key().size() > 64 ||
        it.key().find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") !=
            std::string::npos ||
        v.size() > 1024 || v.find('\0') != v.npos ||
        v.find_first_of("\r\n") != v.npos ||
        (!v.empty() && (v.front() == ' ' || v.back() == ' ')))
      throw std::runtime_error("invalid runtime environment");
    if (std::set<std::string>{"BASH_ENV", "ENV", "SHELL", "LD_PRELOAD",
                              "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
                              "GLIBC_TUNABLES"}
            .contains(it.key()))
      throw std::runtime_error(
          "runtime environment cannot inject shell or loader behavior");
  }
  if (r.contains("cwd"))
    throw std::runtime_error(
        "explicit input manifest owns its working directory");
  if (fs::exists(directory))
    throw std::runtime_error("refusing to reuse runtime input directory");
  fs::create_directories(directory);
  J manifest{{"schema", "indago.runtime-inputs.v1"},
             {"environment", env},
             {"files", J::object()},
             {"delivery", "prepared; not yet observed at target"}};
  for (auto it = files.begin(); it != files.end(); ++it) {
    if (it.key().empty() || it.key().size() > 64 ||
        it.key().find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ"
                                   "RSTUVWXYZ0123456789_-") !=
            std::string::npos)
      throw std::runtime_error("runtime file input requires plain filename");
    const auto bytes = decode(it.value());
    atomic_write(directory / it.key(), bytes);
    manifest["files"][it.key()] = sha256_text(bytes);
  }
  const auto input = decode(r.value("input_hex", J("")));
  atomic_write(directory / ".stdin", input);
  manifest["stdin_sha256"] = sha256_text(input);
  manifest["argv"] = r.value("argv", J::array());
  r["environment"] = env;
  r["cwd"] = directory.string();
  r["stdin_file"] = (directory / ".stdin").string();
  r["stdout_file"] = (directory / ".stdout").string();
  r["stderr_file"] = (directory / ".stderr").string();
  r["input_manifest"] = manifest;
  r["input_manifest_sha256"] = sha256_text(manifest.dump());
  return r;
}
} // namespace indago
