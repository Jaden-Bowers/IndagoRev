#include "workbench_db.hpp"
#include <algorithm>

namespace indago::wb {
namespace {
std::string unhex(const std::string &input) {
  if (input.size() % 2 || input.size() > 8 * 1024 * 1024 ||
      input.find_first_not_of("0123456789abcdefABCDEF") != input.npos)
    throw std::runtime_error("invalid bounded hexadecimal input");
  std::string out;
  out.reserve(input.size() / 2);
  auto val = [](char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; };
  for (std::size_t i = 0; i < input.size(); i += 2)
    out.push_back(static_cast<char>((val(input[i]) << 4) | val(input[i + 1])));
  return out;
}
std::string hex(std::string_view b) {
  static constexpr char h[] = "0123456789abcdef";
  std::string out;
  for (unsigned char c : b) {
    out += h[c >> 4];
    out += h[c & 15];
  }
  return out;
}
std::string transform(std::string input, const J &spec) {
  keys(spec, {"method", "key_hex"});
  auto method = spec.at("method").get<std::string>();
  if (method == "slice")
    return input;
  if (method == "xor") {
    auto key = unhex(spec.at("key_hex").get<std::string>());
    if (key.empty() || key.size() > 4096)
      throw std::runtime_error("XOR key must be 1..4096 bytes");
    for (std::size_t i = 0; i < input.size(); ++i)
      input[i] =
          static_cast<char>(static_cast<unsigned char>(input[i]) ^
                            static_cast<unsigned char>(key[i % key.size()]));
    return input;
  }
  if (method == "hex_decode")
    return unhex(input);
  if (method == "base64_decode") {
    static const std::string alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (input.size() % 4)
      throw std::runtime_error("base64 requires canonical padded groups");
    std::string out;
    for (std::size_t i = 0; i < input.size(); i += 4) {
      unsigned acc = 0, padding = 0;
      for (unsigned j = 0; j < 4; ++j) {
        auto c = input[i + j];
        if (c == '=') {
          if (i + 4 != input.size() || j < 2)
            throw std::runtime_error("invalid base64 padding");
          ++padding;
          acc <<= 6;
        } else {
          auto n = alphabet.find(c);
          if (n == alphabet.npos || padding)
            throw std::runtime_error("invalid base64 symbol");
          acc = (acc << 6) | static_cast<unsigned>(n);
        }
      }
      if (padding > 2 || (padding == 2 && (acc & 0xffff)) ||
          (padding == 1 && (acc & 0xff)))
        throw std::runtime_error("noncanonical base64 padding bits");
      out += static_cast<char>(acc >> 16);
      if (padding < 2)
        out += static_cast<char>(acc >> 8);
      if (!padding)
        out += static_cast<char>(acc);
    }
    return out;
  }
  throw std::runtime_error("unsupported transformation");
}
J dependency(const std::string &artifact) {
  return {{"type", "artifact"}, {"id", artifact}};
}
std::string artifact_bytes(const ProjectStore &store, const std::string &p,
                           const std::string &sha, std::size_t max) {
  hash(sha);
  Db db(store.root() / "indago-native.sqlite3");
  Q q(db, "SELECT 1 FROM targets WHERE project=? AND sha=?");
  if (!q.s(1, p).s(2, sha).row())
    throw std::runtime_error("unknown project artifact");
  auto path = object(store, sha);
  auto b = read(path, max);
  if (sha256_text(b) != sha)
    throw std::runtime_error("artifact integrity mismatch");
  return b;
}
} // namespace
J candidate_transform(const std::string &input,const std::string &representation,const J &spec) {
  if(input.size()>1024||(representation!="hex"&&representation!="utf8"))throw std::runtime_error("Candidate transform requires <=1024 bytes and explicit hex or utf8 representation");
  const auto bytes=representation=="hex"?unhex(input):input;
  const auto output=transform(bytes,spec);
  if(output.size()>512)throw std::runtime_error("Candidate transform output exceeds 512 bytes");
  return {{"hex",hex(output)},{"input_sha256",sha256_text(bytes)},{"spec",spec},
    {"engine","indago.transforms.v1"},{"byte_width",8},{"target_execution",false},{"acceptance_proven",false}};
}
J artifacts(const ProjectStore &store, const std::string &family,
            const std::string &op, const J &r) {
  auto p = project(store, r);
  if (family == "transform") {
    if (op != "run")
      throw std::runtime_error("unknown transform operation");
    keys(r, {"project", "artifact", "offset", "size", "spec", "title",
             "assumptions"});
    auto sha = r.at("artifact").get<std::string>();
    auto input = artifact_bytes(store, p, sha, 16 * 1024 * 1024);
    auto offset = bound(r, "offset", 0, input.size()),
         size = bound(r, "size", input.size() - offset, 4 * 1024 * 1024);
    if (size > input.size() - offset)
      throw std::runtime_error("transform input range exceeds artifact");
    const auto spec = r.at("spec");
    auto output = transform(input.substr(offset, size), spec);
    auto previous_selection = store.target(p, "", false).id;
    auto stage = store.root() / "staging" / make_id("derived");
    atomic_write(stage, output);
    TargetRecord target;
    try {
      target = store.import_target(p, stage);
      fs::remove(stage);
    } catch (...) {
      fs::remove(stage);
      throw;
    }
    J mapping{{"input_artifact", sha},
              {"input_offset", offset},
              {"input_size", size},
              {"output_offset", 0},
              {"output_size", output.size()},
              {"method", spec["method"]},
              {"mapping", spec["method"] == "slice" || spec["method"] == "xor"
                              ? "one output byte per input byte"
                              : "encoded groups to decoded bytes; no "
                                "instruction identity implied"}};
    J lineage{{"kind", "deterministic_transformation"},
              {"engine", "indago.transforms.v1"},
              {"spec", spec},
              {"input_artifact", sha},
              {"mapping", mapping},
              {"output_artifact", target.sha256},
              {"assumptions", r.value("assumptions", J::array())},
              {"execution_claim", "bytes transformed only; no target execution "
                                  "or behavioral equivalence"}};
    store.record_derivation(target, lineage);
    auto record = knowledge_put(
        store,
        {{"project", p},
         {"kind", "transformation"},
         {"title", r.value("title", std::string("Derived byte artifact"))},
         {"state", "derived"},
         {"scope", {{"artifact_sha256", target.sha256}}},
         {"body", lineage},
         {"dependencies", J::array({dependency(sha)})},
         {"assumptions", r.value("assumptions", J::array())}},
        true);
    return {{"schema", "indago.transformation.v1"},
            {"status", "completed"},
            {"artifact_sha256", target.sha256},
            {"target_id", target.id},
            {"record", record},
            {"mapping", mapping},
            {"target_selection_changed",
             store.target(p, "", false).id != previous_selection}};
  }
  if (family == "validate") {
    if (op != "compare" && op != "transform")
      throw std::runtime_error("validator must be compare or transform");
    keys(r, {"project", "subject", "cases", "spec", "title", "scope",
             "dependencies"});
    auto cases = r.at("cases");
    if (!cases.is_array() || cases.empty() || cases.size() > 64)
      throw std::runtime_error("1..64 validation cases required");
    J results = J::array(), deps = J::array();
    bool passed = true;
    std::size_t total = 0;
    if (r.contains("dependencies")) {
      const auto &pins = r.at("dependencies");
      if (!r.contains("subject") || !pins.is_array() || pins.size() != 1 ||
          pins[0].value("type", std::string{}) != "record" ||
          pins[0].at("id") != r.at("subject") || !pins[0].contains("pin"))
        throw std::runtime_error(
            "validator dependencies must pin exactly its subject record");
      deps.push_back(pins[0]);
    } else if (r.contains("subject"))
      deps.push_back({{"type", "record"}, {"id", r["subject"]}});
    for (const auto &c : cases) {
      keys(c, {"input_artifact", "actual_artifact", "expected_artifact",
               "expected_hex", "label"});
      std::string actual;
      auto source =
          c.at(op == "transform" ? "input_artifact" : "actual_artifact")
              .get<std::string>();
      auto input = artifact_bytes(store, p, source, 4 * 1024 * 1024);
      actual = op == "transform" ? transform(input, r.at("spec")) : input;
      deps.push_back(dependency(source));
      if (c.contains("expected_artifact") == c.contains("expected_hex"))
        throw std::runtime_error(
            "exactly one expected representation required");
      std::string expected;
      if (c.contains("expected_hex"))
        expected = unhex(c["expected_hex"]);
      else {
        auto sha = c["expected_artifact"].get<std::string>();
        expected = artifact_bytes(store, p, sha, 4 * 1024 * 1024);
        deps.push_back(dependency(sha));
      }
      total += actual.size() + expected.size();
      if (total > 16 * 1024 * 1024)
        throw std::runtime_error("validation aggregate exceeds 16 MiB");
      bool same = actual == expected;
      passed = passed && same;
      J result{{"label", c.value("label", std::string{})},
               {"input_artifact", source},
               {"actual_sha256", sha256_text(actual)},
               {"expected_sha256", sha256_text(expected)},
               {"actual_size", actual.size()},
               {"expected_size", expected.size()},
               {"passed", same}};
      if (!same) {
        auto offset = std::mismatch(actual.begin(), actual.end(),
                                    expected.begin(), expected.end())
                          .first -
                      actual.begin();
        result["counterexample"] = {
            {"first_difference", offset},
            {"actual_hex", hex(std::string_view(actual).substr(offset, 16))},
            {"expected_hex",
             hex(std::string_view(expected).substr(
                 std::min<std::size_t>(offset, expected.size()), 16))}};
      }
      results.push_back(result);
    }
    J body{{"validator", op == "transform" ? "indago.transform-v1/exact-bytes"
                                           : "indago.exact-bytes-v1"},
           {"passed", passed},
           {"cases", results},
           {"test_spec", r},
           {"scope_limit",
            "exact byte equality for supplied finite cases; expected outputs "
            "are caller-supplied, not independent semantic truth"}};
    return knowledge_put(
        store,
        {{"project", p},
         {"kind", "validation"},
         {"title", r.value("title", std::string("Finite byte validation"))},
         {"state", passed ? "validated" : "contradicted"},
         {"scope", r.at("scope")},
         {"body", body},
         {"dependencies", deps}},
        true);
  }
  if (family == "recognize") {
    if (op != "scan")
      throw std::runtime_error("unknown recognition operation");
    keys(r, {"project", "artifact", "limit", "scan_limit", "publish"});
    auto sha = r.at("artifact").get<std::string>();
    auto input = artifact_bytes(store, p, sha, 64 * 1024 * 1024);
    auto limit = bound(r, "limit", 100, 1000),
         scan = bound(r, "scan_limit", 10000, 100000);
    J findings = J::array();
    bool partial = false;
    auto add = [&](J f) {
      if (findings.size() < limit)
        findings.push_back(f);
      else
        partial = true;
    };
    // Transparent recognition hints. A string match never proves language
    // ownership or behavior.
    for (const auto &[needle, label] :
         std::vector<std::pair<std::string, std::string>>{
             {"Go build ID:", "Go toolchain marker"},
             {".gopclntab", "Go runtime table marker"},
             {"rust_eh_personality", "Rust runtime symbol marker"},
             {".rustc", "Rust metadata section marker"},
             {"__gxx_personality_v0", "GCC C++ exception runtime marker"},
             {"__CxxFrameHandler", "MSVC C++ exception runtime marker"},
             {"vcruntime", "MSVC runtime dependency marker"},
             {"mscoree.dll", "CLR loader dependency marker"}}) {
      auto offset = input.find(needle);
      if (offset != input.npos)
        add({{"kind", "runtime_marker"},
             {"label", label},
             {"match", needle},
             {"file_offset", offset},
             {"artifact_sha256", sha},
             {"method", "literal bytes, indago.recognition.v1"},
             {"verdict",
              "candidate; marker may be unused, embedded or misleading"}});
    }
    std::size_t offset = 0;
    while (offset < scan) {
      auto q = store.index_query(
          p, {{"artifact", sha},
              {"limit", std::min<std::size_t>(1000, scan - offset)},
              {"offset", offset}});
      for (const auto &e : q["records"]) {
        auto name = e.value("name", std::string{});
        for (const auto &[prefix, label] :
             std::vector<std::pair<std::string, std::string>>{
                 {"__scrt_", "MSVC startup"},
                 {"_init", "initialization candidate"},
                 {"__cxa_", "C++ ABI support"},
                 {"runtime.", "Go runtime candidate"},
                 {"std::", "C++ standard library candidate"}})
          if (name.starts_with(prefix))
            add({{"kind", "symbol_family"},
                 {"label", label},
                 {"entity_id", e["id"]},
                 {"evidence_id", e["evidence_id"]},
                 {"location", e["location"]},
                 {"name", name},
                 {"method", "name-prefix hint"},
                 {"verdict", "candidate; symbol text is untrusted and not an "
                             "implementation fingerprint"}});
      }
      offset += q["records"].size();
      if (q["next_offset"].is_null())
        break;
      if (q["records"].empty())
        break;
      if (offset >= scan)
        partial = true;
    }
    auto signatures = knowledge(
        store, "list", {{"project", p}, {"kind", "signature"}, {"limit", 200}});
    partial = partial || !signatures["next_offset"].is_null();
    for (const auto &s : signatures["records"]) {
      auto b = s["body"];
      if (!b.contains("sha256"))
        continue;
      auto start = bound(b, "offset", 0, 512ULL * 1024 * 1024);
      if (start > input.size())
        continue;
      auto size = bound(b, "size", input.size() - start, 512ULL * 1024 * 1024);
      if (size > input.size() - start)
        continue;
      auto matched = sha256_text(std::string_view(input).substr(start, size));
      if (matched == b["sha256"].get<std::string>())
        add({{"kind", "exact_bytes_signature"},
             {"label", s["title"]},
             {"signature", s["id"]},
             {"signature_revision", s["revision"]},
             {"signature_freshness", s["freshness"]},
             {"file_offset", start},
             {"size", size},
             {"sha256", matched},
             {"method", "exact SHA-256 range"},
             {"verdict", "exact byte match to caller-labeled reference; "
                         "label/provenance not independently verified"}});
    }
    J result{{"schema", "indago.recognition.v1"},
             {"findings", findings},
             {"partial", partial},
             {"policy", "navigation hints only; no library code suppressed or "
                        "application behavior inferred"}};
    if (r.value("publish", false)) {
      J deps = J::array({dependency(sha)});
      for (const auto &f : findings) {
        if (f.contains("evidence_id"))
          deps.push_back({{"type", "evidence"}, {"id", f["evidence_id"]}});
        if (f.contains("signature"))
          deps.push_back(
              {{"type", "record"},
               {"id", f["signature"]},
               {"pin", std::to_string(f["signature_revision"].get<int>())}});
      }
      if (deps.size() > 128)
        throw std::runtime_error("reduce limit to publish <=128 dependencies");
      result["record"] =
          knowledge_put(store,
                        {{"project", p},
                         {"kind", "recognition"},
                         {"title", "Library/runtime recognition candidates"},
                         {"state", "inferred"},
                         {"scope", {{"artifact_sha256", sha}}},
                         {"body", result},
                         {"dependencies", deps}},
                        true);
    }
    return result;
  }
  throw std::runtime_error("unknown artifact operation family");
}
} // namespace indago::wb
