#include "research_workflow.hpp"
#include "benchmark.hpp"
#include "harness_artifact_read.hpp"
namespace indago {
using namespace wb;
namespace {
void text_limit(const J &v, std::size_t n = 2048) {
  if (!v.is_string() || v.get<std::string>().empty() || v.get<std::string>().size() > n)
    throw std::runtime_error("bounded nonempty text required");
}
void hex_limit(const J &v, std::size_t n = 4096) {
  if (!v.is_string())
    throw std::runtime_error("hex string required");
  const auto s = v.get<std::string>();
  if (s.size() > n * 2 || s.size() % 2 ||
      s.find_first_not_of("0123456789abcdef") != s.npos)
    throw std::runtime_error("invalid bounded lowercase hex");
}
std::string raw_hex(const std::string &h) {
  hex_limit(h);
  std::string out;
  for (std::size_t i = 0; i < h.size(); i += 2)
    out += static_cast<char>(std::stoul(h.substr(i, 2), nullptr, 16));
  return out;
}
J exact_record(const ProjectStore &store, const J &args, const J &ref) {
  keys(ref, {"id", "revision", "sha256"});
  Db db(store.root() / "indago-native.sqlite3");
  Q q(db, "SELECT record,sha FROM wb_records WHERE project=? AND id=? AND revision=?");
  if (!q.s(1, args.at("project").get<std::string>())
           .s(2, ref.at("id").get<std::string>())
           .n(3, ref.at("revision").get<std::int64_t>())
           .row())
    throw std::runtime_error("unknown exact research receipt");
  if (sha256_text(q.text(0)) != q.text(1) ||
      (ref.contains("sha256") && ref.at("sha256") != q.text(1)))
    throw std::runtime_error("research receipt integrity mismatch");
  auto r = J::parse(q.text(0));
  if (r.at("scope") != args.at("scope"))
    throw std::runtime_error("research receipt outside selected artifact scope");
  if (std::set<std::string>{"native-helper", "native-experiment", "native-research"}
          .contains(r.value("author", std::string{}))) {
    if (!r.contains("harness_origin"))
      throw std::runtime_error(
          "native research evidence requires committed harness publication");
    const auto &origin = r.at("harness_origin");
    Q action(db, "SELECT record FROM wb_investigation_actions WHERE project=? AND id=?");
    if (!action.s(1, args.at("project").get<std::string>())
             .s(2, origin.at("action").get<std::string>())
             .row())
      throw std::runtime_error("native publication action missing");
    const auto a = J::parse(action.text(0));
    const auto expected = r.at("author") == "native-helper"       ? "helper.run"
                          : r.at("author") == "native-experiment" ? "experiment.run"
                                                                  : "research.run";
    if (a.at("request").at("operation") != expected ||
        a.at("publication").at("sha256") != q.text(1) ||
        a.at("publication").at("knowledge_id") != r.at("id") ||
        a.at("publication").at("revision") != r.at("revision"))
      throw std::runtime_error("native publication origin mismatch");
  }
  return r;
}
void native_record(const J &r, const std::string &schema, const std::string &author) {
  if (r.at("kind") != "product" ||
      r.at("body").value("schema", std::string{}) != schema ||
      r.value("author", std::string{}) != author)
    throw std::runtime_error(
        "native typed receipt required; assertions are not observations");
}
J candidates(const J &spec) {
  const auto seed = spec.at("seed_hex").get<std::string>();
  hex_limit(seed, 64);
  const auto count = bound(spec, "count", 8, 16);
  if (count < 2)
    throw std::runtime_error("discriminating input count must be 2..16");
  J result = J::array();
  std::set<std::string> seen;
  auto add = [&](const std::string &h, const char *why) {
    if (result.size() < count && seen.insert(h).second)
      result.push_back(
          {{"input_hex", h}, {"rationale", why}, {"origin", "experimental_stimulus"}});
  };
  add(seed, "baseline");
  add("", "empty boundary");
  add(seed + "00", "length extension");
  if (seed.size() > 1)
    add(seed.substr(0, seed.size() - 2), "length truncation");
  const char *digits = "0123456789abcdef";
  for (std::size_t i = 0; i < seed.size() / 2 && result.size() < count; ++i)
    for (unsigned bit = 0; bit < 8 && result.size() < count; ++bit) {
      auto h = seed;
      auto value = static_cast<unsigned>(std::stoul(seed.substr(i * 2, 2), nullptr, 16)) ^
                   (1U << bit);
      h[i * 2] = digits[value >> 4];
      h[i * 2 + 1] = digits[value & 15];
      add(h, "single-bit perturbation");
    }
  for (unsigned v = 0; v < 256 && result.size() < count; ++v) {
    std::string h;
    h += digits[v >> 4];
    h += digits[v & 15];
    add(h, "byte boundary sweep");
  }
  return result;
}
J checked_body(const ProjectStore &store, const J &args) {
  const auto &s = args.at("body");
  const auto kind = s.at("kind").get<std::string>();
  J body{{"schema", "indago.research.v1"},
         {"kind", kind},
         {"request_sha256", sha256_text(args.dump())},
         {"verified_solve", false},
         {"universal_equivalence", false}};
  if (kind == "algorithm_candidate") {
    keys(s, {"kind", "domain", "assumptions", "evidence", "language", "source_code",
             "generator", "previous"});
    text_limit(s.at("domain"));
    text_limit(s.at("source_code"), 16384);
    if (!std::set<std::string>{"c17", "c++20", "python3", "smt2", "unicorn-x86"}.contains(
            s.at("language").get<std::string>()))
      throw std::runtime_error("unsupported algorithm helper language");
    if (!s.at("assumptions").is_array() || s.at("assumptions").size() > 16)
      throw std::runtime_error("algorithm assumptions bound");
    for (const auto &a : s.at("assumptions"))
      text_limit(a);
    if (!s.at("evidence").is_array() || s.at("evidence").empty() ||
        s.at("evidence").size() > 8)
      throw std::runtime_error("algorithm needs 1..8 exact evidence records");
    for (const auto &r : s.at("evidence"))
      (void)exact_record(store, args, r);
    keys(s.at("generator"), {"seed_hex", "count"});
    for (const char *k : {"domain", "assumptions", "evidence", "language", "source_code"})
      body[k] = s.at(k);
    body["source_sha256"] = sha256_text(s.at("source_code").get<std::string>());
    body["suggested_inputs"] = candidates(s.at("generator"));
    body["counterexamples"] = J::array();
    body["tested_domain"] = J::array();
    body["status"] = "candidate";
    if (s.contains("previous")) {
      const auto previous = exact_record(store, args, s.at("previous"));
      native_record(previous, "indago.research.v1", "native-research");
      if (previous.at("body").at("kind") != "algorithm_comparison")
        throw std::runtime_error("revision requires a prior comparison");
      body["previous"] = s.at("previous");
      body["counterexamples"] = previous.at("body").at("counterexamples");
      for (const auto &c : body.at("counterexamples"))
        if (body["suggested_inputs"].size() < 32)
          body["suggested_inputs"].push_back(
              {{"input_hex", c.at("input_hex")},
               {"rationale", "retained counterexample; must replay"},
               {"origin", "experimental_stimulus"}});
    }
    body["next_action"] =
        "Run this exact source in helper.run with input.generated_hex, run the same "
        "stdin on the granted original target through experiment.run, then submit exact "
        "receipt pairs to algorithm_comparison. Never substitute predicted target "
        "outputs.";
  } else if (kind == "algorithm_comparison") {
    keys(s, {"kind", "candidate", "pairs"});
    const auto candidate = exact_record(store, args, s.at("candidate"));
    native_record(candidate, "indago.research.v1", "native-research");
    const auto &c = candidate.at("body");
    if (c.at("kind") != "algorithm_candidate")
      throw std::runtime_error("algorithm candidate required");
    if (!s.at("pairs").is_array() || s.at("pairs").empty() || s.at("pairs").size() > 16)
      throw std::runtime_error("comparison allows 1..16 receipt pairs");
    body["candidate"] = s.at("candidate");
    body["domain"] = c.at("domain");
    body["assumptions"] = c.at("assumptions");
    body["counterexamples"] = c.at("counterexamples");
    body["tested_domain"] = J::array();
    std::set<std::string> tested;
    unsigned mismatches = 0, incomplete = 0;
    for (const auto &pair : s.at("pairs")) {
      keys(pair, {"helper", "experiment", "case"});
      const auto helper = exact_record(store, args, pair.at("helper")),
                 experiment = exact_record(store, args, pair.at("experiment"));
      native_record(helper, "indago.helper-run.v1", "native-helper");
      native_record(experiment, "indago.experiment.v1", "native-experiment");
      const auto &h = helper.at("body"), &e = experiment.at("body");
      if (h.at("source_sha256") != c.at("source_sha256") ||
          h.at("language") != c.at("language"))
        throw std::runtime_error("helper source differs from candidate");
      const auto index = bound(pair, "case", 0, 1);
      const auto &trial = e.at("cases").at(index);
      const auto input = trial.at("input").at("input_hex").get<std::string>();
      if (h.at("input").at("slice_sha256") != sha256_text(raw_hex(input)))
        throw std::runtime_error("helper and target inputs differ");
      if (!tested.insert(input).second)
        throw std::runtime_error("duplicate comparison input");
      J row{{"input_hex", input},
            {"helper", pair.at("helper")},
            {"experiment", pair.at("experiment")},
            {"case", index},
            {"agreement", false},
            {"complete", false},
            {"helper_status", h.at("status")},
            {"helper_diagnostic", h.value("untrusted_diagnostic_preview", std::string{})},
            {"target_status", trial.value("status", std::string("unknown"))}};
      if (h.value("repeatable_observed", false) &&
          h.value("source_current_at_publication", false) && trial.contains("state") &&
          trial.at("state").contains("observation")) {
        const auto &o = trial.at("state").at("observation").at("data");
        if (o.value("complete", false) &&
            trial.at("input").value("engine", std::string{}) == "io") {
          row["complete"] = true;
          row["actual_hex"] = h.at("output_hex");
          row["expected_hex"] = o.at("output_hex");
          row["agreement"] = row.at("actual_hex") == row.at("expected_hex");
          row["controls"] = trial.at("input");
        }
      }
      if (!row.at("complete").get<bool>())
        ++incomplete;
      else if (!row.at("agreement").get<bool>()) {
        ++mismatches;
        if (body["counterexamples"].size() < 64)
          body["counterexamples"].push_back(row);
        else
          throw std::runtime_error(
              "counterexample retention bound reached; split workflow");
      }
      body["tested_domain"].push_back(row);
    }
    J pending = J::array();
    for (const auto &old : c.at("counterexamples"))
      if (!tested.contains(old.at("input_hex").get<std::string>()))
        pending.push_back(old.at("input_hex"));
    body["unreplayed_counterexamples"] = pending;
    body["status"] = mismatches                       ? "counterexample"
                     : incomplete || !pending.empty() ? "incomplete"
                                                      : "agreement_on_tested_inputs";
    body["scope_limit"] =
        "Exact stdout agreement only on complete listed runs and controls. No "
        "success-branch, semantic, universal-equivalence or solve proof.";
    body["failure_category"] = mismatches         ? "candidate_disagreement"
                               : incomplete       ? "incomplete_observation"
                               : !pending.empty() ? "counterexample_not_replayed"
                                                  : "none";
    body["next_action"] =
        mismatches ? "Revise candidate with previous pointing to this comparison; replay "
                     "retained counterexamples."
        : incomplete
            ? "Read tested_domain helper_status/helper_diagnostic and target_status. "
              "Repair the failed helper or incomplete experiment before generating "
              "additional inputs; retain prior source and receipts."
        : !pending.empty() ? "Replay the listed retained counterexamples before claiming "
                             "tested agreement."
                           : "Generate new discriminating inputs or test a new "
                             "environment; do not infer universal equivalence.";
  } else if (kind == "service_contract") {
    keys(s, {"kind", "hypothesis", "responses", "reject_if", "previous"});
    text_limit(s.at("hypothesis"));
    if (!s.at("reject_if").is_array() || s.at("reject_if").empty() ||
        s.at("reject_if").size() > 16)
      throw std::runtime_error("service contract requires falsification observations");
    for (const auto &v : s.at("reject_if"))
      text_limit(v);
    if (!s.at("responses").is_array() || s.at("responses").empty() ||
        s.at("responses").size() > 16)
      throw std::runtime_error("bounded service responses required");
    body["hypothesis"] = s.at("hypothesis");
    body["reject_if"] = s.at("reject_if");
    body["responses"] = J::array();
    for (auto response : s.at("responses")) {
      keys(response,
           {"origin", "hex", "capture", "rationale", "variable_ranges", "timing"});
      hex_limit(response.at("hex"));
      text_limit(response.at("rationale"));
      const auto origin = response.at("origin").get<std::string>();
      if (!std::set<std::string>{"captured", "inferred", "invented_stimulus"}.contains(
              origin))
        throw std::runtime_error("explicit service origin required");
      if (origin == "captured") {
        const auto &ref = response.at("capture");
        keys(ref, {"target_id", "offset", "max_bytes"});
        const auto target = store.target(args.at("project").get<std::string>(),
                                         ref.at("target_id").get<std::string>(), true);
        auto page = harness_artifact_page(
            store, {{"target_id", target.id}, {"artifact_sha256", target.sha256}},
            {{"project", args.at("project")},
             {"offset", ref.at("offset")},
             {"max_bytes", ref.at("max_bytes")}},
            4096);
        if (page.at("hex") != response.at("hex"))
          throw std::runtime_error("captured response differs from admitted bytes");
        response["capture_pin"] = page;
        response["capture_interpretation"] =
            "Exact artifact bytes; service attribution and framing remain hypotheses, "
            "not independently observed endpoint behavior";
      } else if (response.contains("capture"))
        throw std::runtime_error("noncaptured responses cannot claim capture provenance");
      const auto &ranges = response.at("variable_ranges");
      if (!ranges.is_array() || ranges.size() > 16)
        throw std::runtime_error("variable range bound");
      std::size_t end = 0;
      for (const auto &range : ranges) {
        keys(range, {"offset", "length", "reason"});
        text_limit(range.at("reason"));
        const auto start = bound(range, "offset", 0, 4096),
                   length = bound(range, "length", 0, 4096);
        if (!length || start < end ||
            start + length > response.at("hex").get<std::string>().size() / 2)
          throw std::runtime_error("invalid overlapping variable ranges");
        end = start + length;
      }
      const auto &timing = response.at("timing");
      keys(timing, {"origin", "min_ms", "max_ms"});
      if (!std::set<std::string>{"unknown", "inferred", "invented_stimulus"}.contains(
              timing.at("origin").get<std::string>()))
        throw std::runtime_error(
            "timing lacks native capture-time validator; do not claim observed timing");
      if (bound(timing, "min_ms", 0, 10000) > bound(timing, "max_ms", 0, 10000))
        throw std::runtime_error("invalid timing interval");
      response["can_prove_original_service_acceptance"] = false;
      body["responses"].push_back(response);
    }
    if (s.contains("previous")) {
      const auto prior = exact_record(store, args, s.at("previous"));
      native_record(prior, "indago.research.v1", "native-research");
      if (prior.at("body").at("kind") != "service_contract")
        throw std::runtime_error("prior service contract required");
      body["previous"] = s.at("previous");
    }
    body["status"] = "hypothesis_contract";
    body["simulated_service"] = true;
    body["scope_limit"] =
        "Local responses, including replayed bytes, never independently prove "
        "original-service acceptance. Timing and framing require separate evidence.";
  } else if (kind == "service_observation") {
    keys(s, {"kind", "contract", "response", "capture"});
    const auto contract = exact_record(store, args, s.at("contract"));
    native_record(contract, "indago.research.v1", "native-research");
    if (contract.at("body").at("kind") != "service_contract")
      throw std::runtime_error("service contract required");
    const auto index = bound(s, "response", 0, 15);
    const auto &hypothesis = contract.at("body").at("responses").at(index);
    const auto &ref = s.at("capture");
    keys(ref, {"target_id", "offset", "max_bytes"});
    const auto t = store.target(args.at("project").get<std::string>(),
                                ref.at("target_id").get<std::string>(), true);
    const auto observation =
        harness_artifact_page(store, {{"target_id", t.id}, {"artifact_sha256", t.sha256}},
                              {{"project", args.at("project")},
                               {"offset", ref.at("offset")},
                               {"max_bytes", ref.at("max_bytes")}},
                              4096);
    const auto expected = raw_hex(hypothesis.at("hex").get<std::string>()),
               actual = raw_hex(observation.at("hex").get<std::string>());
    std::set<std::size_t> variable;
    for (const auto &range : hypothesis.at("variable_ranges"))
      for (std::size_t i = range.at("offset").get<std::size_t>();
           i <
           range.at("offset").get<std::size_t>() + range.at("length").get<std::size_t>();
           ++i)
        variable.insert(i);
    bool agrees = actual.size() == expected.size();
    J differing = J::array();
    for (std::size_t i = 0; i < std::min(actual.size(), expected.size()); ++i)
      if (!variable.contains(i) && actual[i] != expected[i]) {
        agrees = false;
        if (differing.size() < 32)
          differing.push_back(i);
      }
    body["contract"] = s.at("contract");
    body["response"] = index;
    body["observed_bytes"] = observation;
    body["fixed_bytes_agree"] = agrees;
    body["differing_offsets"] = differing;
    body["status"] =
        agrees ? "agreement_on_selected_bytes" : "hypothesis_rejected_on_selected_bytes";
    body["timing_tested"] = false;
    body["service_attribution_verified"] = false;
    body["scope_limit"] =
        "Byte/framing hypothesis only. Captured source identity is checked; timing, "
        "endpoint attribution and original service acceptance remain unproven.";
  } else
    throw std::runtime_error("unsupported research operation kind");
  return body;
}
} // namespace
J normalize_research(const ProjectStore &store, const J &inv, const J &, J args) {
  keys(args, {"project", "scope", "body", "sealed"});
  if (args.at("body").dump().size() > 24576)
    throw std::runtime_error("research body exceeds 24 KiB");
  // Every nested reference is scoped before materialization; captured bytes may
  // come from another explicitly admitted component, never arbitrary host paths.
  std::function<void(const J &, unsigned)> scope = [&](const J &v, unsigned depth) {
    if (depth > 16)
      throw std::runtime_error("research nesting bound exceeded");
    if (v.is_object()) {
      if (v.contains("id") && v.contains("revision")) {
        const auto record = exact_record(store, args, v);
        Db db(store.root() / "indago-native.sqlite3");
        harness_check_knowledge(db, inv, record);
      }
      if (v.contains("target_id"))
        (void)harness_select_component(inv, {{"target_id", v.at("target_id")}});
      for (const auto &x : v.items())
        scope(x.value(), depth + 1);
    } else if (v.is_array())
      for (const auto &x : v)
        scope(x, depth + 1);
  };
  scope(args.at("body"), 0);
  auto clean = args;
  clean.erase("sealed");
  const auto result = checked_body(store, clean);
  const J seal{{"body_sha256", sha256_text(result.dump())}};
  if (args.contains("sealed") && args.at("sealed") != seal)
    throw std::runtime_error("research dependency pins changed");
  args["sealed"] = seal;
  return args;
}
J execute_research(const ProjectStore &store, const J &args) {
  auto clean = args;
  clean.erase("sealed");
  auto body = checked_body(store, clean);
  if (sha256_text(body.dump()) != args.at("sealed").at("body_sha256").get<std::string>())
    throw std::runtime_error("research inputs changed");
  body["request_sha256"] = sha256_text(args.dump());
  J dependencies = J::array();
  std::set<std::string> seen;
  auto add = [&](const J &d) {
    if (seen.insert(d.dump()).second)
      dependencies.push_back(d);
  };
  std::function<void(const J &)> visit = [&](const J &v) {
    if (v.is_object()) {
      if (v.contains("id") && v.contains("revision"))
        add({{"type", "record"},
             {"id", v.at("id")},
             {"pin", std::to_string(v.at("revision").get<std::uint64_t>())}});
      if (v.contains("target_id")) {
        const auto t = store.target(args.at("project").get<std::string>(),
                                    v.at("target_id").get<std::string>(), true);
        add({{"type", "artifact"}, {"id", t.sha256}, {"pin", t.sha256}});
      }
      for (const auto &x : v.items())
        visit(x.value());
    } else if (v.is_array())
      for (const auto &x : v)
        visit(x);
  };
  visit(args.at("body"));
  return knowledge_put(store,
                       {{"project", args.at("project")},
                        {"kind", "product"},
                        {"title", "Bounded research workflow"},
                        {"state", "unknown"},
                        {"scope", args.at("scope")},
                        {"body", body},
                        {"dependencies", dependencies},
                        {"author", "native-research"}},
                       true);
}
J evaluation_action(const ProjectStore &store, const std::string &op, const J &r) {
  const std::set<std::string> failures{"none",
                                       "tool_gap",
                                       "controller_failure",
                                       "model_limitation",
                                       "unavailable_dependency",
                                       "invalid_evidence",
                                       "wrong_answer",
                                       "timeout",
                                       "resource_limit",
                                       "interrupted",
                                       "unknown"};
  if (op == "matrix") {
    keys(r, {"catalogue", "requirements", "capabilities", "basis"});
    const auto catalogue = benchmark::load(r.at("catalogue").get<std::string>());
    benchmark::verify_catalogue(catalogue);
    if (!r.at("requirements").is_object() || r.at("requirements").size() > 256 ||
        !r.at("capabilities").is_object() || r.at("capabilities").size() > 128)
      throw std::runtime_error("coverage matrix bounds exceeded");
    J rows = J::array();
    std::set<std::string> ids;
    for (const auto &challenge : catalogue.at("challenges")) {
      const auto id = challenge.at("id").get<std::string>();
      ids.insert(id);
      J row{{"challenge", id},
            {"catalogue_status", challenge.at("status")},
            {"capabilities", J::array()},
            {"requirements_assessed", r.at("requirements").contains(id)},
            {"solved", false}};
      if (r.at("requirements").contains(id)) {
        const auto &req = r.at("requirements").at(id);
        if (!req.is_array() || req.size() > 32)
          throw std::runtime_error("challenge capability bound");
        for (const auto &c : req) {
          identifier(c.get<std::string>());
          const auto state =
              r.at("capabilities").value(c.get<std::string>(), J{{"status", "unknown"}});
          keys(state, {"status", "evidence"});
          if (!std::set<std::string>{"missing", "implemented", "fixture_tested",
                                     "challenge_tested", "unknown"}
                   .contains(state.at("status").get<std::string>()))
            throw std::runtime_error("invalid capability assessment");
          if (state.at("status") != "missing" && state.at("status") != "unknown")
            text_limit(state.at("evidence"));
          row["capabilities"].push_back(
              {{"capability", c},
               {"assessment", state},
               {"assessment_authority", "operator supplied; not independently graded"}});
        }
      }
      rows.push_back(row);
    }
    for (const auto &x : r.at("requirements").items())
      if (!ids.contains(x.key()))
        throw std::runtime_error("unknown challenge in coverage matrix");
    const auto basis = r.value("basis", std::string("operator_assessment"));
    if (!std::set<std::string>{"operator_assessment", "filename_lower_bound"}.contains(
            basis))
      throw std::runtime_error("invalid requirements basis");
    return {{"schema", "indago.capability-matrix.v1"},
            {"catalogue_sha256", catalogue.at("catalogue_sha256")},
            {"denominator", catalogue.at("denominator")},
            {"basis", basis},
            {"requirements_complete", false},
            {"rows", rows},
            {"all_solved", false}};
  }
  const auto root = fs::absolute(r.at("evaluation_root").get<std::string>());
  benchmark::disjoint(root, store.root());
  fs::create_directories(root);
  auto load = [&](const J &id) {
    identifier(id.get<std::string>());
    auto record = J::parse(read(root / (id.get<std::string>() + ".json"), 262144));
    auto copy = record;
    copy.erase("record_sha256");
    if (record.at("id") != id ||
        sha256_text(copy.dump()) != record.at("record_sha256").get<std::string>())
      throw std::runtime_error("evaluation record integrity failure");
    return record;
  };
  auto save = [&](J body, const std::string &prefix) {
    body["id"] = make_id(prefix);
    body["record_sha256"] = sha256_text(body.dump());
    if (body.dump().size() > 262144)
      throw std::runtime_error("evaluation record exceeds 256 KiB");
    atomic_write(root / (body.at("id").get<std::string>() + ".json"), body.dump());
    return body;
  };
  if (op == "record") {
    keys(r, {"evaluation_root", "challenge", "split", "artifact_sha256", "model",
             "settings", "seed", "budget", "features", "outcome", "failure_category",
             "reproduction", "metrics", "attempt"});
    identifier(r.at("challenge").get<std::string>());
    hash(r.at("artifact_sha256").get<std::string>());
    text_limit(r.at("model"));
    if (!r.contains("seed") || !r.contains("attempt"))
      throw std::runtime_error("evaluation seed and attempt required");
    (void)bound(r, "seed", 0, 4294967295ULL);
    if (bound(r, "attempt", 1, 10000) == 0)
      throw std::runtime_error("attempt starts at one");
    if (!std::set<std::string>{"development", "synthetic_private", "held_out"}.contains(
            r.at("split").get<std::string>()))
      throw std::runtime_error("explicit evaluation split required");
    if (!failures.contains(r.at("failure_category").get<std::string>()))
      throw std::runtime_error("unknown machine-readable failure category");
    if (!std::set<std::string>{"passed", "failed", "incomplete"}.contains(
            r.at("outcome").get<std::string>()))
      throw std::runtime_error("invalid evaluation outcome");
    if ((r.at("outcome") == "passed") != (r.at("failure_category") == "none"))
      throw std::runtime_error("outcome/failure inconsistency");
    if (!r.at("settings").is_object() || r.at("settings").dump().size() > 4096 ||
        !r.at("budget").is_object() || r.at("budget").dump().size() > 4096 ||
        !r.at("features").is_object() || r.at("features").size() > 32)
      throw std::runtime_error("evaluation setting bounds");
    for (const auto &f : r.at("features").items()) {
      identifier(f.key());
      if (!f.value().is_boolean())
        throw std::runtime_error("feature flag must be boolean");
    }
    const auto &repro = r.at("reproduction");
    keys(repro, {"source_path", "source_sha256", "request_path", "request_sha256",
                 "diagnostic"});
    text_limit(repro.at("diagnostic"));
    for (const auto *prefix : {"source", "request"}) {
      const auto path = repro.at(std::string(prefix) + "_path").get<std::string>();
      if (fs::file_size(path) > 262144 ||
          sha256_file(path) !=
              repro.at(std::string(prefix) + "_sha256").get<std::string>())
        throw std::runtime_error("minimal reproduction identity mismatch");
    }
    const auto &metrics = r.at("metrics");
    keys(metrics, {"wall_ms", "model_generations", "native_actions", "tokens"});
    for (const auto &m : metrics.items())
      if (!m.value().is_number_unsigned() &&
          !(m.value().is_number_integer() && m.value().get<std::int64_t>() >= 0))
        throw std::runtime_error("nonnegative metrics required");
    auto body = r;
    body.erase("evaluation_root");
    body["schema"] = "indago.evaluation-attempt.v1";
    body["verified_solve"] = false;
    body["outcome_authority"] =
        "operator supplied; independent benchmark certification is separate";
    fs::create_directories(root / "reproductions");
    for (const auto *prefix : {"source", "request"}) {
      const auto data =
          read(repro.at(std::string(prefix) + "_path").get<std::string>(), 262144);
      const auto digest = sha256_text(data);
      if (digest != repro.at(std::string(prefix) + "_sha256").get<std::string>())
        throw std::runtime_error("reproduction changed during retention");
      const auto file = root / "reproductions" / digest;
      if (fs::exists(file) && sha256_file(file) != digest)
        throw std::runtime_error("retained reproduction integrity mismatch");
      if (!fs::exists(file))
        atomic_write(file, data);
      body["reproduction"][std::string(prefix) + "_retained"] =
          fs::relative(file, root).generic_string();
    }
    return save(body, "eval");
  }
  if (op == "compare") {
    keys(r, {"evaluation_root", "baseline", "variant", "feature"});
    const auto a = load(r.at("baseline")), b = load(r.at("variant"));
    for (const auto &entry : {a, b}) {
      auto copy = entry;
      copy.erase("record_sha256");
      if (sha256_text(copy.dump()) != entry.at("record_sha256").get<std::string>())
        throw std::runtime_error("evaluation record integrity failure");
    }
    for (const char *k : {"schema", "challenge", "split", "artifact_sha256", "model",
                          "settings", "seed", "budget"})
      if (a.at(k) != b.at(k))
        throw std::runtime_error(
            "ablation confound: model, task, settings, seed and budgets must match");
    auto af = a.at("features"), bf = b.at("features");
    const auto feature = r.at("feature").get<std::string>();
    if (!af.contains(feature) || !bf.contains(feature) ||
        af.at(feature) == bf.at(feature))
      throw std::runtime_error("ablation must toggle requested feature");
    af.erase(feature);
    bf.erase(feature);
    if (af != bf)
      throw std::runtime_error("ablation changes multiple features");
    return save({{"schema", "indago.ablation.v1"},
                 {"baseline", r.at("baseline")},
                 {"variant", r.at("variant")},
                 {"feature", feature},
                 {"model", a.at("model")},
                 {"outcomes", J::array({a.at("outcome"), b.at("outcome")})},
                 {"metrics", J::array({a.at("metrics"), b.at("metrics")})},
                 {"causal_claim", false},
                 {"scope_limit", "One matched pair; repeat across private tasks and "
                                 "seeds before claiming transfer or superiority"}},
                "ablation");
  }
  if (op == "recipe") {
    keys(r, {"evaluation_root", "project", "scope", "comparison", "applicability",
             "limitations", "technique", "answer_free_review"});
    if (!r.value("answer_free_review", false))
      throw std::runtime_error("operator answer-free source review required");
    text_limit(r.at("technique"));
    text_limit(r.at("applicability"));
    text_limit(r.at("limitations"));
    const auto comparison = exact_record(store, r, r.at("comparison"));
    native_record(comparison, "indago.research.v1", "native-research");
    if (comparison.at("body").at("kind") != "algorithm_comparison" ||
        comparison.at("body").at("status") != "agreement_on_tested_inputs")
      throw std::runtime_error("recipe requires completed native comparison");
    const auto candidate = exact_record(store, r, comparison.at("body").at("candidate"));
    return save({{"schema", "indago.validated-recipe.v1"},
                 {"technique", r.at("technique")},
                 {"applicability", r.at("applicability")},
                 {"limitations", r.at("limitations")},
                 {"language", candidate.at("body").at("language")},
                 {"source_code", candidate.at("body").at("source_code")},
                 {"source_sha256", candidate.at("body").at("source_sha256")},
                 {"tested_case_count", comparison.at("body").at("tested_domain").size()},
                 {"validation_receipt_sha256", sha256_text(comparison.at("body").dump())},
                 {"answer_free_review", "operator reviewed; semantic absence of "
                                        "hardcoded answers is not machine proven"},
                 {"universal_equivalence", false}},
                "recipe");
  }
  if (op == "show") {
    keys(r, {"evaluation_root", "id"});
    return load(r.at("id"));
  }
  throw std::runtime_error("unknown evaluation operation");
}
} // namespace indago
