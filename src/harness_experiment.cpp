#include "harness_experiment.hpp"
#include "indago/airece.hpp"
#include "indago/runtime.hpp"
#include <thread>

namespace indago {
using namespace wb;
namespace {
const std::set<std::string> engines{"io", "debugger", "frida", "dynamorio",
                                    "rr"};
void literal(const J &v, std::size_t cap = 1024) {
  if (!v.is_string() || v.get<std::string>().size() > cap ||
      v.get<std::string>().find('\0') != std::string::npos)
    throw std::runtime_error("invalid experiment literal");
}
void bytes(const J &v) {
  literal(v, 8192);
  const auto s = v.get<std::string>();
  if (s.size() % 2 || s.find_first_not_of("0123456789abcdef") != s.npos)
    throw std::runtime_error("invalid experiment bytes");
}
bool terminal(const J &s) {
  return std::set<std::string>{"completed",  "failed", "cancelled",
                               "terminated", "exited", "detached"}
      .contains(s.value("state", ""));
}
J summarize_observations(const J &c) {
  J out{{"counts", J::object()},
        {"values", J::array()},
        {"coverage",
         "bounded observed prefix; missing events are not proof of absence"}};
  auto records = c.value("observations", J::array());
  if (records.is_object())
    records = records.value("observations", J::array());
  for (const auto &entry : records) {
    const auto kind =
        entry.value("operation", entry.value("kind", std::string("unknown")));
    out["counts"][kind] = out["counts"].value(kind, 0) + 1;
    const auto r = entry.value("result", entry), data = r.value("data", r);
    J values{{"kind", kind}};
    for (const auto *key :
         {"registers", "flags", "output_hex", "input_hex", "accepted"})
      if (data.contains(key) && data.at(key).dump().size() <= 2048)
        values[key] = data.at(key);
    if (data.contains("location"))
      for (const auto *key : {"artifact_sha256", "rva", "static_address"})
        if (data.at("location").contains(key))
          values[key] = data.at("location").at(key);
    if (values.size() > 1 && out["values"].size() < 8)
      out["values"].push_back(values);
  }
  return out;
}
} // namespace
J normalize_execution_grant(const ProjectStore &store, const J &inv,
                            const J &grant) {
  keys(grant, {"trusted_host_execution", "targets", "engines"});
  if (!grant.value("trusted_host_execution", false))
    throw std::runtime_error(
        "runtime grant requires explicit trusted_host_execution "
        "acknowledgement; no sandbox");
  if (!grant.at("targets").is_array() || grant.at("targets").empty() ||
      grant.at("targets").size() > 8)
    throw std::runtime_error(
        "execution grant needs 1..8 exact original targets");
  J out = grant;
  std::set<std::string> seen;
  for (auto &t : out["targets"]) {
    keys(t, {"target_id", "file", "artifact_sha256", "acceptance_oracle",
             "acceptance_oracle_sha256"});
    const auto selected =
        harness_select_component(inv, {{"target_id", t.at("target_id")}});
    const auto file = fs::canonical(t.at("file").get<std::string>());
    const auto sha = sha256_file(file);
    if (sha != selected.at("artifact_sha256").get<std::string>() ||
        !seen.insert(t.at("target_id").get<std::string>()).second)
      throw std::runtime_error(
          "execution target is duplicate or does not match scoped original");
    (void)store.target(inv.at("project").get<std::string>(),
                       t.at("target_id").get<std::string>(), true);
    t["file"] = file.string();
    t["artifact_sha256"] = sha;
    if (t.contains("acceptance_oracle")) {
      const auto oracle =
          fs::canonical(t.at("acceptance_oracle").get<std::string>());
      const auto relative =
          oracle.lexically_relative(fs::canonical(store.root()));
      if (!relative.empty() && *relative.begin() != "..")
        throw std::runtime_error(
            "operator oracle must be outside model workspace");
      const auto raw = wb::read(oracle, 16384);
      const auto definition = J::parse(raw);
      if (definition.at("schema") != "indago.io-oracle.v1" ||
          definition.at("artifact_sha256").get<std::string>() != sha)
        throw std::runtime_error(
            "operator oracle is not bound to this original artifact");
      t["acceptance_oracle"] = oracle.string();
      t["acceptance_oracle_sha256"] = sha256_text(raw);
    } else if (t.contains("acceptance_oracle_sha256"))
      throw std::runtime_error("oracle pin requires an oracle");
  }
  if (!out.at("engines").is_array() || out.at("engines").empty() ||
      out.at("engines").size() > 5)
    throw std::runtime_error("execution engine grant required");
  for (const auto &e : out.at("engines"))
    if (!engines.contains(e.get<std::string>()))
      throw std::runtime_error("unknown execution engine");
  return out;
}
J normalize_experiment(const ProjectStore &store, const J &inv,
                       const J &selected, J args) {
  keys(args, {"project", "scope", "engine", "cases", "steps", "prediction",
              "sealed", "companions", "recipe", "telemetry", "recover_code", "managed_trace"});
  if (args.contains("recover_code") && !args.at("recover_code").is_boolean())
    throw std::runtime_error("recover_code must be boolean");
  const auto grant = inv.at("envelope").value("runtime_execution", J::object());
  if (grant.empty())
    throw std::runtime_error(
        "capability_blocked: operator runtime_execution grant required");
  const auto engine = args.at("engine").get<std::string>();
  if(args.contains("managed_trace")&&(!args.at("managed_trace").is_boolean()||engine!="io"))throw std::runtime_error("managed_trace requires I/O execution");
  if (std::find(grant.at("engines").begin(), grant.at("engines").end(),
                engine) == grant.at("engines").end())
    throw std::runtime_error("engine not granted");
  J target;
  for (const auto &t : grant.at("targets"))
    if (t.at("target_id") == selected.at("target_id"))
      target = t;
  if (target.is_null() || sha256_file(target.at("file").get<std::string>()) !=
                              selected.at("artifact_sha256").get<std::string>())
    throw std::runtime_error("execution target is not granted or changed");
  literal(args.at("prediction"));
  if (args.contains("recipe") &&
      (engine != "frida" ||
       !std::set<std::string>{"io", "input", "code", "modules", "managed", "config", "network"}
            .contains(args.at("recipe").get<std::string>())))
    throw std::runtime_error(
        "recipe requires Frida and a bounded native recipe");
  if (args.contains("telemetry") &&
      (engine != "dynamorio" ||
       !std::set<std::string>{"blocks", "effects"}.contains(
           args.at("telemetry").get<std::string>())))
    throw std::runtime_error("telemetry requires DynamoRIO blocks or effects");
  auto &cases = args.at("cases");
  if (!cases.is_array() || cases.empty() || cases.size() > 2)
    throw std::runtime_error("experiment requires 1..2 cases");
  for (auto &c : cases) {
    keys(c, {"label", "argv", "input_hex", "files", "environment",
             "solver_candidate", "engine", "managed_trace", "timeout_ms"});
    if(c.contains("timeout_ms")&&(runtime_number(c.at("timeout_ms"))<100||runtime_number(c.at("timeout_ms"))>10000))throw std::runtime_error("case timeout must be 100..10000 ms");
    c["timeout_ms"]=c.contains("timeout_ms")?runtime_number(c.at("timeout_ms")):3000;
    const auto case_engine=c.value("engine",engine);
    if(!engines.contains(case_engine)||std::find(grant.at("engines").begin(),grant.at("engines").end(),case_engine)==grant.at("engines").end())
      throw std::runtime_error("case observation engine not granted");
    if(c.contains("managed_trace")&&(!c.at("managed_trace").is_boolean()||case_engine!="io"))
      throw std::runtime_error("case managed trace requires I/O engine");
    if(case_engine=="io")c["managed_trace"]=c.value("managed_trace",args.value("managed_trace",false));
    c["engine"]=case_engine;
    if (c.contains("solver_candidate")) {
      auto &ref = c["solver_candidate"];
      keys(ref, {"session", "observation", "terminal", "branch", "candidate",
                 "receipt_sha256"});
      const auto sessions =
          inv.value("runtime_observation_sessions", J::array());
      if (std::find(sessions.begin(), sessions.end(), ref.at("session")) ==
          sessions.end())
        throw std::runtime_error(
            "solver candidate session outside investigation");
      Db db(store.root() / "runtime.sqlite3");
      Q session(db,
                "SELECT record FROM runtime_sessions WHERE id=? AND project=?");
      if (!session.s(1, ref.at("session").get<std::string>())
               .s(2, inv.at("project").get<std::string>())
               .row() ||
          J::parse(session.text(0)).at("artifact_sha256") !=
              selected.at("artifact_sha256"))
        throw std::runtime_error(
            "solver candidate belongs to a different original target");
      Q q(db, "SELECT record FROM runtime_observations WHERE session=? AND "
              "id=? AND kind='symbolic'");
      if (!q.s(1, ref.at("session").get<std::string>())
               .s(2, ref.at("observation").get<std::string>())
               .row())
        throw std::runtime_error("native symbolic observation missing");
      auto record = J::parse(q.text(0));
      const auto hash = sha256_text(record.dump());
      if (ref.contains("receipt_sha256") && ref.at("receipt_sha256") != hash)
        throw std::runtime_error("symbolic receipt changed");
      ref["receipt_sha256"] = hash;
      const auto &data = record.at("data");
      if (data.at("status") != "completed")
        throw std::runtime_error(
            "partial symbolic result cannot supply automatic replay bytes");
      const auto &branch = data.at("results")
                               .at(runtime_number(ref.at("terminal")))
                               .at("branches")
                               .at(runtime_number(ref.at("branch")));
      const auto &candidate =
          branch.at("input_candidates").at(runtime_number(ref.at("candidate")));
      if (branch.at("native_verdict") != "sat" ||
          !candidate.at("complete").get<bool>())
        throw std::runtime_error("incomplete/unsatisfied solver candidate");
      // No implicit channel guessing or replacement of an entire original
      // input. The caller supplies its baseline; only the mapped byte interval
      // is patched.
      const auto &mapping = candidate.at("mapping");
      const auto source = mapping.at("source").get<std::string>();
      const auto offset = runtime_number(mapping.value("offset", J(0)));
      const auto replacement = candidate.at("hex").get<std::string>();
      if (source != "stdin" && source != "file")
        throw std::runtime_error(
            "automatic candidate replay supports stdin/files; argv requires "
            "explicit encoding");
      auto &channel = source == "stdin"
                          ? c["input_hex"]
                          : c["files"][mapping.at("name").get<std::string>()];
      if (!channel.is_string())
        throw std::runtime_error(
            "candidate replay requires baseline input bytes");
      auto baseline = channel.get<std::string>();
      bytes(baseline);
      bytes(replacement);
      if (offset > baseline.size() / 2 ||
          replacement.size() > baseline.size() - offset * 2)
        throw std::runtime_error("candidate interval leaves baseline input");
      baseline.replace(offset * 2, replacement.size(), replacement);
      channel = baseline;
    }
    literal(c.at("label"), 64);
    auto argv = c.value("argv", J::array());
    if (!argv.is_array() || argv.size() > 16)
      throw std::runtime_error("experiment argv exceeds 16");
    for (const auto &a : argv)
      literal(a);
    c["argv"] = argv;
    c["input_hex"] = c.value("input_hex", std::string{});
    bytes(c.at("input_hex"));
    c["files"] = c.value("files", J::object());
    c["environment"] = c.value("environment", J::object());
    if (!c["files"].is_object() || c["files"].size() > 4 ||
        !c["environment"].is_object() || c["environment"].size() > 16)
      throw std::runtime_error("experiment file/environment bounds exceeded");
    for (auto it = c["files"].begin(); it != c["files"].end(); ++it) {
      if (it.key().empty() || it.key().size() > 64 ||
          it.key().find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO"
                                     "PQRSTUVWXYZ0123456789_-") !=
              std::string::npos)
        throw std::runtime_error("experiment file must be a plain name");
      bytes(it.value());
    }
    for (auto it = c["environment"].begin(); it != c["environment"].end();
         ++it) {
      if (it.key().empty() || it.key().size() > 64 ||
          it.key().find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") !=
              std::string::npos)
        throw std::runtime_error("invalid experiment environment name");
      literal(it.value());
    }
  }
  if (cases.size() == 2) {
    auto a = cases[0], b = cases[1];
    a.erase("label");
    b.erase("label");
    if (a == b)
      throw std::runtime_error(
          "contrasting cases require distinct delivered inputs");
  }
  args["steps"] = args.value("steps", J::array());
  if (!args["steps"].is_array() || args["steps"].size() > 6)
    throw std::runtime_error("experiment step bound exceeded");
  if (engine != "debugger" && !args["steps"].empty())
    throw std::runtime_error("steps require debugger engine");
  for (const auto &step : args["steps"]) {
    keys(step, {"operation", "static_address", "rva", "function", "memory",
                "max_steps", "mode", "path", "symbolic_registers",
                "symbolic_memory", "input_ranges", "byte_constraints", "sink"});
    const auto op = step.at("operation").get<std::string>();
    if (!std::set<std::string>{"breakpoint", "continue", "capture", "registers",
                               "modules", "threads", "trace", "reanalyze",
                               "symbolic"}
             .contains(op))
      throw std::runtime_error("experiment debugger step not admitted");
    if (step.contains("max_steps") && (runtime_number(step["max_steps"]) < 1 ||
                                       runtime_number(step["max_steps"]) > 32))
      throw std::runtime_error("trace exceeds 32 steps");
    if (step.contains("memory")) {
      if (!step["memory"].is_array() || step["memory"].size() > 2)
        throw std::runtime_error("capture exceeds two ranges");
      for (const auto &m : step["memory"]) {
        keys(m, {"address", "size"});
        if (runtime_number(m.at("size")) > 1024)
          throw std::runtime_error("capture exceeds 1 KiB per range");
      }
    }
  }
  args["companions"] = args.value("companions", J::array());
  J peers = J::array();
  if (!args["companions"].is_array() || args["companions"].size() > 2)
    throw std::runtime_error("at most two companion processes");
  if (!args["companions"].empty() &&
      (engine != "debugger" || cases.size() != 1))
    throw std::runtime_error("companions require one debugger case");
  for (const auto &peer : args["companions"]) {
    keys(peer, {"target_id", "argv", "ready"});
    J granted;
    for (const auto &t : grant.at("targets"))
      if (t.at("target_id") == peer.at("target_id"))
        granted = t;
    if (granted.is_null())
      throw std::runtime_error("companion not operator granted");
    const auto argv = peer.value("argv", J::array());
    if (!argv.is_array() || argv.size() > 16)
      throw std::runtime_error("companion argv bounds");
    for (const auto &a : argv)
      literal(a);
    granted["argv"] = argv;
    if (peer.contains("ready")) {
      const auto ready = peer.at("ready");
      keys(ready, {"file", "hex"});
      literal(ready.at("file"), 64);
      bytes(ready.at("hex"));
      const auto name = ready.at("file").get<std::string>();
      if (name.empty() ||
          name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS"
                                 "TUVWXYZ0123456789_-") != name.npos ||
          ready.at("hex").get<std::string>().size() > 256)
        throw std::runtime_error(
            "readiness requires a bounded owned-directory file and bytes");
      granted["ready"] = ready;
    }
    peers.push_back(granted);
  }
  const J sealed{{"target", target},
                 {"investigation", inv.at("id")},
                 {"companions", peers}};
  if (args.contains("sealed") && args.at("sealed") != sealed)
    throw std::runtime_error("experiment seal changed");
  args["sealed"] = sealed;
  if (args["steps"].empty())
    args.erase("steps");
  return args;
}
J execute_experiment(ProjectStore &store, const J &args) {
  const auto p = args.at("project").get<std::string>(),
             engine = args.at("engine").get<std::string>();
  const auto target = args.at("sealed").at("target");
  const auto run_id = make_id("experiment");
  const auto journal =
      store.root() / "runtime-experiments" / (run_id + ".json");
  fs::create_directories(journal.parent_path());
  J body{{"schema", "indago.experiment.v1"},
         {"id", run_id},
         {"request_sha256", sha256_text(args.dump())},
         {"request", args},
         {"status", "running"},
         {"cases", J::array()},
         {"journal", journal.string()},
         {"verified_solve", false},
         {"behavior_verified", false},
         {"outcome_unknown", false},
         {"scope_limit",
          "Host execution of granted original file; not a sandbox, "
          "causal proof, or independent acceptance oracle"}};
  auto save = [&] { atomic_write(journal, body.dump()); };
  save();
  auto call = [&](J r) {
    r["project"] = p;
    return runtime_command(store, {}, r);
  };
  const auto start = now_ms();
  auto cancelled = [&] {
    Db db(store.root() / "indago-native.sqlite3");
    Q q(db, "SELECT record FROM wb_investigations WHERE project=? AND id=?");
    if (!q.s(1, p)
             .s(2, args.at("sealed").at("investigation").get<std::string>())
             .row())
      return true;
    return J::parse(q.text(0)).at("status") == "cancelled" ||
           now_ms() - start > 25000;
  };
  for (const auto &c : args.at("cases")) {
    const auto engine=c.value("engine",args.at("engine").get<std::string>());
    if (cancelled()) {
      body["status"] = "cancelled";
      break;
    }
    J item{{"label", c.at("label")},
           {"input", c},
           {"observations", J::array()},
           {"dispatch_started", true}};
    body["cases"].push_back(item);
    auto &current = body["cases"].back();
    save();
    std::string session;
    std::vector<std::string> companions;
    try {
      current["companions"] = J::array();
      for (const auto &peer : args.at("sealed").at("companions")) {
        if (cancelled())
          throw std::runtime_error("cancelled before companion launch");
        if (sha256_file(peer.at("file").get<std::string>()) !=
            peer.at("artifact_sha256").get<std::string>())
          throw std::runtime_error("companion changed");
        current["pending_companion"] = peer;
        const auto peer_key =
            run_id + "/peer/" + std::to_string(companions.size());
        current["pending_companion"]["launch_key"] = peer_key;
        save();
        auto s = call({{"operation", "launch"},
                       {"experiment_key", peer_key},
                       {"file", peer.at("file")},
                       {"argv", peer.at("argv")},
                       {"input_hex", ""},
                       {"files", J::object()},
                       {"environment", J::object()},
                       {"lifetime_ms", 12000},
                       {"terminate_on_expiry", true}});
        const auto sid = s.at("id").get<std::string>();
        companions.push_back(sid);
        current["companions"].push_back(s);
        current.erase("pending_companion");
        save();
        call({{"operation", "continue"},
              {"session", sid},
              {"wait", false},
              {"timeout_ms", 1000}});
        if (peer.contains("ready")) {
          const auto path = store.root() / "runtime-artifacts" / sid /
                            "inputs" /
                            peer.at("ready").at("file").get<std::string>();
          bool ready = false;
          unsigned loader_stops = 0;
          const auto end = now_ms() + 2000;
          while (now_ms() < end && !cancelled()) {
            const auto state =
                call({{"operation", "status"}, {"session", sid}});
            const auto event = state.value("last_event", J::object());
            if (state.value("state", std::string{}) == "stopped" &&
                loader_stops < 2 &&
                (event.value("kind", std::string{}) == "loader_breakpoint" ||
                 event.value("code", std::string{}) == "0x80000003")) {
              ++loader_stops;
              current["companions"].back()["loader_continuations"] =
                  loader_stops;
              call({{"operation", "continue"},
                    {"session", sid},
                    {"wait", false},
                    {"timeout_ms", 1000}});
            }
            if (fs::exists(path) && !fs::is_symlink(path) &&
                fs::is_regular_file(path) && fs::file_size(path) <= 128) {
              const auto raw = wb::read(path, 128);
              std::string hex;
              const char *digits = "0123456789abcdef";
              for (unsigned char byte : raw) {
                hex += digits[byte >> 4];
                hex += digits[byte & 15];
              }
              if (hex == peer.at("ready").at("hex").get<std::string>()) {
                current["companions"].back()["readiness"] = {
                    {"kind", "owned_file"},
                    {"name", peer.at("ready").at("file")},
                    {"sha256", sha256_text(raw)},
                    {"process_session", sid},
                    {"observed", true}};
                ready = true;
                break;
              }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
          }
          save();
          if (!ready)
            throw std::runtime_error(
                "companion readiness not observed; primary was not launched");
        }
      }
      if (sha256_file(target.at("file").get<std::string>()) !=
          target.at("artifact_sha256").get<std::string>())
        throw std::runtime_error("original artifact changed before execution");
      J launch{{"operation", engine == "io"         ? "io-run"
                             : engine == "debugger" ? "launch"
                             : engine == "rr"       ? "record"
                                                    : "instrument"},
               {"file", target.at("file")},
               {"argv", c.at("argv")},
               {"timeout_ms", c.value("timeout_ms",3000u)}};
      launch["input_hex"] = c.at("input_hex");
      launch["files"] = c.at("files");
      launch["environment"] = c.at("environment");
      current["launch_key"] =
          run_id + "/case/" + std::to_string(body.at("cases").size() - 1);
      launch["experiment_key"] = current.at("launch_key");
      save();
      if (engine == "io") {
        launch["managed_trace"]=c.value("managed_trace",args.value("managed_trace",false));
        launch["trusted_target_ack"] = true;
        launch["artifact"] = target.at("artifact_sha256");
        launch["input_hex"] = c.at("input_hex");
        launch["files"] = c.at("files");
        launch["environment"] = c.at("environment");
        launch["max_output_bytes"] = 4096;
        if (target.contains("acceptance_oracle") &&
            body.at("cases").size() == 1) {
          if (sha256_file(target.at("acceptance_oracle").get<std::string>()) !=
              target.at("acceptance_oracle_sha256").get<std::string>())
            throw std::runtime_error("operator oracle changed after grant");
          launch["acceptance_oracle"] = target.at("acceptance_oracle");
        }
      } else if (engine == "debugger") {
        launch["lifetime_ms"] = 12000;
        launch["terminate_on_expiry"] = true;
      } else {
        launch["backend"] = engine;
        if (engine == "rr")
          launch["trace_bytes"] = 16777216;
        else {
          launch["max_events"] =
              (engine == "frida" &&
               (args.value("recipe", std::string("io")) == "code"||args.value("recipe",std::string("io"))=="input"||args.value("recipe",std::string("io"))=="managed"))
                  ? 256
                  : 64;
          if (engine == "frida")
            launch["recipe"] = args.value("recipe", std::string("io"));
          if (engine == "dynamorio")
            launch["telemetry"] =
                args.value("telemetry", std::string("blocks"));
        }
      }
      auto state = call(launch);
      session = state.at("id").get<std::string>();
      current["session"] = session;
      save();
      if (engine == "debugger") {
        // Default first experiment stops at the image entry; later
        // model-selected function/static selectors use the existing
        // relocation/identity layer.
        auto steps = args.value("steps", J::array());
        if (steps.empty())
          steps =
              J::array({{{"operation", "breakpoint"},
                         {"static_address",
                          runtime_image(target.at("file").get<std::string>())
                              .at("entry")}},
                        {{"operation", "continue"}},
                        {{"operation", "capture"}},
                        {{"operation", "reanalyze"}}});
        std::string capture, planned_stop;
        for (auto step : steps) {
          if (cancelled())
            throw std::runtime_error(
                "experiment cancelled or deadline reached");
          step["session"] = session;
          step["experiment_key"] =
              current.at("launch_key").get<std::string>() + "/step/" +
              std::to_string(current.at("observations").size());
          step["timeout_ms"] = 1000;
          if (step.at("operation") == "continue")
            step["wait"] = true;
          if (step.at("operation") == "trace" && !step.contains("max_steps"))
            step["max_steps"] = 16;
          if (step.at("operation") == "reanalyze" ||
              step.at("operation") == "symbolic") {
            if (capture.empty())
              throw std::runtime_error("reanalyze requires preceding capture");
            step["observation"] = capture;
            if (step.at("operation") == "reanalyze")
              step["backend"] = "xair";
          }
          current["pending_step"] = step;
          save();
          auto result = call(step);
          if (step.at("operation") == "breakpoint" &&
              result.contains("location"))
            planned_stop =
                result.at("location").value("runtime_address", std::string{});
          if (step.at("operation") == "continue" && !planned_stop.empty()) {
            unsigned loader_stops = 0;
            while (result.value("state", std::string{}) == "stopped" &&
                   loader_stops < 2) {
              const auto event = result.value("last_event", J::object());
              if (event.value("address", std::string{}) == planned_stop ||
                  event.value("code", std::string{}) != "0x80000003")
                break;
              current["loader_stops"].push_back(event);
              save();
              ++loader_stops;
              result = call(step);
            }
            current["planned_breakpoint_reached"] =
                result.value("last_event", J::object())
                    .value("address", std::string{}) == planned_stop;
          }
          if (result.value("status", std::string{}) == "pending" ||
              result.value("status", std::string{}) == "queued") {
            current["uncertain_request"] = result;
            body["outcome_unknown"] = true;
            throw std::runtime_error("debugger request pending; inspect "
                                     "request identity, do not replay");
          }
          if (step.at("operation") == "capture" && result.contains("id"))
            capture = result.at("id").get<std::string>();
          current["observations"].push_back(
              {{"operation", step.at("operation")}, {"result", result}});
          current.erase("pending_step");
          save();
        }
        current["cleanup"] = call({{"operation", "terminate"},
                                   {"session", session},
                                   {"timeout_ms", 1000}});
      } else if (engine != "io") {
        const auto deadline = now_ms() + 5000;
        while (!terminal(state) && now_ms() < deadline && !cancelled()) {
          std::this_thread::sleep_for(std::chrono::milliseconds(25));
          state = call({{"operation", "status"}, {"session", session}});
        }
        if (!terminal(state)) {
          current["cleanup"] =
              call({{"operation", "cancel"}, {"session", session}});
          current["partial"] = true;
        }
        current["observations"] = call({{"operation", "observations"},
                                        {"session", session},
                                        {"limit", 16}});
        if(engine=="frida"&&args.value("recipe",std::string{})=="input") {
          current["input_solutions"]=J::array();auto observations=call({{"operation","observations"},{"session",session},{"kind","input_comparison"},{"limit",2}});
          for(const auto &o:observations.at("observations")) {
            if(cancelled())break;
            current["input_solutions"].push_back(call({{"operation","solve-input"},{"session",session},{"observation",o.at("id")}}));save();
          }
        }
        if (args.value("recover_code", false)) {
          current["code_recoveries"] = J::array();
          auto code = call(
              {{"operation", "observations"},
               {"session", session},
               {"kind", engine == "frida" ? "code_capture" : "write_execute"},
               {"limit", 16}});
          std::set<std::string> recovered_regions;
          for (const auto &observation : code.at("observations")) {
            if (cancelled() || current["code_recoveries"].size() >= 2)
              break;
            const auto &d = observation.at("data");
            if (d.contains("code_bytes") &&
                !recovered_regions
                     .insert(
                         sha256_text(
                             d.at("code_bytes").value("hex", std::string{})) +
                         d.at("code_bytes").value("address", std::string{}))
                     .second)
              continue;
            current["pending_recovery"] = observation.at("id");
            save();
            auto recovered = call({{"operation", "feedback"},
                                   {"session", session},
                                   {"observation", observation.at("id")},
                                   {"backend", "xair"},
                                   {"timeout_ms", 1000}});
            current["code_recoveries"].push_back(recovered);
            current.erase("pending_recovery");
            save();
          }
          current["recovery_scope"] =
              "at most two observed write/execute regions; no packer signature "
              "or XOR assumption; absent events do not prove absent runtime "
              "code";
        }
        if (engine == "rr" && state.value("replay_ready", false) &&
            !cancelled()) {
          current["replay_dispatch_started"] = true;
          save();
          auto replay = call({{"operation", "replay"},
                              {"session", session},
                              {"timeout_ms", 2000},
                              {"trace_bytes", 16777216}});
          current["replay_session"] = replay.at("id");
          save();
          const auto end = now_ms() + 3500;
          while (!terminal(replay) && now_ms() < end && !cancelled()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
            replay = call({{"operation", "status"},
                           {"session", current.at("replay_session")}});
          }
          current["replay"] = replay;
          if (!terminal(replay))
            current["replay_cleanup"] =
                call({{"operation", "cancel"},
                      {"session", current.at("replay_session")}});
        }
      } else
        current["observations"].push_back(state.at("observation"));
      current["state"] = state;
      current["status"] = "observed";
    } catch (const std::exception &e) {
      current["status"] = "partial";
      current["diagnostic"] = e.what();
      if (session.empty())
        body["outcome_unknown"] = current.contains("launch_key") ||
                                  current.contains("pending_companion");
      else
        try {
          current["cleanup"] = call(
              {{"operation", engine == "debugger" ? "terminate" : "cancel"},
               {"session", session},
               {"timeout_ms", 1000}});
        } catch (const std::exception &cleanup) {
          current["cleanup_error"] = cleanup.what();
          body["outcome_unknown"] = true;
        }
    }
    current["companion_cleanup"] = J::array();
    for (const auto &sid : companions)
      try {
        const auto status = call({{"operation", "status"}, {"session", sid}});
        current["companion_cleanup"].push_back(
            terminal(status) ? status
                             : call({{"operation", "terminate"},
                                     {"session", sid},
                                     {"timeout_ms", 1000}}));
      } catch (const std::exception &e) {
        current["companion_cleanup"].push_back(
            {{"session", sid}, {"error", e.what()}});
        body["outcome_unknown"] = true;
      }
    current["observation_summary"] = summarize_observations(current);
    save();
    if (body.at("outcome_unknown") == true)
      break;
  }
  body["comparison"] = {{"contrasting_cases", body["cases"].size() == 2},
                        {"acceptance_proven", false}};
  if (body["cases"].size() == 2) {
    const auto &left=body["cases"][0].at("input"), &right=body["cases"][1].at("input");
    body["comparison"]["changed_controls"]=J::array();
    for(const auto *key:{"argv","input_hex","files","environment","engine","managed_trace","timeout_ms"})
      if(left.value(key,J{})!=right.value(key,J{}))body["comparison"]["changed_controls"].push_back({{"field",key},{"baseline",left.value(key,J{})},{"variant",right.value(key,J{})}});
    body["comparison"]["observer_changed"]=left.value("engine",J{})!=right.value("engine",J{})||left.value("managed_trace",J(false))!=right.value("managed_trace",J(false));
    body["comparison"]["causal_attribution"]="unproven; observer schemas, nondeterminism and uncontrolled host state may differ";
    body["comparison"]["clock_control"]="host clock is not virtualized; environment values are delivered literally";
    body["comparison"]["native_observations_changed"] =
        body["cases"][0].value("observation_summary", J{}) !=
        body["cases"][1].value("observation_summary", J{});
    body["comparison"]["scope"] = "bounded native counts and selected values; "
                                  "no causal or complete-coverage claim";
  }
  if (body["cases"].size() == 2 &&
      body["cases"][0]["input"].value("engine",engine)=="io" && body["cases"][1]["input"].value("engine",engine)=="io" &&
      body["cases"][0].contains("state") &&
      body["cases"][1].contains("state")) {
    const auto a = body["cases"][0]["state"]["observation"]["data"],
               b = body["cases"][1]["state"]["observation"]["data"];
    body["comparison"]["complete"] =
        a.at("complete") == true && b.at("complete") == true;
    body["comparison"]["output_changed"] =
        a.at("output_hex") != b.at("output_hex");
    body["comparison"]["exit_changed"] = a.at("exit_code") != b.at("exit_code");
  }
  if (body["status"] == "running")
    body["status"] =
        body["outcome_unknown"] == true ? "interrupted" : "completed";
  if (body["status"] == "completed")
    for (const auto &c : body["cases"])
      if (c.value("status", "") != "observed" || c.value("partial", false) ||
          (c.contains("state") &&
           c.at("state").value("result_status", std::string("completed")) !=
               "completed"))
        body["status"] = "partial";
  body["elapsed_ms"] = now_ms() - start;
  save();
  return knowledge_put(
      store,
      {{"project", p},
       {"kind", "product"},
       {"title", "Bounded runtime experiment"},
       {"state", "unknown"},
       {"scope", args.at("scope")},
       {"body", body},
       {"dependencies", J::array({{{"type", "artifact"},
                                   {"id", target.at("artifact_sha256")},
                                   {"pin", target.at("artifact_sha256")}}})},
       {"author", "native-experiment"}},
      true);
}
J reconcile_experiment(ProjectStore &store, const J &inv, const J &r) {
  keys(r, {"project", "action_id"});
  const auto p = inv.at("project").get<std::string>();
  Db db(store.root() / "indago-native.sqlite3");
  Q q(db, "SELECT record FROM wb_investigation_actions WHERE project=? AND "
          "investigation=? AND id=?");
  if (!q.s(1, p)
           .s(2, inv.at("id").get<std::string>())
           .s(3, r.at("action_id").get<std::string>())
           .row())
    throw std::runtime_error("experiment action outside investigation");
  const auto action = J::parse(q.text(0));
  const auto request = action.at("request");
  if (request.at("backend") != "workbench" ||
      request.at("operation") != "experiment.run")
    throw std::runtime_error("not a runtime experiment action");
  J out{{"action_id", r.at("action_id")},
        {"action_status", action.at("status")},
        {"sessions", J::array()},
        {"replayed", false},
        {"outcome_unknown", true},
        {"journal_found", false},
        {"scope", "read-only reconciliation; terminal sessions do not prove "
                  "absence of escaped children or external effects"}};
  const auto directory = store.root() / "runtime-experiments";
  std::size_t scanned = 0;
  if (!fs::exists(directory))
    return out;
  for (const auto &entry : fs::directory_iterator(directory)) {
    if (++scanned > 128) {
      out["scan_partial"] = true;
      break;
    }
    if (entry.is_symlink() || !entry.is_regular_file() ||
        entry.file_size() > 2097152)
      continue;
    J journal;
    try {
      journal = J::parse(wb::read(entry.path(), 2097152));
    } catch (...) {
      continue;
    }
    if (journal.value("request_sha256", std::string{}) !=
        sha256_text(request.at("arguments").dump()))
      continue;
    if (journal.at("request").at("sealed").at("investigation") != inv.at("id"))
      continue;
    out["journal_found"] = true;
    out["journal_sha256"] = sha256_text(journal.dump());
    bool unknown = false;
    std::set<std::string> sessions;
    auto recover_session = [&](const J &value) {
      if (value.is_null() || !fs::exists(store.root() / "runtime.sqlite3"))
        return false;
      Db runtime(store.root() / "runtime.sqlite3");
      Q find(runtime,
             "SELECT id FROM runtime_sessions WHERE project=? AND "
             "json_extract(record,'$.request.experiment_key')=? LIMIT 2");
      if (!find.s(1, p).s(2, value.get<std::string>()).row())
        return false;
      const auto id = find.text(0);
      if (find.row())
        return false;
      sessions.insert(id);
      return true;
    };
    for (const auto &c : journal.at("cases")) {
      if (c.contains("session"))
        sessions.insert(c.at("session").get<std::string>());
      else if (c.value("dispatch_started", false))
        unknown |= !recover_session(c.value("launch_key", J(nullptr)));
      if (c.contains("pending_companion"))
        unknown |= !recover_session(
            c.at("pending_companion").value("launch_key", J(nullptr)));
      if (c.contains("replay_session"))
        sessions.insert(c.at("replay_session").get<std::string>());
      else if (c.value("replay_dispatch_started", false))
        unknown = true;
      for (const auto &peer : c.value("companions", J::array()))
        sessions.insert(peer.at("id").get<std::string>());
      if (c.contains("pending_step")) {
        bool completed = false;
        if (fs::exists(store.root() / "runtime.sqlite3") &&
            c.at("pending_step").contains("experiment_key")) {
          Db runtime(store.root() / "runtime.sqlite3");
          Q pending(runtime,
                    "SELECT id,state FROM runtime_requests WHERE session=? AND "
                    "json_extract(request,'$.experiment_key')=? LIMIT 2");
          if (pending
                  .s(1, c.at("pending_step").at("session").get<std::string>())
                  .s(2, c.at("pending_step")
                            .at("experiment_key")
                            .get<std::string>())
                  .row()) {
            const auto id = pending.text(0), state = pending.text(1);
            completed = state == "completed" || state == "failed";
            out["requests"].push_back({{"id", id}, {"state", state}});
            if (pending.row())
              completed = false;
          }
        }
        unknown |= !completed;
      }
    }
    bool all_terminal = true;
    for (const auto &sid : sessions)
      try {
        const auto state = runtime_command(
            store, {},
            {{"operation", "status"}, {"project", p}, {"session", sid}});
        if (!harness_contains_artifact(inv, state.at("artifact_sha256")))
          throw std::runtime_error("runtime artifact outside scope");
        out["sessions"].push_back(
            {{"id", sid},
             {"state", state.at("state")},
             {"terminal", terminal(state)},
             {"heartbeat_ms", state.value("heartbeat_ms", J(nullptr))}});
        all_terminal &= terminal(state);
      } catch (const std::exception &e) {
        out["sessions"].push_back({{"id", sid}, {"error", e.what()}});
        unknown = true;
        all_terminal = false;
      }
    out["known_sessions_terminal"] = all_terminal;
    out["outcome_unknown"] = unknown || !all_terminal;
    out["next_action"] =
        unknown ? "operator reconciliation required; do not repeat dispatch"
        : all_terminal
            ? "retain observations; external side effects are not rolled back"
            : "wait or explicitly cancel/terminate these owned runtime "
              "sessions";
    break;
  }
  return out;
}
J normalize_experiment_cleanup(const ProjectStore &store, const J &inv,
                               const J &selected, J args) {
  if (!inv.at("envelope").contains("runtime_execution"))
    throw std::runtime_error("cleanup requires local execution authority");
  keys(args, {"project", "scope", "action_id", "sealed"});
  Db db(store.root() / "indago-native.sqlite3");
  Q q(db, "SELECT record FROM wb_investigation_actions WHERE project=? AND "
          "investigation=? AND id=?");
  if (!q.s(1, inv.at("project").get<std::string>())
           .s(2, inv.at("id").get<std::string>())
           .s(3, args.at("action_id").get<std::string>())
           .row())
    throw std::runtime_error("cleanup action outside investigation");
  const auto action = J::parse(q.text(0));
  if (action.at("request").at("backend") != "workbench" ||
      action.at("request").at("operation") != "experiment.run" ||
      action.at("request").at("artifact_sha256") !=
          selected.at("artifact_sha256"))
    throw std::runtime_error("cleanup does not own the selected experiment");
  const J sealed{{"investigation", inv.at("id")},
                 {"request_sha256", sha256_text(action.at("request").dump())}};
  if (args.contains("sealed") && args.at("sealed") != sealed)
    throw std::runtime_error("cleanup identity changed");
  args["sealed"] = sealed;
  return args;
}
J cleanup_experiment(ProjectStore &store, const J &args) {
  const auto p = args.at("project").get<std::string>();
  J inv;
  {
    Db db(store.root() / "indago-native.sqlite3");
    Q q(db, "SELECT record FROM wb_investigations WHERE project=? AND id=?");
    if (!q.s(1, p)
             .s(2, args.at("sealed").at("investigation").get<std::string>())
             .row())
      throw std::runtime_error("cleanup investigation disappeared");
    inv = J::parse(q.text(0));
  }
  auto before = reconcile_experiment(
      store, inv, {{"project", p}, {"action_id", args.at("action_id")}});
  J body{{"schema", "indago.experiment-cleanup.v1"},
         {"request_sha256", sha256_text(args.dump())},
         {"before", before},
         {"results", J::array()},
         {"status", "partial"},
         {"verified_solve", false},
         {"scope_limit", "cleanup of owned runtime sessions only; external "
                         "effects and escaped children are not rolled back"}};
  for (const auto &entry : before.at("sessions")) {
    const auto sid = entry.at("id");
    try {
      auto state = runtime_command(
          store, {},
          {{"operation", "status"}, {"project", p}, {"session", sid}});
      if (!harness_contains_artifact(inv, state.at("artifact_sha256")))
        throw std::runtime_error("cleanup artifact scope changed");
      if (!terminal(state)) {
        const auto backend = state.value("backend", std::string{});
        const auto command =
            (backend == "dbgeng" || backend == "gdb") ? "terminate" : "cancel";
        const auto result = runtime_command(store, {},
                                            {{"operation", command},
                                             {"project", p},
                                             {"session", sid},
                                             {"timeout_ms", 1000}});
        body["results"].push_back(
            {{"session", sid}, {"operation", command}, {"result", result}});
      } else
        body["results"].push_back(
            {{"session", sid}, {"already_terminal", true}});
    } catch (const std::exception &e) {
      body["results"].push_back({{"session", sid}, {"error", e.what()}});
    }
  }
  const auto end = now_ms() + 2000;
  J after;
  do {
    after = reconcile_experiment(
        store, inv, {{"project", p}, {"action_id", args.at("action_id")}});
    if (after.value("known_sessions_terminal", false))
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  } while (now_ms() < end);
  body["after"] = after;
  if (after.value("journal_found", false) &&
      !after.value("outcome_unknown", true))
    body["status"] = "completed";
  return knowledge_put(
      store,
      {{"project", p},
       {"kind", "product"},
       {"title", "Owned experiment cleanup"},
       {"state", "unknown"},
       {"scope", args.at("scope")},
       {"body", body},
       {"dependencies",
        J::array({{{"type", "artifact"},
                   {"id", args.at("scope").at("artifact_sha256")},
                   {"pin", args.at("scope").at("artifact_sha256")}}})},
       {"author", "native-experiment-cleanup"}},
      true);
}
} // namespace indago
