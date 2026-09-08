#include "indago/contracts.hpp"
#include "workbench_db.hpp"
#include <atomic>
#include <thread>

namespace indago::wb {
namespace {
J batch_load(Db &db, const std::string &p, const std::string &id) {
  Q q(db, "SELECT record FROM wb_batches WHERE project=? AND id=?");
  if (!q.s(1, p).s(2, id).row())
    throw std::runtime_error("unknown batch");
  return J::parse(q.text(0));
}
void save(Db &db, const std::string &p, const std::string &id, const J &r,
          const std::string &token) {
  Q q(db, "UPDATE wb_batches SET record=?,deadline=? WHERE project=? AND id=? "
          "AND owner=?");
  q.s(1, r.dump()).n(2, now_ms() + 30000).s(3, p).s(4, id).s(5, token).row();
  if (sqlite3_changes(db.p) != 1)
    throw std::runtime_error("batch ownership lost");
}
bool success(const std::string &s, bool partial) {
  return s == "completed" || s == "complete" || (partial && s == "partial");
}
} // namespace
J batch(StaticService &service, const std::string &op, const J &r) {
  auto &store = service.store();
  auto p = project(store, r);
  Db db(store.root() / "indago-native.sqlite3");
  initialize(db);
  if (op == "create") {
    keys(r, {"project", "steps", "budget", "title"});
    auto steps = r.at("steps");
    if (!steps.is_array() || steps.empty() || steps.size() > 64)
      throw std::runtime_error("batch requires 1..64 ordered steps");
    auto budget = r.at("budget");
    keys(budget, {"wall_ms", "output_bytes", "memory_bytes", "max_jobs"});
    J normalized{{"wall_ms", bound(budget, "wall_ms", 600000, 86400000)},
                 {"output_bytes", bound(budget, "output_bytes",
                                        16 * 1024 * 1024, 256 * 1024 * 1024)},
                 {"memory_bytes",
                  bound(budget, "memory_bytes", 2ULL * 1024 * 1024 * 1024,
                        16ULL * 1024 * 1024 * 1024)},
                 {"max_jobs", bound(budget, "max_jobs", 64, 128)}};
    std::set<std::string> names;
    J prepared = J::array();
    for (auto step : steps) {
      keys(step,
           {"name", "depends_on", "allow_partial_dependencies", "request"});
      auto name = step.at("name").get<std::string>();
      identifier(name);
      if (names.contains(name))
        throw std::runtime_error("duplicate batch step name");
      auto deps = step.value("depends_on", J::array());
      if (!deps.is_array() || deps.size() > 64)
        throw std::runtime_error("invalid batch dependencies");
      for (const auto &d : deps)
        if (!names.contains(d.get<std::string>()))
          throw std::runtime_error(
              "dependencies must name preceding steps; cycles forbidden");
      names.insert(name);
      auto action = step.at("request");
      if (action.contains("project") && action["project"] != p)
        throw std::runtime_error("cross-project batch request forbidden");
      action["project"] = p;
      auto backend = action.at("backend").get<std::string>(),
           operation = action.at("operation").get<std::string>();
      if (!std::set<std::string>{"airece", "xair", "sym", "ghidra", "ilspy", "capa", "floss", "lief", "wireshark"}.contains(
              backend) ||
          std::set<std::string>{"annotate", "analyze", "flush", "close"}
              .contains(operation))
        throw std::runtime_error(
            "batch supports read analysis operations only; edits/session "
            "controls require explicit actions");
      if (action.contains("idempotency_key"))
        throw std::runtime_error("batch owns action idempotency keys");
      auto target = store.target(p, action.value("target_id", std::string{}));
      action["target_id"] = target.id;
      action["artifact_sha256"] = target.sha256;
      if (!action.contains("budget"))
        action["budget"] = {{"wall_ms", 60000},
                            {"output_bytes", 1024 * 1024},
                            {"memory_bytes", normalized["memory_bytes"]},
                            {"max_items", 1024}};
      action = service.normalize(action);
      auto &b = action["budget"];
      if (b.value("wall_ms", 120000ULL) >
              normalized["wall_ms"].get<std::size_t>() ||
          b.value("output_bytes", 2097152ULL) >
              normalized["output_bytes"].get<std::size_t>() ||
          b.value("memory_bytes", 2147483648ULL) >
              normalized["memory_bytes"].get<std::size_t>())
        throw std::runtime_error("step budget exceeds batch ceiling");
      prepared.push_back({{"name", name},
                          {"depends_on", deps},
                          {"allow_partial_dependencies",
                           step.value("allow_partial_dependencies", false)},
                          {"request", action},
                          {"status", "pending"},
                          {"attempt", 0}});
    }
    auto id = make_id("batch");
    J record{{"schema", "indago.batch.v1"},
             {"id", id},
             {"project", p},
             {"title", r.value("title", std::string("Bounded analysis batch"))},
             {"status", "queued"},
             {"steps", prepared},
             {"budget", normalized},
             {"reserved_wall_ms", 0},
             {"reserved_output_bytes", 0},
             {"jobs_started", 0},
             {"created_at", utc_timestamp()},
             {"policy", "sequential read analysis; conservative per-attempt "
                        "budget reservations include failed/interrupted jobs; "
                        "no automatic retry of runtime side effects"}};
    Tx tx(db);
    Q q(db, "INSERT INTO wb_batches(project,id,record) VALUES(?,?,?)");
    q.s(1, p).s(2, id).s(3, record.dump()).row();
    event(db, p, id, "created", {{"steps", prepared.size()}});
    tx.commit();
    return record;
  }
  keys(r, {"project", "id", "retry_failed", "reset_cancel", "offset", "limit"});
  auto id = r.at("id").get<std::string>();
  identifier(id);
  if (op == "show")
    return batch_load(db, p, id);
  if (op == "events") {
    batch_load(db, p, id);
    auto limit = bound(r, "limit", 100, 1000),
         offset = bound(r, "offset", 0, 10000000);
    Q q(db, "SELECT sequence,kind,at,record FROM wb_events WHERE project=? AND "
            "id=? ORDER BY sequence LIMIT ? OFFSET ?");
    q.s(1, p).s(2, id).n(3, limit + 1).n(4, offset);
    J events = J::array();
    bool more = false;
    while (q.row()) {
      if (events.size() == limit) {
        more = true;
        break;
      }
      events.push_back({{"sequence", q.num(0)},
                        {"kind", q.text(1)},
                        {"at", q.text(2)},
                        {"detail", J::parse(q.text(3))}});
    }
    return {{"schema", "indago.batch-events.v1"},
            {"events", events},
            {"next_offset", more ? J(offset + events.size()) : J(nullptr)}};
  }
  if (op == "cancel") {
    auto b = batch_load(db, p, id);
    Q q(db, "UPDATE wb_batches SET cancel=1 WHERE project=? AND id=?");
    q.s(1, p).s(2, id).row();
    event(db, p, id, "cancel_requested", J::object());
    for (const auto &step : b["steps"])
      if (step.value("status", std::string{}) == "running" &&
          step.contains("job_id"))
        store.cancel_job(p, step["job_id"].get<std::string>());
    return {{"status", "cancellation_requested"}, {"id", id}};
  }
  if (op != "run")
    throw std::runtime_error("unknown batch operation");
  const auto token = make_id("owner");
  J record;
  {
    Tx tx(db);
    record = batch_load(db, p, id);
    Q claim(db, "UPDATE wb_batches SET owner=?,deadline=?,cancel=CASE WHEN ? "
                "THEN 0 ELSE cancel END WHERE project=? AND id=? AND (owner='' "
                "OR deadline<?)");
    claim.s(1, token)
        .n(2, now_ms() + 30000)
        .n(3, r.value("reset_cancel", false))
        .s(4, p)
        .s(5, id)
        .n(6, now_ms())
        .row();
    if (sqlite3_changes(db.p) != 1)
      throw std::runtime_error("batch already has an active owner");
    event(db, p, id, "run_claimed", {{"owner", token}});
    tx.commit();
  }
  std::atomic<bool> lost = false;
  std::jthread heartbeat([&](std::stop_token stop) {
    try {
      Db hb(store.root() / "indago-native.sqlite3");
      while (!stop.stop_requested()) {
        for (unsigned i = 0; i < 10 && !stop.stop_requested(); ++i)
          std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (stop.stop_requested())
          break;
        Q q(hb, "UPDATE wb_batches SET deadline=? WHERE project=? AND id=? AND "
                "owner=?");
        q.n(1, now_ms() + 30000).s(2, p).s(3, id).s(4, token).row();
        if (sqlite3_changes(hb.p) != 1) {
          lost = true;
          break;
        }
      }
    } catch (...) {
      lost = true;
    }
  });
  auto release = [&] {
    heartbeat.request_stop();
    heartbeat.join();
    Q q(db, "UPDATE wb_batches SET owner='',deadline=0 WHERE project=? AND "
            "id=? AND owner=?");
    q.s(1, p).s(2, id).s(3, token).row();
  };
  try {
    record["status"] = "running";
    save(db, p, id, record, token);
    std::map<std::string, std::string> states;
    for (auto &step : record["steps"]) {
      if (lost)
        throw std::runtime_error("batch heartbeat lost");
      bool cancelled = false;
      {
        Q cancel(db, "SELECT cancel FROM wb_batches WHERE project=? AND id=?");
        cancel.s(1, p).s(2, id).row();
        cancelled = cancel.num(0) != 0;
      }
      if (cancelled) {
        record["status"] = "cancelled";
        break;
      }
      auto name = step["name"].get<std::string>(),
           status = step["status"].get<std::string>();
      if (success(status, true)) {
        states[name] = status;
        continue;
      }
      bool ready = true;
      for (const auto &d : step["depends_on"])
        if (!success(states[d.get<std::string>()],
                     step["allow_partial_dependencies"]))
          ready = false;
      if (!ready) {
        step["status"] = "dependency_blocked";
        states[name] = "dependency_blocked";
        continue;
      }
      if (step.contains("job_id")) {
        auto previous =
            store.job_info(p, step["job_id"].get<std::string>())["jobs"][0];
        if (previous.contains("result")) {
          step["status"] = previous["result"]["status"];
          step["result_revision"] = previous["revision"];
          status = step["status"];
          if (success(status, true)) {
            states[name] = status;
            continue;
          }
        } else if (previous["status"] == "running") {
          store.recover_jobs(p);
          previous =
              store.job_info(p, step["job_id"].get<std::string>())["jobs"][0];
          if (previous["status"] == "running") {
            record["status"] = "waiting_for_job";
            break;
          }
          status = previous["status"];
          step["status"] = status;
        }
        if (status != "running" && status != "pending" &&
            previous["status"] != "queued") {
          if (!r.value("retry_failed", false) ||
              step["attempt"].get<int>() >= 2) {
            states[name] = status;
            continue;
          }
          step.erase("job_id");
        }
      }
      auto action = step["request"];
      const auto wall = action["budget"].value("wall_ms", 120000ULL),
                 output = action["budget"].value("output_bytes", 2097152ULL);
      if (!step.contains("job_id")) {
        if (!step.value("reserved", false) &&
            (record["jobs_started"].get<std::size_t>() >=
                 record["budget"]["max_jobs"].get<std::size_t>() ||
             record["reserved_wall_ms"].get<std::size_t>() + wall >
                 record["budget"]["wall_ms"].get<std::size_t>() ||
             record["reserved_output_bytes"].get<std::size_t>() + output >
                 record["budget"]["output_bytes"].get<std::size_t>())) {
          record["status"] = "budget_exhausted";
          break;
        }
        action["idempotency_key"] =
            id + ":" + sha256_text(name) + ":" +
            std::to_string(step["attempt"].get<int>() + 1);
        // Persist reservation/key before submission. A restart reuses this
        // attempt, not another side effect.
        if (!step.value("reserved", false)) {
          record["reserved_wall_ms"] =
              record["reserved_wall_ms"].get<std::size_t>() + wall;
          record["reserved_output_bytes"] =
              record["reserved_output_bytes"].get<std::size_t>() + output;
          record["jobs_started"] = record["jobs_started"].get<int>() + 1;
          step["reserved"] = true;
          step["reserved_key"] = action["idempotency_key"];
          save(db, p, id, record, token);
        }
        action["idempotency_key"] = step["reserved_key"];
        auto job = service.prepare(action);
        step["job_id"] = job["id"];
        step["attempt"] = step["attempt"].get<int>() + 1;
        step["reserved"] = false;
      }
      step["status"] = "running";
      save(db, p, id, record, token);
      event(db, p, id, "step_started",
            {{"step", name}, {"job_id", step["job_id"]}});
      auto job =
          store.job_info(p, step["job_id"].get<std::string>())["jobs"][0];
      std::atomic<bool> executing = true;
      auto jobId = step["job_id"].get<std::string>();
      std::jthread cancellation([&](std::stop_token stop) {
        try {
          Db cdb(store.root() / "indago-native.sqlite3");
          while (!stop.stop_requested() && executing) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            Q q(cdb, "SELECT cancel FROM wb_batches WHERE project=? AND id=?");
            q.s(1, p).s(2, id).row();
            if (lost || q.num(0)) {
              store.cancel_job(p, jobId);
              break;
            }
          }
        } catch (...) {
          lost = true;
        }
      });
      J result;
      try {
        result = service.execute(job);
      } catch (...) {
        executing = false;
        cancellation.request_stop();
        throw;
      }
      executing = false;
      cancellation.request_stop();
      cancellation.join();
      step["status"] = result["status"];
      step["result_revision"] = result.value("result_revision", J{});
      step["evidence_ids"] = result.value("evidence_ids", J::array());
      step["retry_class"] = success(step["status"], true)
                                ? "not_needed"
                                : "explicit_read_analysis_retry_only";
      states[name] = step["status"];
      save(db, p, id, record, token);
      event(db, p, id, "step_finished",
            {{"step", name}, {"status", step["status"]}});
    }
    if (record["status"] == "running") {
      bool all = true;
      for (const auto &s : record["steps"])
        all = all && success(s["status"], false);
      record["status"] = all ? "completed" : "partial";
    }
    save(db, p, id, record, token);
    event(db, p, id, "run_finished", {{"status", record["status"]}});
    release();
    return record;
  } catch (...) {
    try {
      record["status"] = "interrupted";
      save(db, p, id, record, token);
      event(db, p, id, "interrupted",
            {{"retry", "resume explicitly; completed jobs will not repeat"}});
    } catch (...) {
    }
    release();
    throw;
  }
}
} // namespace indago::wb
