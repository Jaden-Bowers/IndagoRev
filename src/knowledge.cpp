#include "workbench_db.hpp"
#include "workbench_publication.hpp"
#include <map>

namespace indago::wb {
namespace {
J load(Db &db, const std::string &p, const std::string &id,
       std::int64_t rev = 0) {
  Q q(db, "SELECT r.record,r.sha FROM wb_records r WHERE r.project=? AND "
          "r.id=? AND r.revision=CASE WHEN ?=0 THEN (SELECT revision FROM "
          "wb_heads WHERE project=r.project AND id=r.id) ELSE ? END");
  q.s(1, p).s(2, id).n(3, rev).n(4, rev);
  if (!q.row())
    throw std::runtime_error("unknown knowledge revision: " + id);
  if (sha256_text(q.text(0)) != q.text(1))
    throw std::runtime_error("knowledge integrity mismatch");
  return J::parse(q.text(0));
}
J resolve(Db &db, const ProjectStore &store, const std::string &p,
          const J &dependency) {
  keys(dependency, {"type", "id", "pin"});
  auto type = dependency.at("type").get<std::string>(),
       id = dependency.at("id").get<std::string>();
  J d{{"type", type}, {"id", id}};
  std::string pin;
  if (type == "record") {
    auto record = load(db, p, id);
    pin = std::to_string(record["revision"].get<std::int64_t>());
  } else if (type == "artifact") {
    hash(id);
    Q q(db, "SELECT sha FROM targets WHERE project=? AND sha=?");
    if (!q.s(1, p).s(2, id).row())
      throw std::runtime_error("unknown project artifact");
    if (sha256_file(object(store, id)) != id)
      throw std::runtime_error("artifact integrity mismatch");
    pin = id;
  } else if (type == "entity" || type == "evidence" || type == "revision") {
    const std::string sql =
        type == "entity"
            ? "SELECT revision FROM static_entities WHERE project=? AND id=?"
        : type == "evidence"
            ? "SELECT revision FROM evidence WHERE project=? AND id=?"
            : "SELECT revision FROM indexed_revisions WHERE project=? AND "
              "revision=?";
    Q q(db, sql);
    if (!q.s(1, p).s(2, id).row())
      throw std::runtime_error("unknown project dependency: " + id);
    pin = q.text(0);
  } else if (type == "observation" || type == "epoch") {
    if (!fs::exists(store.root() / "runtime.sqlite3"))
      throw std::runtime_error("runtime evidence unavailable");
    Db runtime(store.root() / "runtime.sqlite3");
    Q q(runtime, type == "observation"
                     ? "SELECT o.record,o.sha FROM runtime_observations o JOIN "
                       "runtime_sessions s ON s.id=o.session WHERE s.project=? "
                       "AND o.id=?"
                     : "SELECT e.record,'' FROM runtime_code_epochs e JOIN "
                       "runtime_sessions s ON s.id=e.session WHERE s.project=? "
                       "AND e.id=?");
    if (!q.s(1, p).s(2, id).row())
      throw std::runtime_error("unknown project runtime dependency");
    pin = sha256_text(q.text(0));
    if (type == "observation" && pin != q.text(1))
      throw std::runtime_error("runtime evidence integrity mismatch");
  } else
    throw std::runtime_error(
        "dependency type must be record, artifact, entity, evidence, revision, "
        "observation or epoch");
  if (dependency.contains("pin") && dependency["pin"] != pin)
    throw std::runtime_error("dependency pin is stale");
  d["pin"] = pin;
  return d;
}
struct Freshness {
  Db &db;
  const ProjectStore &store;
  std::string p;
  std::size_t visited = 0;
  bool bounded = false;
  std::set<std::string> active;
  J check(const J &r, unsigned depth = 0) {
    J reasons = J::array();
    if (depth > 32 || ++visited > 4096) {
      bounded = true;
      return J::array({{{"reason", "dependency traversal limit"}}});
    }
    auto key = r["id"].get<std::string>() + ":" +
               std::to_string(r["revision"].get<int>());
    if (!active.insert(key).second)
      return J::array({{{"reason", "dependency cycle"}}});
    for (const auto &d : r["dependencies"]) {
      auto type = d["type"].get<std::string>(), id = d["id"].get<std::string>(),
           pin = d["pin"].get<std::string>();
      if (type == "record") {
        auto current = load(db, p, id);
        if (std::to_string(current["revision"].get<int>()) != pin)
          reasons.push_back({{"dependency", d}, {"reason", "record revised"}});
        auto inherited = check(load(db, p, id, std::stoll(pin)), depth + 1);
        if (!inherited.empty())
          reasons.push_back({{"dependency", d},
                             {"reason", "upstream dependency stale"},
                             {"upstream", inherited}});
      } else if (type == "artifact") {
        // Hashes are verified when artifacts are consumed/exported; existence
        // is a cheap retrieval check.
        if (!fs::is_regular_file(object(store, id)))
          reasons.push_back(
              {{"dependency", d}, {"reason", "artifact unavailable"}});
      } else if (type == "observation" || type == "epoch") {
        try {
          auto current = resolve(db, store, p, {{"type", type}, {"id", id}});
          if (current["pin"] != pin)
            reasons.push_back(
                {{"dependency", d}, {"reason", "runtime evidence changed"}});
        } catch (const std::exception &) {
          reasons.push_back(
              {{"dependency", d},
               {"reason", "runtime evidence missing or corrupt"}});
        }
      } else {
        Q q(db, "SELECT 1 FROM analysis_heads WHERE project=? AND revision=?");
        if (!q.s(1, p).s(2, pin).row())
          reasons.push_back({{"dependency", d},
                             {"reason", "analysis superseded or not current"}});
        Q edited(
            db,
            R"sql(SELECT 1 FROM indexed_revisions old JOIN indexed_revisions newer ON newer.project=old.project AND newer.artifact=old.artifact AND newer.backend=old.backend
WHERE old.project=? AND old.revision=? AND old.backend='ghidra'
AND json_extract(old.record,'$.provenance.session_key') IS NOT NULL
AND json_extract(old.record,'$.provenance.session_key')=json_extract(newer.record,'$.provenance.session_key')
AND json_extract(newer.record,'$.backend_program_revision')>json_extract(old.record,'$.backend_program_revision') LIMIT 1)sql");
        if (edited.s(1, p).s(2, pin).row())
          reasons.push_back(
              {{"dependency", d},
               {"reason",
                "Ghidra Program revision advanced; requery affected view"}});
      }
      if (reasons.size() >= 64) {
        bounded = true;
        break;
      }
    }
    active.erase(key);
    return reasons;
  }
};
J decorated(Db &db, const ProjectStore &store, const std::string &p, J r) {
  Freshness f{db, store, p};
  r["stale_reasons"] = f.check(r);
  Q head(db, "SELECT revision FROM wb_heads WHERE project=? AND id=?");
  head.s(1, p).s(2, r["id"].get<std::string>());
  if (head.row() && head.num(0) != r["revision"].get<std::int64_t>())
    r["stale_reasons"].push_back({{"reason", "record revision superseded"}});
  r["freshness"] = f.bounded                    ? "unknown"
                   : r["stale_reasons"].empty() ? "current"
                                                : "stale";
  r["freshness_complete"] = !f.bounded;
  return r;
}
} // namespace

J knowledge_put(const ProjectStore &store, const J &request, bool internal) {
  keys(request, {"project", "id", "expected_revision", "kind", "title", "state",
                 "scope", "body", "assumptions", "dependencies", "support",
                 "counterevidence", "author"});
  auto p = project(store, request);
  Db db(store.root() / "indago-native.sqlite3");
  initialize(db);
  Tx tx(db);
  check_publication_dependencies(db, p);
  auto id = request.value("id", make_id("kn"));
  identifier(id);
  auto expected = bound(request, "expected_revision", 0, 100000000);
  Q head(db, "SELECT revision FROM wb_heads WHERE project=? AND id=?");
  head.s(1, p).s(2, id);
  auto actual = head.row() ? head.num(0) : 0;
  if (static_cast<std::int64_t>(expected) != actual)
    throw std::runtime_error(
        "revision_conflict: expected_revision does not match current record");
  const auto kind = request.at("kind").get<std::string>();
  if (!std::set<std::string>{"behavior", "hypothesis", "question", "summary",
                             "assumption", "product", "transformation",
                             "validation", "recognition", "signature",
                             "system_manifest"}
           .contains(kind))
    throw std::runtime_error("unknown knowledge kind");
  if (!internal && (kind == "validation" || kind == "transformation" ||
                    kind == "system_manifest"))
    throw std::runtime_error(
        "use validate, transform or system to publish computed records");
  auto state = request.value("state", std::string("inferred"));
  if (!std::set<std::string>{"observed", "derived", "inferred", "contradicted",
                             "unknown", "validated"}
           .contains(state) ||
      (!internal && state == "validated"))
    throw std::runtime_error(
        "validated state requires a deterministic validator");
  auto title = request.at("title").get<std::string>();
  if (title.empty() || title.size() > 4096)
    throw std::runtime_error("title must contain 1..4096 bytes");
  auto scope = request.at("scope");
  if (!scope.is_object() || scope.empty())
    throw std::runtime_error("explicit nonempty scope required");
  auto body = request.at("body");
  if (!body.is_object())
    throw std::runtime_error("body must be an object");
  if (kind == "behavior")
    for (const auto *field : {"inputs", "outputs", "guards", "state_changes",
                              "side_effects", "unknowns"})
      if (!body.contains(field) || !body[field].is_array())
        throw std::runtime_error(std::string("behavior requires array: ") +
                                 field);
  if (kind == "hypothesis")
    for (const auto *field : {"prediction", "alternatives", "unknowns"})
      if (!body.contains(field))
        throw std::runtime_error(std::string("hypothesis requires ") + field);
  if (kind == "signature") {
    hash(body.at("sha256").get<std::string>());
    bound(body, "offset", 0, 512ULL * 1024 * 1024);
    bound(body, "size", 0, 512ULL * 1024 * 1024);
  }
  J deps = J::array();
  std::set<std::string> seen;
  auto add = [&](const J &input) {
    auto d = resolve(db, store, p, input);
    if (d["type"] == "record" && d["id"] == id)
      throw std::runtime_error("self dependency forbidden");
    if (seen.insert(d.dump()).second)
      deps.push_back(d);
  };
  auto list = request.value("dependencies", J::array());
  if (!list.is_array() || list.size() > 128)
    throw std::runtime_error("dependencies must be an array <=128");
  for (const auto &d : list)
    add(d);
  for (const auto *field : {"support", "counterevidence"}) {
    auto refs = request.value(field, J::array());
    if (!refs.is_array() || refs.size() > 128)
      throw std::runtime_error("evidence references must be arrays <=128");
    for (const auto &ref : refs)
      add({{"type", "evidence"}, {"id", ref}});
  }
  if (scope.contains("artifact_sha256"))
    add({{"type", "artifact"}, {"id", scope["artifact_sha256"]}});
  if (scope.contains("observation_id"))
    add({{"type", "observation"}, {"id", scope["observation_id"]}});
  if (scope.contains("epoch_id"))
    add({{"type", "epoch"}, {"id", scope["epoch_id"]}});
  if (deps.size() > 128)
    throw std::runtime_error("combined dependencies exceed 128");
  auto assumptions = request.value("assumptions", J::array());
  if (!assumptions.is_array())
    throw std::runtime_error("assumptions must be an array");
  J r{{"schema", "indago.knowledge-record.v1"},
      {"project", p},
      {"id", id},
      {"revision", actual + 1},
      {"kind", kind},
      {"title", title},
      {"state", state},
      {"scope", scope},
      {"body", body},
      {"assumptions", assumptions},
      {"dependencies", deps},
      {"support", request.value("support", J::array())},
      {"counterevidence", request.value("counterevidence", J::array())},
      {"author", request.value("author", std::string("cli"))},
      {"created_at", utc_timestamp()},
      {"assertion_origin",
       internal ? "deterministic_operation" : "caller_assertion"},
      {"semantic_entailment_checked", false}};
  if (publication_context)
    r["harness_origin"] = publication_origin();
  auto text = r.dump();
  if (text.size() > 256 * 1024)
    throw std::runtime_error("knowledge record exceeds 256 KiB");
  Q insert(db, "INSERT INTO wb_records VALUES(?,?,?,?,?,?)");
  insert.s(1, p)
      .s(2, id)
      .n(3, actual + 1)
      .s(4, kind)
      .s(5, text)
      .s(6, sha256_text(text))
      .row();
  for (const auto &d : deps) {
    Q q(db, "INSERT INTO wb_dependencies VALUES(?,?,?,?,?,?)");
    q.s(1, p)
        .s(2, id)
        .n(3, actual + 1)
        .s(4, d["type"].get<std::string>())
        .s(5, d["id"].get<std::string>())
        .s(6, d["pin"].get<std::string>())
        .row();
  }
  Q update(db, "INSERT INTO wb_heads VALUES(?,?,?) ON CONFLICT(project,id) DO "
               "UPDATE SET revision=excluded.revision");
  update.s(1, p).s(2, id).n(3, actual + 1).row();
  event(db, p, id, "revision_published",
        {{"revision", actual + 1}, {"sha256", sha256_text(text)}});
  link_publication(db, r, sha256_text(text));
  tx.commit();
  return decorated(db, store, p, r);
}

J knowledge(const ProjectStore &store, const std::string &op, const J &r) {
  if (op == "put")
    return knowledge_put(store, r);
  keys(r, {"project", "id", "revision", "kind", "search", "limit", "offset",
           "history", "type", "artifact"});
  auto p = project(store, r);
  Db db(store.root() / "indago-native.sqlite3");
  initialize(db);
  if (op == "show") {
    auto id = r.at("id").get<std::string>();
    return decorated(db, store, p,
                     load(db, p, id, bound(r, "revision", 0, 100000000)));
  }
  const auto limit = bound(r, "limit", 50, 200),
             offset = bound(r, "offset", 0, 10000000);
  if (!limit)
    throw std::runtime_error("limit must be positive");
  J rows = J::array();
  if (op == "impact") {
    auto id = r.at("id").get<std::string>(),
         type = r.value("type", std::string("record"));
    std::vector<std::pair<std::string, std::string>> todo{{type, id}};
    std::set<std::string> seen;
    for (std::size_t pos = 0; pos < todo.size() && rows.size() < limit; ++pos) {
      Q q(db, "SELECT DISTINCT d.id FROM wb_dependencies d JOIN wb_heads h ON "
              "h.project=d.project AND h.id=d.id AND h.revision=d.revision "
              "WHERE d.project=? AND d.type=? AND d.dependency=? ORDER BY d.id "
              "LIMIT 201");
      q.s(1, p).s(2, todo[pos].first).s(3, todo[pos].second);
      while (q.row()) {
        auto next = q.text(0);
        if (seen.insert(next).second) {
          todo.emplace_back("record", next);
          rows.push_back(decorated(db, store, p, load(db, p, next)));
          if (rows.size() == limit)
            break;
        }
      }
    }
    return {
        {"schema", "indago.knowledge-impact.v1"},
        {"records", rows},
        {"partial", rows.size() == limit},
        {"interpretation",
         "Dependency impact, not a claim that affected conclusions are false"}};
  }
  if (op != "list" && op != "refresh")
    throw std::runtime_error("unknown knowledge operation");
  std::string sql =
      "SELECT r.id,r.revision FROM wb_records r WHERE r.project=? AND (?='' OR "
      "r.kind=?) AND instr(lower(r.record),lower(?))>0 AND "
      "(?='' OR json_extract(r.record,'$.scope.artifact_sha256')=?)";
  if (!r.value("history", false))
    sql += " AND EXISTS(SELECT 1 FROM wb_heads h WHERE h.project=r.project AND "
           "h.id=r.id AND h.revision=r.revision)";
  sql += " ORDER BY r.id,r.revision LIMIT ? OFFSET ?";
  Q q(db, sql);
  auto kind = r.value("kind", std::string{});
  auto artifact = r.value("artifact", std::string{});
  if (!artifact.empty())
    hash(artifact);
  q.s(1, p)
      .s(2, kind)
      .s(3, kind)
      .s(4, r.value("search", std::string{}))
      .s(5, artifact)
      .s(6, artifact)
      .n(7, limit + 1)
      .n(8, offset);
  bool more = false;
  while (q.row()) {
    if (rows.size() == limit) {
      more = true;
      break;
    }
    rows.push_back(decorated(db, store, p, load(db, p, q.text(0), q.num(1))));
  }
  return {{"schema", "indago.knowledge-list.v1"},
          {"records", rows},
          {"next_offset", more ? J(offset + rows.size()) : J(nullptr)},
          {"freshness_policy", "computed transitively from pinned "
                               "dependencies; source claims remain immutable"}};
}
} // namespace indago::wb
