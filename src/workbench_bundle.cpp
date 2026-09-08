#include "workbench_db.hpp"
#include <map>

namespace indago::wb {
namespace {
const std::vector<std::string> core_tables = {"projects",
                                              "targets",
                                              "jobs",
                                              "evidence",
                                              "functions",
                                              "function_views",
                                              "idempotency",
                                              "job_leases",
                                              "job_events",
                                              "indexed_revisions",
                                              "artifact_layouts",
                                              "analysis_heads",
                                              "static_entities",
                                              "static_relations",
                                              "static_claims",
                                              "artifact_derivations",
                                              "wb_records",
                                              "wb_heads",
                                              "wb_dependencies",
                                              "wb_batches",
                                              "wb_events",
                                              "wb_investigations",
                                              "wb_investigation_actions",
                                              "wb_model_runs"};
const std::vector<std::string> runtime_tables = {
    "runtime_sessions", "runtime_requests", "runtime_observations",
    "runtime_code_epochs", "runtime_lifetimes"};
std::vector<std::string> columns(Db &db, const std::string &table) {
  Q q(db, "PRAGMA table_info(" + table + ")");
  std::vector<std::string> cols;
  while (q.row())
    cols.push_back(q.text(1));
  return cols;
}
void hashes(const J &value, std::set<std::string> &refs, unsigned depth = 0) {
  if (depth > 64)
    throw std::runtime_error("reference traversal exceeds depth budget");
  if (value.is_string()) {
    auto s = value.get<std::string>();
    if (s.size() == 64 && s.find_first_not_of("0123456789abcdef") == s.npos)
      refs.insert(s);
    else if (!s.empty() && (s[0] == '{' || s[0] == '[')) {
      auto v = J::parse(s, nullptr, false);
      if (!v.is_discarded())
        hashes(v, refs, depth + 1);
    }
  } else if (value.is_structured())
    for (const auto &v : value)
      hashes(v, refs, depth + 1);
}
void raw_files(const J &value, std::map<std::string, fs::path> &files,
               unsigned depth = 0) {
  if (depth > 64)
    throw std::runtime_error("raw-file traversal limit");
  if (value.is_string()) {
    auto s = value.get<std::string>();
    if (!s.empty() && (s[0] == '{' || s[0] == '[')) {
      auto v = J::parse(s, nullptr, false);
      if (!v.is_discarded())
        raw_files(v, files, depth + 1);
    }
  } else if (value.is_structured()) {
    if (value.is_object() && value.contains("raw_file") &&
        value.contains("raw_sha256") && value["raw_file"].is_string() &&
        value["raw_sha256"].is_string()) {
      auto sha = value["raw_sha256"].get<std::string>();
      hash(sha);
      files[sha] = fs::path(value["raw_file"].get<std::string>());
    }
    for (const auto &v : value)
      raw_files(v, files, depth + 1);
  }
}
J rows(Db &db, const std::string &table, const std::string &p,
       std::size_t &count) {
  const auto cols = columns(db, table);
  if (cols.empty())
    return J::array();
  std::string where;
  if (table == "projects")
    where = "name=?";
  else if (table == "function_views")
    where = "function IN (SELECT id FROM functions WHERE project=?)";
  else if (table == "job_leases" || table == "job_events")
    where = "job IN (SELECT id FROM jobs WHERE project=?)";
  else if (table.starts_with("runtime_") && table != "runtime_sessions")
    where = "session IN (SELECT id FROM runtime_sessions WHERE project=?)";
  else
    where = "project=?";
  Q q(db, "SELECT * FROM " + table + " WHERE " + where + " ORDER BY rowid");
  q.s(1, p);
  J out = J::array();
  while (q.row()) {
    if (++count > 100000)
      throw std::runtime_error(
          "bundle exceeds 100000 rows; narrow project before export");
    J row = J::object();
    for (std::size_t i = 0; i < cols.size(); ++i) {
      auto type = sqlite3_column_type(q.p, static_cast<int>(i));
      row[cols[i]] = type == SQLITE_NULL      ? J(nullptr)
                     : type == SQLITE_INTEGER ? J(q.num(static_cast<int>(i)))
                                              : J(q.text(static_cast<int>(i)));
    }
    out.push_back(row);
  }
  return out;
}
void insert_rows(Db &db, const std::string &table, const J &records) {
  auto cols = columns(db, table);
  if (cols.empty())
    throw std::runtime_error("bundle table unsupported");
  std::string sql = "INSERT INTO " + table + "(";
  for (std::size_t i = 0; i < cols.size(); ++i) {
    if (i)
      sql += ",";
    sql += '"' + cols[i] + '"';
  }
  sql += ") VALUES(";
  for (std::size_t i = 0; i < cols.size(); ++i)
    sql += i ? ",?" : "?";
  sql += ")";
  for (const auto &row : records) {
    if (!row.is_object() || row.size() != cols.size())
      throw std::runtime_error("bundle columns mismatch");
    Q q(db, sql);
    for (std::size_t i = 0; i < cols.size(); ++i) {
      const auto &v = row.at(cols[i]);
      auto index = static_cast<int>(i + 1);
      if (v.is_null())
        sqlite3_bind_null(q.p, index);
      else if (v.is_number_integer())
        q.n(index, v.get<std::int64_t>());
      else if (v.is_string())
        q.s(index, v.get<std::string>());
      else
        throw std::runtime_error("invalid bundle SQL value");
    }
    q.row();
  }
}
void safe_child(const fs::path &root, const fs::path &path) {
  auto base = fs::weakly_canonical(root), resolved = fs::weakly_canonical(path);
  auto rel = resolved.lexically_relative(base);
  if (rel.empty() || rel.is_absolute() || *rel.begin() == "..")
    throw std::runtime_error("path escapes bundle/workspace");
  for (auto current = path; current != root && current.has_parent_path();
       current = current.parent_path()) {
    if (fs::is_symlink(current))
      throw std::runtime_error("symlink in artifact path");
    if (current.parent_path() == current)
      break;
  }
}
void copy_verified(const fs::path &source, const fs::path &dest,
                   const std::string &sha) {
  if (sha256_file(source) != sha)
    throw std::runtime_error("bundle object integrity mismatch");
  fs::create_directories(dest.parent_path());
  fs::copy_file(source, dest);
  if (sha256_file(dest) != sha)
    throw std::runtime_error("copied bundle object integrity mismatch");
}
// A checksum is transport integrity, not authority to revive sessions or to
// import records from a different project. Validate the snapshot before
// staging.
void validate_snapshot(const J &manifest, const std::string &project) {
  const auto &core = manifest.at("core"), &runtime = manifest.at("runtime");
  auto projects = core.value("projects", J::array());
  if (!projects.is_array() || projects.size() != 1 ||
      projects[0].at("name") != project)
    throw std::runtime_error(
        "bundle must contain exactly its declared project");
  std::size_t count = 0;
  for (const auto *collection : {&core, &runtime})
    for (auto it = collection->begin(); it != collection->end(); ++it) {
      if (!it.value().is_array() || (count += it.value().size()) > 100000)
        throw std::runtime_error("bundle row budget exceeded");
      for (const auto &row : it.value()) {
        if (!row.is_object() ||
            (row.contains("project") && row["project"] != project))
          throw std::runtime_error("cross-project or invalid bundle row");
        if (row.contains("record")) {
          auto record = J::parse(row.at("record").get<std::string>());
          if (!record.is_object() ||
              (record.contains("project") && record["project"] != project))
            throw std::runtime_error("cross-project or invalid bundle record");
        }
      }
    }
  for (const auto &row : core.value("jobs", J::array()))
    if (!std::set<std::string>{"completed", "partial", "failed", "cancelled",
                               "unavailable", "invalid_request", "timeout",
                               "not_found", "interrupted"}
             .contains(row.at("status").get<std::string>()))
      throw std::runtime_error("bundle contains unsettled job");
  for (const auto &row : core.value("wb_investigations", J::array()))
    if (row.at("token_hash") != "" || row.at("deadline") != 0)
      throw std::runtime_error(
          "bundle cannot restore investigation ownership lease");
  for (const auto &row : core.value("wb_investigation_actions", J::array()))
    if (row.at("runner") != "" || row.at("deadline") != 0)
      throw std::runtime_error(
          "bundle cannot restore active investigation runner");
  std::map<std::string, std::string> observations;
  for (const auto &row : core.value("wb_model_runs", J::array()))
    if (row.at("runner") != "" || row.at("deadline") != 0)
      throw std::runtime_error("bundle cannot restore active model runner");
  std::set<std::string> sessions;
  for (const auto &row : runtime.value("runtime_sessions", J::array())) {
    const auto record = J::parse(row.at("record").get<std::string>());
    if (record.at("id") != row.at("id") ||
        !std::set<std::string>{"exited", "detached", "terminated", "failed"}
             .contains(record.at("state").get<std::string>()))
      throw std::runtime_error("bundle contains live or inconsistent session");
    sessions.insert(row.at("id").get<std::string>());
  }
  for (auto it = runtime.begin(); it != runtime.end(); ++it)
    if (it.key() != "runtime_sessions")
      for (const auto &row : it.value()) {
        auto session = row.at("session").get<std::string>();
        if (!sessions.contains(session))
          throw std::runtime_error(
              "bundle runtime session relationship mismatch");
        if (it.key() == "runtime_observations") {
          auto text = row.at("record").get<std::string>();
          auto record = J::parse(text);
          if (record.at("id") != row.at("id") ||
              record.at("session_id") != session ||
              sha256_text(text) != row.at("sha").get<std::string>())
            throw std::runtime_error(
                "bundle runtime evidence integrity mismatch");
          observations[row.at("id").get<std::string>()] = session;
        }
      }
  for (const auto *table : {"runtime_code_epochs", "runtime_lifetimes"})
    for (const auto &row : runtime.value(table, J::array()))
      for (const auto *field :
           {"observation", "first_observation", "last_observation"})
        if (row.contains(field) && !row[field].is_null()) {
          auto id = row[field].get<std::string>();
          if (!observations.contains(id) ||
              observations.at(id) != row.at("session").get<std::string>())
            throw std::runtime_error(
                "bundle observation relationship mismatch");
        }
}
} // namespace
J bundles(const ProjectStore &store, const std::string &op, const J &r) {
  if (op == "import") {
    keys(r, {"source", "destination", "max_bytes"});
    auto source =
             fs::absolute(r.at("source").get<std::string>()).lexically_normal(),
         dest = fs::absolute(r.at("destination").get<std::string>())
                    .lexically_normal();
    if (fs::exists(dest))
      throw std::runtime_error("bundle import destination must not exist");
    safe_child(source, source / "manifest.json");
    safe_child(source, source / "manifest.sha256");
    auto text = read(source / "manifest.json", 64 * 1024 * 1024);
    auto expected = read(source / "manifest.sha256", 128);
    if (sha256_text(text) != expected)
      throw std::runtime_error("manifest integrity mismatch");
    auto manifest = J::parse(text);
    keys(manifest, {"schema", "project", "core", "runtime", "objects",
                    "created_at", "limits", "unavailable_external_objects"});
    if (manifest["schema"] != "indago.bundle.v1")
      throw std::runtime_error("unsupported bundle schema");
    auto p = manifest["project"].get<std::string>();
    identifier(p);
    if (!manifest["core"].is_object() || !manifest["runtime"].is_object() ||
        !manifest["objects"].is_array())
      throw std::runtime_error("invalid bundle collections");
    for (auto it = manifest["core"].begin(); it != manifest["core"].end(); ++it)
      if (std::find(core_tables.begin(), core_tables.end(), it.key()) ==
          core_tables.end())
        throw std::runtime_error("unknown core bundle table");
    for (auto it = manifest["runtime"].begin(); it != manifest["runtime"].end();
         ++it)
      if (std::find(runtime_tables.begin(), runtime_tables.end(), it.key()) ==
          runtime_tables.end())
        throw std::runtime_error("unknown runtime bundle table");
    validate_snapshot(manifest, p);
    auto max =
        bound(r, "max_bytes", 1024ULL * 1024 * 1024, 8ULL * 1024 * 1024 * 1024);
    std::uint64_t total = 0;
    std::set<std::string> seen;
    for (const auto &item : manifest["objects"]) {
      keys(item, {"sha256", "size"});
      auto sha = item.at("sha256").get<std::string>();
      hash(sha);
      if (!seen.insert(sha).second)
        throw std::runtime_error("duplicate bundle object");
      auto path = source / "objects" / sha;
      safe_child(source, path);
      auto size = fs::file_size(path);
      if (item["size"] != size || size > max - total)
        throw std::runtime_error("bundle byte budget or size mismatch");
      total += size;
      if (sha256_file(path) != sha)
        throw std::runtime_error("bundle hash mismatch");
    }
    // Import never merges into or overwrites an existing workspace.
    auto staging = dest.parent_path() /
                   (dest.filename().string() + ".import-" + make_id("stage"));
    [&] {
      ProjectStore imported(staging);
      imported.initialize();
      Db db(staging / "indago-native.sqlite3");
      initialize(db);
      Tx tx(db);
      db.exec("PRAGMA defer_foreign_keys=ON");
      std::size_t rows_count = 0;
      for (const auto &table : core_tables) {
        auto records = manifest["core"].value(table, J::array());
        if (!records.is_array() || (rows_count += records.size()) > 100000)
          throw std::runtime_error("bundle row budget exceeded");
        for (const auto &row : records)
          if (row.contains("project") && row["project"] != p)
            throw std::runtime_error("cross-project bundle row");
        if (table == "wb_investigations")
          for (auto &row : records) {
            auto record = J::parse(row.at("record").get<std::string>());
            if (record.at("owner").at("mode") == "builtin") {
              record["owner"] = {{"mode", "external"},
                                 {"name", "imported investigation; inference "
                                          "must be configured explicitly"},
                                 {"model_declaration",
                                  record["owner"]
                                      .value("profile", J::object())
                                      .value("model", std::string("unknown"))}};
              record["envelope"]["model_calls"] = false;
              record["import_policy"] =
                  "Inference ownership, credentials and cloud grants are not "
                  "portable authority.";
              row["record"] = record.dump();
            }
            if (record.at("envelope").value("workbench_mutations", false)) {
              record["envelope"]["workbench_mutations"] = false;
              record["envelope"]["profile"] = "static-read-only-v1";
              record["mutation_import_policy"] =
                  "Portable records do not grant new workbench mutations; "
                  "create an explicitly granted investigation.";
              row["record"] = record.dump();
            }
            if (record["envelope"].contains("derived_artifacts")) {
              record["envelope"]["derived_artifacts"] = {{"max_artifacts", 0},
                                                         {"max_bytes", 0}};
              row["record"] = record.dump();
            }
          }
        insert_rows(db, table, records);
      }
      Q check(db, "PRAGMA foreign_key_check");
      if (check.row())
        throw std::runtime_error("bundle foreign-key mismatch");
      if (!manifest["runtime"].empty()) {
        Db rd(staging / "runtime.sqlite3");
        rd.exec(
            "CREATE TABLE runtime_sessions(id TEXT PRIMARY KEY,project TEXT "
            "NOT NULL,record TEXT NOT NULL,cancel INTEGER NOT NULL DEFAULT "
            "0);CREATE TABLE runtime_requests(id TEXT PRIMARY KEY,session TEXT "
            "NOT NULL,state TEXT NOT NULL,request TEXT NOT NULL,response "
            "TEXT);CREATE TABLE runtime_observations(sequence INTEGER PRIMARY "
            "KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,session TEXT NOT "
            "NULL,kind TEXT NOT NULL,anchor TEXT NOT NULL,sha TEXT NOT "
            "NULL,record TEXT NOT NULL);CREATE TABLE runtime_code_epochs(id "
            "TEXT PRIMARY KEY,session TEXT NOT NULL,observation TEXT NOT "
            "NULL,address TEXT NOT NULL,bytes_sha TEXT NOT NULL,record TEXT "
            "NOT NULL);CREATE TABLE runtime_lifetimes(id TEXT PRIMARY "
            "KEY,session TEXT NOT NULL,kind TEXT NOT NULL,first_observation "
            "TEXT NOT NULL,last_observation TEXT,record TEXT NOT NULL);PRAGMA "
            "user_version=2;");
        Tx rt(rd);
        for (const auto &table : runtime_tables) {
          auto records = manifest["runtime"].value(table, J::array());
          if (!records.is_array() || (rows_count += records.size()) > 100000)
            throw std::runtime_error("runtime row budget exceeded");
          insert_rows(rd, table, records);
        }
        rt.commit();
      }
      for (const auto &sha : seen)
        copy_verified(source / "objects" / sha, object(imported, sha), sha);
      // Validate every required core object rather than trusting only the
      // manifest list.
      Q refs(db, "SELECT sha FROM targets UNION SELECT sha FROM evidence");
      while (refs.row()) {
        auto sha = refs.text(0);
        if (!fs::exists(object(imported, sha)))
          throw std::runtime_error("bundle missing referenced core object");
      }
      tx.commit();
      db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
      atomic_write(staging / "bundle-origin.json",
                   J{{"manifest_sha256", expected},
                     {"source_project", p},
                     {"note", "Evidence only; backend sessions/environment "
                              "images are not restored"}}
                       .dump());
    }();
    fs::rename(staging, dest);
    return {{"schema", "indago.bundle-import.v1"},
            {"status", "completed"},
            {"workspace", dest.string()},
            {"project", p}};
  }
  if (op == "retention") {
    keys(r, {"limit", "apply", "plan_digest"});
    StorageLease maintenance(store.root(), true);
    Db db(store.root() / "indago-native.sqlite3", false);
    initialize(db);
    Tx tx(db);
    std::set<std::string> refs;
    std::size_t scanned = 0;
    for (const auto &table : core_tables) {
      Q q(db, "SELECT * FROM " + table);
      while (q.row()) {
        if (++scanned > 1000000)
          throw std::runtime_error(
              "retention scan budget exceeded; no files moved");
        for (int i = 0; i < sqlite3_column_count(q.p); ++i)
          hashes(q.text(i), refs);
      }
    }
    std::unique_ptr<Db> runtime;
    std::unique_ptr<Tx> runtime_tx;
    if (fs::exists(store.root() / "runtime.sqlite3")) {
      runtime = std::make_unique<Db>(store.root() / "runtime.sqlite3", false);
      runtime_tx = std::make_unique<Tx>(*runtime);
      for (const auto &table : runtime_tables) {
        Q q(*runtime, "SELECT * FROM " + table);
        while (q.row()) {
          if (++scanned > 1000000)
            throw std::runtime_error("retention scan budget exceeded");
          for (int i = 0; i < sqlite3_column_count(q.p); ++i)
            hashes(q.text(i), refs);
        }
      }
    }
    Q active(db,
             "SELECT 1 FROM jobs WHERE status IN ('queued','running') LIMIT 1");
    if (active.row())
      throw std::runtime_error("retention requires no active/queued jobs");
    if (runtime) {
      Q activeRun(
          *runtime,
          "SELECT 1 FROM runtime_sessions WHERE json_extract(record,'$.state') "
          "IN ('starting','running','stopped') LIMIT 1");
      if (activeRun.row())
        throw std::runtime_error(
            "retention requires terminal runtime sessions");
    }
    auto limit = bound(r, "limit", 100, 10000);
    J candidates = J::array();
    bool more = false;
    for (const auto &entry : fs::recursive_directory_iterator(
             store.root() / "objects" / "sha256")) {
      if (!entry.is_regular_file())
        continue;
      safe_child(store.root(), entry.path());
      auto sha = entry.path().parent_path().filename().string() +
                 entry.path().filename().string();
      hash(sha);
      if (!refs.contains(sha)) {
        // A grace interval protects staged publications in other processes.
        if (fs::file_time_type::clock::now() - entry.last_write_time() <
            std::chrono::hours(24))
          continue;
        if (candidates.size() == limit) {
          more = true;
          break;
        }
        candidates.push_back({{"sha256", sha}, {"size", entry.file_size()}});
      }
    }
    std::sort(candidates.begin(), candidates.end(),
              [](const J &a, const J &b) { return a["sha256"] < b["sha256"]; });
    auto digest = sha256_text(candidates.dump());
    std::string quarantine;
    if (r.value("apply", false)) {
      if (more)
        throw std::runtime_error("increase retention limit before apply");
      if (r.value("plan_digest", std::string{}) != digest)
        throw std::runtime_error(
            "retention plan changed; inspect and resubmit digest");
      auto destination = store.root() / "quarantine" / make_id("retention");
      fs::create_directories(destination);
      for (const auto &c : candidates) {
        auto sha = c["sha256"].get<std::string>();
        fs::rename(object(store, sha), destination / sha);
      }
      atomic_write(destination / "manifest.json", candidates.dump());
      quarantine = destination.string();
    }
    tx.commit();
    if (runtime_tx)
      runtime_tx->commit();
    return {{"schema", "indago.retention.v1"},
            {"candidates", candidates},
            {"partial", more},
            {"plan_digest", digest},
            {"quarantine", quarantine},
            {"policy", "conservative all-record references; 24-hour grace; "
                       "recoverable quarantine, never permanent deletion"}};
  }
  if (op != "export")
    throw std::runtime_error("unknown bundle operation");
  keys(r, {"project", "destination", "max_bytes"});
  auto p = project(store, r);
  auto destination =
      fs::absolute(r.at("destination").get<std::string>()).lexically_normal();
  if (fs::exists(destination))
    throw std::runtime_error("export destination must not exist");
  Db db(store.root() / "indago-native.sqlite3");
  initialize(db);
  Tx tx(db);
  Q active(db, "SELECT 1 FROM jobs WHERE project=? AND status IN "
               "('queued','running') LIMIT 1");
  if (active.s(1, p).row())
    throw std::runtime_error(
        "settle queued/running jobs before portable export");
  Q owner(db, "SELECT 1 FROM wb_batches WHERE project=? AND owner<>'' AND "
              "deadline>? LIMIT 1");
  if (owner.s(1, p).n(2, now_ms()).row())
    throw std::runtime_error("batch is active");
  J core = J::object(), runtimeRows = J::object();
  std::size_t count = 0;
  for (const auto &table : core_tables)
    core[table] = rows(db, table, p, count);
  for (auto &row : core["wb_investigations"]) {
    if (row.at("deadline").get<std::int64_t>() > now_ms())
      throw std::runtime_error(
          "release investigation owner before portable export");
    row["token_hash"] = "";
    row["deadline"] = 0;
  }
  for (auto &row : core["wb_investigation_actions"]) {
    if (row.at("deadline").get<std::int64_t>() > now_ms())
      throw std::runtime_error(
          "settle investigation runner before portable export");
    row["runner"] = "";
    row["deadline"] = 0;
  }
  std::unique_ptr<Db> rd;
  for (auto &row : core["wb_model_runs"]) {
    if (row.at("deadline").get<std::int64_t>() > now_ms())
      throw std::runtime_error("settle model controller before export");
    row["runner"] = "";
    row["deadline"] = 0;
  }
  std::unique_ptr<Tx> rt;
  if (fs::exists(store.root() / "runtime.sqlite3")) {
    rd = std::make_unique<Db>(store.root() / "runtime.sqlite3");
    rt = std::make_unique<Tx>(*rd);
    Q runs(*rd, "SELECT 1 FROM runtime_sessions WHERE project=? AND "
                "json_extract(record,'$.state') IN "
                "('starting','running','stopped') LIMIT 1");
    if (runs.s(1, p).row())
      throw std::runtime_error("settle runtime sessions before export");
    for (const auto &table : runtime_tables)
      runtimeRows[table] = rows(*rd, table, p, count);
  }
  J manifest{{"schema", "indago.bundle.v1"},
             {"project", p},
             {"created_at", utc_timestamp()},
             {"core", core},
             {"runtime", runtimeRows},
             {"objects", J::array()},
             {"limits", "Evidence/index snapshot; no private engine cache, "
                        "saved Ghidra Program, live process or VM image. "
                        "Reanalyze original artifacts to reopen backends."}};
  std::set<std::string> refs;
  hashes(core, refs);
  hashes(runtimeRows, refs);
  auto max =
      bound(r, "max_bytes", 1024ULL * 1024 * 1024, 8ULL * 1024 * 1024 * 1024);
  std::uint64_t total = 0;
  for (const auto *table : {"targets", "evidence"})
    for (const auto &row : core[table])
      if (!fs::is_regular_file(object(store, row["sha"].get<std::string>())))
        throw std::runtime_error("required evidence/target object missing");
  std::map<std::string, fs::path> raw;
  raw_files(runtimeRows, raw);
  manifest["unavailable_external_objects"] = J::array();
  fs::create_directories(destination / "objects");
  for (const auto &sha : refs) {
    auto path = object(store, sha);
    if (!fs::is_regular_file(path)) {
      if (!raw.contains(sha))
        continue;
      path = raw[sha];
      try {
        safe_child(store.root(), path);
        if (!fs::is_regular_file(path))
          throw std::runtime_error("missing raw file");
      } catch (const std::exception &) {
        manifest["unavailable_external_objects"].push_back(
            {{"sha256", sha},
             {"reason", "raw file missing or outside workspace; no external "
                        "paths followed"}});
        continue;
      }
    }
    safe_child(store.root(), path);
    auto size = fs::file_size(path);
    if (size > max - total)
      throw std::runtime_error(
          "export byte budget exceeded; incomplete export retained");
    total += size;
    copy_verified(path, destination / "objects" / sha, sha);
    manifest["objects"].push_back({{"sha256", sha}, {"size", size}});
  }
  auto text = manifest.dump();
  if (text.size() > 64 * 1024 * 1024)
    throw std::runtime_error("manifest exceeds 64 MiB");
  atomic_write(destination / "manifest.json", text);
  atomic_write(destination / "manifest.sha256", sha256_text(text));
  tx.commit();
  if (rt)
    rt->commit();
  return {{"schema", "indago.bundle-export.v1"},
          {"status", "completed"},
          {"destination", destination.string()},
          {"objects", manifest["objects"].size()},
          {"bytes", total},
          {"manifest_sha256", sha256_text(text)}};
}
} // namespace indago::wb
