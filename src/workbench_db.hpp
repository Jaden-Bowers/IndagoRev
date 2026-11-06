#pragma once
#include "indago/storage_lease.hpp"
#include "indago/workbench.hpp"
#include <chrono>
#include <fstream>
#include <set>
#include <sqlite3.h>

namespace indago::wb {
using J = nlohmann::json;
// Returns the current wall-clock time in milliseconds.
inline std::int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}
// RAII SQLite connection with an optional shared storage lease.
struct Db {
  std::unique_ptr<StorageLease> storage;
  sqlite3 *p{};
// Opens the database (taking a lease by default) and enables foreign keys.
  explicit Db(const fs::path &path, bool lease = true) {
    if (lease)
      storage = std::make_unique<StorageLease>(path.parent_path());
    auto u = path.u8string();
    if (sqlite3_open(reinterpret_cast<const char *>(u.c_str()), &p) !=
        SQLITE_OK) {
      std::string error = p ? sqlite3_errmsg(p) : "database open failed";
      if (p)
        sqlite3_close(p);
      throw std::runtime_error(error);
    }
    sqlite3_busy_timeout(p, 10000);
    exec("PRAGMA foreign_keys=ON");
  }
// Closes the connection.
  ~Db() { sqlite3_close(p); }
  Db(const Db &) = delete;
// Executes SQL, throwing on error.
  void exec(const char *sql) {
    char *e{};
    if (sqlite3_exec(p, sql, nullptr, nullptr, &e) != SQLITE_OK) {
      std::string s = e ? e : "SQL failed";
      sqlite3_free(e);
      throw std::runtime_error(s);
    }
  }
};
// RAII prepared statement with text/integer binding and row stepping.
struct Q {
  sqlite3_stmt *p{};
// Prepares sql, throwing on error.
  Q(Db &db, const std::string &sql) {
    if (sqlite3_prepare_v2(db.p, sql.c_str(), -1, &p, nullptr) != SQLITE_OK)
      throw std::runtime_error(sqlite3_errmsg(db.p));
  }
// Finalizes the statement.
  ~Q() { sqlite3_finalize(p); }
// Binds a text value at the given 1-based index.
  Q &s(int i, std::string_view v) {
    if (sqlite3_bind_text(p, i, v.data(), static_cast<int>(v.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK)
      throw std::runtime_error("SQL bind failed");
    return *this;
  }
// Binds an integer value at the given 1-based index.
  Q &n(int i, std::int64_t v) {
    if (sqlite3_bind_int64(p, i, v) != SQLITE_OK)
      throw std::runtime_error("SQL integer bind failed");
    return *this;
  }
// Steps to the next row; returns false once the statement is done.
  bool row() {
    auto r = sqlite3_step(p);
    if (r == SQLITE_ROW)
      return true;
    if (r == SQLITE_DONE)
      return false;
    throw std::runtime_error(sqlite3_errmsg(sqlite3_db_handle(p)));
  }
// Returns a column as text, or an empty string for NULL.
  std::string text(int i) const {
    auto t = sqlite3_column_text(p, i);
    return t ? reinterpret_cast<const char *>(t) : "";
  }
// Returns a column as a 64-bit integer.
  std::int64_t num(int i) const { return sqlite3_column_int64(p, i); }
};
// RAII BEGIN IMMEDIATE transaction that rolls back unless committed.
struct Tx {
  Db &db;
  bool done = false;
// Starts an immediate write transaction.
  explicit Tx(Db &d) : db(d) { db.exec("BEGIN IMMEDIATE"); }
// Rolls back if the transaction was not explicitly committed.
  ~Tx() {
    if (!done)
      sqlite3_exec(db.p, "ROLLBACK", nullptr, nullptr, nullptr);
  }
// Commits the transaction.
  void commit() {
    db.exec("COMMIT");
    done = true;
  }
};
// Validates a project or record identifier.
inline void identifier(std::string_view s) {
  if (s.empty() || s.size() > 128 ||
      s.find_first_not_of(
          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") !=
          s.npos)
    throw std::runtime_error("invalid identifier");
}
// Validates a lowercase hex SHA-256.
inline void hash(std::string_view s) {
  if (s.size() != 64 || s.find_first_not_of("0123456789abcdef") != s.npos)
    throw std::runtime_error("invalid SHA-256");
}
// Maps a hash to its path in the content-addressed object store.
inline fs::path object(const ProjectStore &store, const std::string &sha) {
  hash(sha);
  return store.root() / "objects" / "sha256" / sha.substr(0, 2) / sha.substr(2);
}
// Reads a bounded file, failing if it changed or exceeds max bytes.
inline std::string read(const fs::path &p,
                        std::uint64_t max = 4 * 1024 * 1024) {
  const auto size = fs::file_size(p);
  if (size > max)
    throw std::runtime_error("input exceeds byte budget");
  std::ifstream f(p, std::ios::binary);
  if (!f)
    throw std::runtime_error("input unavailable");
  std::string result(static_cast<std::size_t>(size), '\0');
  f.read(result.data(), static_cast<std::streamsize>(result.size()));
  if (f.gcount() != static_cast<std::streamsize>(size) || f.bad() ||
      f.peek() != std::char_traits<char>::eof())
    throw std::runtime_error("input changed while reading bounded file");
  return result;
}
// Reads an optional non-negative size bound, capped at max.
inline std::size_t bound(const J &j, const char *key, std::size_t fallback,
                         std::size_t max) {
  if (!j.contains(key))
    return fallback;
  if (!j[key].is_number_integer() || j[key].get<std::int64_t>() < 0 ||
      j[key].get<std::uint64_t>() > max)
    throw std::runtime_error(std::string("invalid bound: ") + key);
  return j[key].get<std::size_t>();
}
// Rejects request fields not present in the allowed set.
inline void keys(const J &j, std::initializer_list<const char *> allowed) {
  if (!j.is_object())
    throw std::runtime_error("expected an object");
  std::set<std::string> a;
  for (auto s : allowed)
    a.insert(s);
  for (auto it = j.begin(); it != j.end(); ++it)
    if (!a.contains(it.key()))
      throw std::runtime_error("unknown field: " + it.key());
}
// Validates and resolves the request's project name.
inline std::string project(const ProjectStore &store, const J &r) {
  auto p = r.at("project").get<std::string>();
  identifier(p);
  store.project_info(p);
  return p;
}
// Creates the workbench tables and indexes if absent.
inline void initialize(Db &db) {
  db.exec(R"sql(
CREATE TABLE IF NOT EXISTS wb_records(project TEXT NOT NULL REFERENCES projects(name),id TEXT NOT NULL,revision INTEGER NOT NULL,kind TEXT NOT NULL,record TEXT NOT NULL,sha TEXT NOT NULL,PRIMARY KEY(project,id,revision));
CREATE TABLE IF NOT EXISTS wb_heads(project TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,PRIMARY KEY(project,id),FOREIGN KEY(project,id,revision) REFERENCES wb_records(project,id,revision));
CREATE TABLE IF NOT EXISTS wb_dependencies(project TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,type TEXT NOT NULL,dependency TEXT NOT NULL,pin TEXT NOT NULL,FOREIGN KEY(project,id,revision) REFERENCES wb_records(project,id,revision));
CREATE INDEX IF NOT EXISTS wb_dep_reverse ON wb_dependencies(project,type,dependency);
CREATE TABLE IF NOT EXISTS wb_batches(project TEXT NOT NULL REFERENCES projects(name),id TEXT NOT NULL,record TEXT NOT NULL,owner TEXT NOT NULL DEFAULT '',deadline INTEGER NOT NULL DEFAULT 0,cancel INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(project,id));
CREATE TABLE IF NOT EXISTS wb_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,project TEXT NOT NULL,id TEXT NOT NULL,kind TEXT NOT NULL,at TEXT NOT NULL,record TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS wb_investigations(project TEXT NOT NULL REFERENCES projects(name),id TEXT NOT NULL,record TEXT NOT NULL,token_hash TEXT NOT NULL DEFAULT '',deadline INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(project,id));
CREATE TABLE IF NOT EXISTS wb_investigation_actions(project TEXT NOT NULL,investigation TEXT NOT NULL,id TEXT NOT NULL,action_key TEXT NOT NULL,request_hash TEXT NOT NULL,record TEXT NOT NULL,runner TEXT NOT NULL DEFAULT '',deadline INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(project,id),UNIQUE(project,investigation,action_key),FOREIGN KEY(project,investigation) REFERENCES wb_investigations(project,id));
CREATE TABLE IF NOT EXISTS wb_model_runs(project TEXT NOT NULL,id TEXT NOT NULL,record TEXT NOT NULL,runner TEXT NOT NULL DEFAULT '',deadline INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(project,id),FOREIGN KEY(project,id) REFERENCES wb_investigations(project,id));
)sql");
}
// Appends a workbench audit event.
inline void event(Db &db, const std::string &p, const std::string &id,
                  const std::string &kind, const J &r) {
  Q q(db, "INSERT INTO wb_events(project,id,kind,at,record) VALUES(?,?,?,?,?)");
  q.s(1, p).s(2, id).s(3, kind).s(4, utc_timestamp()).s(5, r.dump()).row();
}
// Serves knowledge put/show/list/refresh/impact operations.
J knowledge(const ProjectStore &, const std::string &, const J &);
// Applies a declared transform and returns the candidate result.
J candidate_transform(const std::string &input,const std::string &representation,const J &spec);
// Validates and records a knowledge revision (optionally internal).
J knowledge_put(const ProjectStore &, const J &, bool internal = false);
// Serves graph search/neighborhood/packet/event operations.
J graph(const ProjectStore &, const std::string &, const J &);
// Builds a coverage report.
J coverage(const ProjectStore &, const J &);
// Serves system-manifest create/show/list/preflight operations.
J system_manifest(const ProjectStore &, const std::string &, const J &);
// Serves recognize/transform/validate artifact operations.
J artifacts(const ProjectStore &, const std::string &, const std::string &,
            const J &);
// Serves batch create/show/run/cancel/events operations.
J batch(StaticService &, const std::string &, const J &);
// Serves bundle export/import and retention planning.
J bundles(const ProjectStore &, const std::string &, const J &);
} // namespace indago::wb
