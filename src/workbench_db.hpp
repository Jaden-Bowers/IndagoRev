#pragma once
#include "indago/storage_lease.hpp"
#include "indago/workbench.hpp"
#include <chrono>
#include <fstream>
#include <set>
#include <sqlite3.h>

namespace indago::wb {
using J = nlohmann::json;
inline std::int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}
struct Db {
  std::unique_ptr<StorageLease> storage;
  sqlite3 *p{};
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
  ~Db() { sqlite3_close(p); }
  Db(const Db &) = delete;
  void exec(const char *sql) {
    char *e{};
    if (sqlite3_exec(p, sql, nullptr, nullptr, &e) != SQLITE_OK) {
      std::string s = e ? e : "SQL failed";
      sqlite3_free(e);
      throw std::runtime_error(s);
    }
  }
};
struct Q {
  sqlite3_stmt *p{};
  Q(Db &db, const std::string &sql) {
    if (sqlite3_prepare_v2(db.p, sql.c_str(), -1, &p, nullptr) != SQLITE_OK)
      throw std::runtime_error(sqlite3_errmsg(db.p));
  }
  ~Q() { sqlite3_finalize(p); }
  Q &s(int i, std::string_view v) {
    if (sqlite3_bind_text(p, i, v.data(), static_cast<int>(v.size()),
                          SQLITE_TRANSIENT) != SQLITE_OK)
      throw std::runtime_error("SQL bind failed");
    return *this;
  }
  Q &n(int i, std::int64_t v) {
    if (sqlite3_bind_int64(p, i, v) != SQLITE_OK)
      throw std::runtime_error("SQL integer bind failed");
    return *this;
  }
  bool row() {
    auto r = sqlite3_step(p);
    if (r == SQLITE_ROW)
      return true;
    if (r == SQLITE_DONE)
      return false;
    throw std::runtime_error(sqlite3_errmsg(sqlite3_db_handle(p)));
  }
  std::string text(int i) const {
    auto t = sqlite3_column_text(p, i);
    return t ? reinterpret_cast<const char *>(t) : "";
  }
  std::int64_t num(int i) const { return sqlite3_column_int64(p, i); }
};
struct Tx {
  Db &db;
  bool done = false;
  explicit Tx(Db &d) : db(d) { db.exec("BEGIN IMMEDIATE"); }
  ~Tx() {
    if (!done)
      sqlite3_exec(db.p, "ROLLBACK", nullptr, nullptr, nullptr);
  }
  void commit() {
    db.exec("COMMIT");
    done = true;
  }
};
inline void identifier(std::string_view s) {
  if (s.empty() || s.size() > 128 ||
      s.find_first_not_of(
          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") !=
          s.npos)
    throw std::runtime_error("invalid identifier");
}
inline void hash(std::string_view s) {
  if (s.size() != 64 || s.find_first_not_of("0123456789abcdef") != s.npos)
    throw std::runtime_error("invalid SHA-256");
}
inline fs::path object(const ProjectStore &store, const std::string &sha) {
  hash(sha);
  return store.root() / "objects" / "sha256" / sha.substr(0, 2) / sha.substr(2);
}
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
inline std::size_t bound(const J &j, const char *key, std::size_t fallback,
                         std::size_t max) {
  if (!j.contains(key))
    return fallback;
  if (!j[key].is_number_integer() || j[key].get<std::int64_t>() < 0 ||
      j[key].get<std::uint64_t>() > max)
    throw std::runtime_error(std::string("invalid bound: ") + key);
  return j[key].get<std::size_t>();
}
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
inline std::string project(const ProjectStore &store, const J &r) {
  auto p = r.at("project").get<std::string>();
  identifier(p);
  store.project_info(p);
  return p;
}
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
inline void event(Db &db, const std::string &p, const std::string &id,
                  const std::string &kind, const J &r) {
  Q q(db, "INSERT INTO wb_events(project,id,kind,at,record) VALUES(?,?,?,?,?)");
  q.s(1, p).s(2, id).s(3, kind).s(4, utc_timestamp()).s(5, r.dump()).row();
}
J knowledge(const ProjectStore &, const std::string &, const J &);
J candidate_transform(const std::string &input,const std::string &representation,const J &spec);
J knowledge_put(const ProjectStore &, const J &, bool internal = false);
J graph(const ProjectStore &, const std::string &, const J &);
J coverage(const ProjectStore &, const J &);
J system_manifest(const ProjectStore &, const std::string &, const J &);
J artifacts(const ProjectStore &, const std::string &, const std::string &,
            const J &);
J batch(StaticService &, const std::string &, const J &);
J bundles(const ProjectStore &, const std::string &, const J &);
} // namespace indago::wb
