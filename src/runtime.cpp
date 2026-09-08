#include "indago/runtime.hpp"
#include "indago/contracts.hpp"
#include "indago/service.hpp"
#include "indago/airece.hpp"
#include "indago/storage_lease.hpp"
#include "indago/replay.hpp"
#include "runtime_call_identity.hpp"
#include <chrono>
#include <fstream>
#include <future>
#include <set>
#include <sqlite3.h>
#include <thread>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#endif

namespace indago {
namespace {
using J = RuntimeJson;
std::int64_t now() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}
struct Db {
  StorageLease storage;
  sqlite3 *db{};
  explicit Db(const ProjectStore &store):storage(store.root()) {
    auto p = (store.root() / "runtime.sqlite3").u8string();
    if (sqlite3_open(reinterpret_cast<const char *>(p.c_str()), &db) !=
        SQLITE_OK)
      throw std::runtime_error("cannot open runtime database");
    sqlite3_busy_timeout(db, 5000);
    const auto version=std::stoi(run("PRAGMA user_version")[0]["user_version"].get<std::string>());
    if (version > 2)
      throw std::runtime_error(
          "runtime database version is newer than this executable");
    if(version==2)return;
    run("PRAGMA journal_mode=WAL");
    run("PRAGMA synchronous=FULL");
    run("CREATE TABLE IF NOT EXISTS runtime_sessions(id TEXT PRIMARY "
        "KEY,project TEXT NOT NULL,record TEXT NOT NULL,cancel INTEGER NOT "
        "NULL DEFAULT 0)");
    run("CREATE TABLE IF NOT EXISTS runtime_requests(id TEXT PRIMARY "
        "KEY,session TEXT NOT NULL,state TEXT NOT NULL,request TEXT NOT "
        "NULL,response TEXT)");
    run("CREATE INDEX IF NOT EXISTS runtime_queue ON "
        "runtime_requests(session,state)");
    run("CREATE TABLE IF NOT EXISTS runtime_observations(sequence INTEGER "
        "PRIMARY KEY AUTOINCREMENT,id TEXT UNIQUE NOT NULL,session TEXT NOT "
        "NULL,kind TEXT NOT NULL,anchor TEXT NOT NULL,sha TEXT NOT NULL,record "
        "TEXT NOT NULL)");
    run("CREATE INDEX IF NOT EXISTS runtime_evidence_session ON "
        "runtime_observations(session,sequence)");
    run("CREATE INDEX IF NOT EXISTS runtime_evidence_anchor ON "
        "runtime_observations(anchor,sequence)");
    run("CREATE TABLE IF NOT EXISTS runtime_code_epochs(id TEXT PRIMARY "
        "KEY,session TEXT NOT NULL,observation TEXT NOT NULL,address TEXT NOT "
        "NULL,bytes_sha TEXT NOT NULL,record TEXT NOT NULL)");
    run("CREATE INDEX IF NOT EXISTS runtime_epoch_address ON "
        "runtime_code_epochs(session,address)");
    run("CREATE TABLE IF NOT EXISTS runtime_lifetimes(id TEXT PRIMARY "
        "KEY,session TEXT NOT NULL,kind TEXT NOT NULL,first_observation TEXT "
        "NOT NULL,last_observation TEXT,record TEXT NOT NULL)");
    run("CREATE INDEX IF NOT EXISTS runtime_lifetime_session ON "
        "runtime_lifetimes(session,kind)");
    run("PRAGMA user_version=2");
  }
  ~Db() {
    if (db)
      sqlite3_close(db);
  }
  J run(const std::string &sql, const std::vector<std::string> &args = {}) {
    sqlite3_stmt *st{};
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK)
      throw std::runtime_error(sqlite3_errmsg(db));
    struct Guard {
      sqlite3_stmt *p;
      ~Guard() { sqlite3_finalize(p); }
    } guard{st};
    for (std::size_t i = 0; i < args.size(); ++i)
      sqlite3_bind_text(st, static_cast<int>(i + 1), args[i].c_str(), -1,
                        SQLITE_TRANSIENT);
    J rows = J::array();
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) {
      J row = J::object();
      for (int i = 0; i < sqlite3_column_count(st); ++i) {
        const auto *value = sqlite3_column_text(st, i);
        row[sqlite3_column_name(st, i)] =
            value ? J(reinterpret_cast<const char *>(value)) : J(nullptr);
      }
      rows.push_back(row);
    }
    if (rc != SQLITE_DONE)
      throw std::runtime_error(sqlite3_errmsg(db));
    return rows;
  }
  J session(const std::string &id, const std::string &project) {
    auto rows =
        run("SELECT record FROM runtime_sessions WHERE id=? AND project=?",
            {id, project});
    if (rows.empty())
      throw std::runtime_error("runtime session not found in project");
    return J::parse(rows[0]["record"].get<std::string>());
  }
  void save(const J &s) {
    run("UPDATE runtime_sessions SET record=? WHERE id=?",
        {s.dump(), s.at("id")});
  }
  J observe(const std::string &session, const std::string &kind, J data,
            const std::string &state = "observed") {
    J record{{"schema", "indago.runtime-observation.v1"},
             {"id", make_id("obs")},
             {"session_id", session},
             {"kind", kind},
             {"state", state},
             {"created_at", utc_timestamp()},
             {"scope", "this execution only"},
             {"data", data}};
    record["clock_domain"] = "collector UTC; not target execution order";
    record["collected_unix_ms"] = now();
    auto sha = sha256_text(record.dump());
    auto anchor = data.contains("location") && data["location"].is_object()
                      ? data["location"].value("anchor_id", "")
                      : "";
    run("BEGIN IMMEDIATE");
    try {
      run("INSERT INTO runtime_observations(id,session,kind,anchor,sha,record) "
          "VALUES(?,?,?,?,?,?)",
          {record["id"], session, kind, anchor, sha, record.dump()});
      record["sequence"] = sqlite3_last_insert_rowid(db);
      if (data.contains("code_epoch") && data["code_epoch"].is_object()) {
        auto e = data["code_epoch"];
        run("INSERT INTO runtime_code_epochs VALUES(?,?,?,?,?,?)",
            {e.at("id"), session, record["id"], e.at("address"),
             e.at("bytes_sha256"), e.dump()});
      }
      J entity;
      std::string type;
      bool closed = false;
      if (kind == "module_loaded" || kind == "module_unloaded") {
        entity = data.value("module", data);
        type = "module";
        closed = kind == "module_unloaded";
      } else if (kind == "thread_first_observed" || kind == "thread_created" ||
                 kind == "thread_exited") {
        entity = data.value("thread", data);
        type = "thread";
        closed = kind == "thread_exited";
      } else if (kind == "session_started" || kind == "process_created" || kind == "process_identity_retired") {
        entity = data;
        entity["id"] = data.at("process_id");
        type = "process";
        closed=kind=="process_identity_retired";
      } else if (data.contains("socket") && data.at("socket").is_object()) {
        entity=data.at("socket");
        type="socket";
        closed=data.value("socket_event",std::string{})=="close_api_success" &&
               !data.value("socket_generation_race",false);
      }
      if (entity.is_object() && entity.contains("id")) {
        run("INSERT OR IGNORE INTO runtime_lifetimes VALUES(?,?,?,?,NULL,?)",
            {entity.at("id"), session, type, record["id"], entity.dump()});
        if (closed)
          run("UPDATE runtime_lifetimes SET last_observation=? WHERE id=? AND "
              "session=?",
              {record["id"], entity.at("id"), session});
      }
      if ((kind=="api_enter" || kind=="api_leave") &&
          data.value("backend",std::string{})=="frida" && data.contains("call_id")) {
        const auto call_id=data.at("call_id").get<std::string>();
        auto prior=run("SELECT record FROM runtime_lifetimes WHERE session=? AND id=? AND kind='api_call'",{session,call_id});
        auto call=advance_api_call_identity(prior.empty()?J(nullptr):J::parse(prior.at(0).at("record").get<std::string>()),data,kind,record.at("id"));
        run("INSERT INTO runtime_lifetimes(id,session,kind,first_observation,last_observation,record) VALUES(?,?,'api_call',?,NULLIF(?,''),?) "
            "ON CONFLICT(id) DO UPDATE SET last_observation=COALESCE(excluded.last_observation,runtime_lifetimes.last_observation),record=excluded.record "
            "WHERE runtime_lifetimes.session=excluded.session AND runtime_lifetimes.kind='api_call'",
            {call_id,session,record.at("id"),kind=="api_leave"?record.at("id").get<std::string>():std::string{},call.dump()});
        if (sqlite3_changes(db)!=1) throw std::runtime_error("API identity collides with another lifetime");
      }
      if (kind == "collection_closed")
        run("UPDATE runtime_lifetimes SET last_observation=? WHERE session=? "
            "AND last_observation IS NULL",
            {record["id"], session});
      run("COMMIT");
    } catch (...) {
      run("ROLLBACK");
      throw;
    }
    record["sha256"] = sha;
    return record;
  }
  J network_observations(const std::string &session, const J &r) {
    const auto limit=std::clamp<std::uint64_t>(runtime_number(r.value("limit",J(32))),1,128);
    const auto offset=runtime_number(r.value("offset",J(0)));
    const auto socket_filter=r.value("id",std::string{});
    const bool cursor_mode=r.contains("from") || r.contains("to");
    std::uint64_t cursor=0, snapshot=0, scanned=0, omitted=0;
    J omissions=J::array(), rows;
    if (cursor_mode) {
      if (offset) throw std::runtime_error("network sequence cursor cannot be combined with offset");
      cursor=runtime_number(r.value("from",J(0)));
      auto last=run("SELECT COALESCE(MAX(sequence),0) AS last FROM runtime_observations WHERE session=?",{session});
      snapshot=std::stoull(last.at(0).at("last").get<std::string>());
      if (r.contains("to")) snapshot=std::min(snapshot,runtime_number(r.at("to")));
      if (cursor>9223372036854775807ULL || (r.contains("to") && runtime_number(r.at("to"))<cursor))
        throw std::runtime_error("invalid network sequence window");
      // Seek through the existing (session,sequence) index before inspecting
      // native JSON. A sparse match cannot cause an unbounded full-session scan.
      rows=run("SELECT sequence,id,kind,sha,CASE WHEN length(CAST(record AS BLOB))<=65536 THEN record ELSE NULL END AS record "
          "FROM runtime_observations WHERE session=? AND sequence>? AND sequence<=? ORDER BY sequence LIMIT 256",
          {session,std::to_string(cursor),std::to_string(snapshot)});
    } else {
      if (offset>10000) throw std::runtime_error("network offset exceeds 10000; use from/to sequence paging");
      rows=run("SELECT sequence,sha,record FROM runtime_observations WHERE session=? "
        "AND kind IN ('api_enter','api_leave') AND json_extract(record,'$.data.backend')='frida' "
        "AND (json_type(record,'$.data.socket')='object' OR "
        "json_extract(record,'$.data.native.payload.api') IN ('socket','accept','accept4','bind','listen','connect','send','recv','sendto','recvfrom','shutdown','closesocket','WSASend','WSARecv')) "
        "AND (?='' OR json_extract(record,'$.data.socket.id')=?) ORDER BY sequence LIMIT ? OFFSET ?",
        {session,socket_filter,socket_filter,std::to_string(limit+1),std::to_string(offset)});
    }
    J events=J::array(); std::size_t used_bytes=0;
    for (const auto &row : rows) {
      if (events.size()>=limit) break;
      const auto sequence=std::stoull(row.at("sequence").get<std::string>());
      auto consume=[&] {cursor=sequence;++scanned;};
      if (cursor_mode && row.at("record").is_null()) {
        ++omitted;
        if (omissions.size()<8) omissions.push_back({{"observation_id",row.at("id")},{"observation_sha256",row.at("sha")},
            {"sequence",sequence},{"reason","source exceeds 64 KiB cursor read allowance; network relevance not inspected"}});
        consume();continue;
      }
      const auto raw=row.at("record").get<std::string>();
      if (sha256_text(raw)!=row.at("sha").get<std::string>())
        throw std::runtime_error("network source observation integrity mismatch");
      const auto observation=J::parse(raw);
      if (cursor_mode) {
        const auto &candidate=observation.at("data");
        const auto payload=candidate.value("native",J::object()).value("payload",J::object());
        const auto api=payload.value("api",std::string{});
        const bool selected=std::set<std::string>{"socket","accept","accept4","bind","listen","connect","send","recv","sendto","recvfrom","shutdown","closesocket","WSASend","WSARecv"}.contains(api);
        if ((observation.at("kind")!="api_enter" && observation.at("kind")!="api_leave") ||
            candidate.value("backend",std::string{})!="frida" ||
            (!candidate.value("socket",J{}).is_object() && !selected) ||
            (!socket_filter.empty() && candidate.value("socket",J::object()).value("id",std::string{})!=socket_filter)) {
          consume();continue;
        }
      }
      const auto &data=observation.at("data"), &native=data.at("native").at("payload");
      J event{{"observation_id",observation.at("id")},{"observation_sha256",row.at("sha")},
          {"sequence",std::stoull(row.at("sequence").get<std::string>())},
          {"phase",observation.at("kind")},{"api",native.at("api")},
          {"call_id",data.value("call_id",J(nullptr))},{"socket",data.value("socket",J(nullptr))},
          {"process_id",data.value("process_id",J(nullptr))},{"location",data.value("location",J(nullptr))},
          {"network",data.value("network",J(nullptr))}};
      event["native_fields"]=J::object();
      for (const char *key : {"args","return_value","timestamp_ms","clock_domain","thread_id","errno","last_error", "error_semantics",
          "socket_event","socket_generation_race","socket_argument_invalid","listener_socket","requested_bytes","transferred_bytes",
          "buffer_hex","buffer_truncated","sockaddr_hex","sockaddr_truncated","sockaddr_capacity","sockaddr_returned_length","sockaddr_read_status","argument_read_status","return_read_status","network_outcome","network_completeness"})
        if (native.contains(key)) event["native_fields"][key]=native.at(key);
      auto bytes=event.dump().size();
      if (bytes>60000) {
        event={{"observation_id",observation.at("id")},{"observation_sha256",row.at("sha")},
               {"fields_omitted",true},{"diagnostic","Retrieve the bounded original observation; network view item exceeds output allowance"}};
        bytes=event.dump().size();
      }
      if (used_bytes+bytes>60000) break;
      used_bytes+=bytes; events.push_back(event);consume();
    }
    J result{{"schema","indago.network-api-evidence.v1"},{"session_id",session},{"events",events},
        {"next_offset",events.size()<rows.size()?J(offset+events.size()):J(nullptr)},
        {"coverage_complete",false},{"packet_capture",false},{"remote_delivery_proven",false},
        {"scope","Selected Frida API observations; native source records retained; no cross-process flow join or packet/protocol reconstruction"}};
    if (cursor_mode) {
      result["next_offset"]=nullptr;
      result["snapshot_to"]=snapshot;
      result["next_from"]=cursor<snapshot?J(cursor):J(nullptr);
      result["scanned_observations"]=scanned;
      result["scan_limit"]=256;
      result["scan_omissions"]=omissions;
      result["omitted_observations"]=omitted;
      result["page_complete"]=omitted==0;
      // Empty snapshots or gaps at a session's tail must not produce a cursor
      // which loops forever without examining any additional observation.
      if (rows.empty()) result["next_from"]=nullptr;
    }
    return result;
  }
  J observations(const std::string &session, const J &r) {
    auto limit = std::clamp<std::uint64_t>(
        runtime_number(r.value("limit", J(100))), 1, 1000);
    auto offset = runtime_number(r.value("offset", J(0)));
    std::string sql =
        "SELECT sequence,sha,record FROM runtime_observations WHERE session=?";
    std::vector<std::string> args{session};
    for (auto key : {"id", "anchor", "kind"})
      if (r.contains(key) && !r[key].get<std::string>().empty()) {
        sql += " AND " + std::string(key) + "=?";
        args.push_back(r[key]);
      }
    sql += " ORDER BY sequence LIMIT ? OFFSET ?";
    args.push_back(std::to_string(limit + 1));
    args.push_back(std::to_string(offset));
    auto rows = run(sql, args);
    J out = J::array();
    std::size_t bytes = 0;
    for (auto &row : rows) {
      auto raw = row["record"].get<std::string>();
      if (sha256_text(raw) != row["sha"].get<std::string>())
        throw std::runtime_error("runtime evidence hash mismatch");
      if (out.size() >= limit || bytes + raw.size() > 2 * 1024 * 1024)
        break;
      bytes += raw.size();
      auto record = J::parse(raw);
      record["sha256"] = row["sha"];
      record["sequence"] = std::stoull(row["sequence"].get<std::string>());
      out.push_back(record);
    }
    return {{"observations", out},
            {"next_offset",
             out.size() < rows.size() ? J(offset + out.size()) : J(nullptr)}};
  }
};
fs::path self_executable(const fs::path &fallback) {
#ifdef _WIN32
  std::wstring p(32768, L'\0');
  auto n = GetModuleFileNameW(nullptr, p.data(), static_cast<DWORD>(p.size()));
  if (n && n < p.size()) {
    p.resize(n);
    return p;
  }
#else
  std::error_code ec;
  auto p = fs::read_symlink("/proc/self/exe", ec);
  if (!ec)
    return p;
#endif
  return fs::absolute(fallback);
}
void spawn_runtime(const fs::path &executable, const ProjectStore &store,
                   const std::string &id) {
#ifdef _WIN32
  auto quote = [](const std::wstring &s) {
    std::wstring r = L"\"";
    unsigned slashes = 0;
    for (auto c : s) {
      if (c == L'\\') {
        ++slashes;
        continue;
      }
      r.append(c == L'"' ? slashes * 2 + 1 : slashes, L'\\');
      r += c;
      slashes = 0;
    }
    r.append(slashes * 2, L'\\');
    return r + L'"';
  };
  auto cmd = quote(executable.wstring()) + L" --workspace " +
             quote(fs::absolute(store.root()).wstring()) +
             L" __runtime --session " + quote(fs::path(id).wstring());
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  if (!CreateProcessW(executable.c_str(), cmd.data(), nullptr, nullptr, FALSE,
                      CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
    throw std::runtime_error("cannot start runtime worker");
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
#else
  auto child = fork();
  if (child < 0)
    throw std::runtime_error("cannot fork runtime worker");
  if (child == 0) {
    setsid();
    int sink = open("/dev/null", O_RDWR);
    dup2(sink, 0);
    dup2(sink, 1);
    dup2(sink, 2);
    if (sink > 2)
      close(sink);
    auto root = fs::absolute(store.root()).string();
    execl(executable.c_str(), executable.c_str(), "--workspace", root.c_str(),
          "__runtime", "--session", id.c_str(), nullptr);
    _exit(127);
  }
#endif
}
bool live_worker(const J &s) {
  auto pid = s.value("worker_pid", std::uint64_t{});
  if (!pid)
    return s.value("state", "") == "starting" &&
           now() - s.value("heartbeat_ms", std::int64_t{}) < 15000;
#ifdef _WIN32
  HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                         static_cast<DWORD>(pid));
  if (!h)
    return false;
  DWORD code{};
  bool live = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
  CloseHandle(h);
  return live;
#else
  return kill(static_cast<pid_t>(pid), 0) == 0 || errno == EPERM;
#endif
}
std::uint64_t bounded(const J &r, const char *key, std::uint64_t fallback,
                      std::uint64_t max) {
  auto n = runtime_number(r.value(key, J(fallback)));
  if (n == 0 || n > max)
    throw std::runtime_error(std::string(key) + " outside allowed budget");
  return n;
}
J location(const J &session, std::uint64_t address) {
  J l{{"session_id", session["id"]},
      {"process_id", session["process_id"]},
      {"address_space_id",
       session.value("address_space_id", session["process_id"])},
      {"runtime_address", hex_address(address)},
      {"mapping_status", "unmapped"}};
  for (const auto &m : session.value("modules", J::array())) {
    auto base = runtime_number(m["base"]),
         size = m.value("size", std::uint64_t{});
    if (address < base || address - base >= size)
      continue;
    l["module_id"] = m["id"];
    if (!m.contains("artifact_sha256") || !m.contains("image"))
      continue;
    auto preferred = runtime_number(m["image"]["image_base"]);
    if (preferred > UINT64_MAX - (address - base))
      continue;
    auto va = hex_address(preferred + (address - base));
    l["module_id"] = m["id"];
    l["artifact_sha256"] = m["artifact_sha256"];
    l["rva"] = hex_address(address - base);
    l["address"] = va;
    l["address_space"] = "program";
    l["anchor_id"] =
        "loc_" +
        sha256_text(J::array({m["artifact_sha256"], "program", va}).dump());
    l["mapping_status"] = "file_identity_only";
    l["code_identity_note"] =
        "live bytes may differ; captures retain observed bytes";
    break;
  }
  return l;
}
void refresh_modules(RuntimeBackend &backend, J &session, Db &db) {
  if (!backend.alive())
    return;
  auto modules = backend.modules();
  auto old = session.value("modules", J::array());
  for (auto &m : modules) {
    bool found = false;
    for (const auto &p : old)
      if (p["path"] == m["path"] && p["base"] == m["base"]) {
        auto mappings = m.value("mappings", J{});
        auto size = m["size"];
        m = p;
        m["size"] = size;
        if (!mappings.is_null())
          m["mappings"] = mappings;
        found = true;
        break;
      }
    if (found)
      continue;
    m["id"] = make_id("mod");
    m["process_id"] = session["process_id"];
    m["first_observed_at"] = utc_timestamp();
    m["lifetime_coverage"] =
        "snapshot-delimited; unload/reload between snapshots may be missed";
    try {
      fs::path p = m["path"].get<std::string>();
      if (fs::file_size(p) > 512ULL * 1024 * 1024)
        throw std::runtime_error("module hashing exceeds budget");
      m["artifact_sha256"] = sha256_file(p);
      m["image"] = runtime_image(p);
    } catch (const std::exception &e) {
      m["identity_diagnostic"] = e.what();
    }
    db.observe(session["id"], "module_loaded", m);
  }
  for (const auto &p : old) {
    bool found = false;
    for (const auto &m : modules)
      if (p["id"] == m["id"])
        found = true;
    if (!found)
      db.observe(session["id"], "module_unloaded", p);
  }
  session["modules"] = modules;
  auto threads = backend.threads();
  for (auto &thread : threads) {
    thread["process_id"] = session["process_id"];
    for (const auto &prior : session.value("threads", J::array()))
      if (prior["thread_id"] == thread["thread_id"] && prior.contains("id"))
        thread["id"] = prior["id"];
    if (!thread.contains("id")) {
      thread["id"] = make_id("thr");
      db.observe(session["id"], "thread_first_observed", thread);
    }
    thread["process_id"] = session["process_id"];
  }
  for (const auto &prior : session.value("threads", J::array())) {
    bool found = false;
    for (const auto &thread : threads) if (thread["id"] == prior["id"]) found = true;
    if (!found) db.observe(session["id"], "thread_exited", prior);
  }
  session["threads"] = threads;
}
std::uint64_t resolve_address(ProjectStore &store, const J &session,
                              const J &r) {
  if (r.contains("address"))
    return runtime_number(r["address"]);
  J selector = r;
  if (r.contains("function")) {
    auto views = store.function_views(session["project"].get<std::string>(),
                                      r["function"].get<std::string>());
    if (!views.contains("location"))
      throw std::runtime_error("function identity unavailable");
    auto f = views["location"];
    selector["static_address"] = f.at("address");
    selector["artifact"] = f.at("artifact_sha256");
  }
  if (!selector.contains("static_address") && !selector.contains("rva"))
    throw std::runtime_error(
        "address, static_address, rva, or function required");
  std::vector<std::uint64_t> matches;
  for (auto &m : session.value("modules", J::array())) {
    if (selector.contains("module") && selector["module"] != m["id"])
      continue;
    auto artifact = selector.value(
        "artifact", session.value("artifact_sha256", std::string{}));
    if (!artifact.empty() && m.value("artifact_sha256", "") != artifact)
      continue;
    if (!m.contains("image"))
      continue;
    auto preferred = runtime_number(m["image"]["image_base"]);
    auto value = selector.contains("rva")
                     ? runtime_number(selector["rva"])
                     : runtime_number(selector["static_address"]);
    if (!selector.contains("rva") && value < preferred)
      continue;
    auto rva = selector.contains("rva") ? value : value - preferred;
    auto base = runtime_number(m["base"]);
    if (rva < m["size"].get<std::uint64_t>() && base <= UINT64_MAX - rva)
      matches.push_back(base + rva);
  }
  if (matches.size() != 1)
    throw std::runtime_error("static address needs exactly one loaded module; "
                             "specify module/artifact or retry after load");
  return matches[0];
}
J capture(RuntimeBackend &backend, const J &session, const J &request) {
  auto regs = backend.registers(runtime_number(request.value("thread", J(0))));
  for (const auto &thread : session.value("threads", J::array()))
    if (thread["thread_id"] == regs["thread_id"] && thread.contains("id"))
      regs["thread_instance_id"] = thread["id"];
  auto pc =
      runtime_number(regs["values"][regs["arch"] == "x86" ? "eip" : "rip"]);
  auto address =
      request.contains("address") ? runtime_number(request["address"]) : pc;
  auto size = bounded(request, "size", 64, 65536);
  if (address > UINT64_MAX - size)
    throw std::runtime_error("code capture range overflow");
  const auto read_begin = now();
  J data{{"registers", regs},
         {"arch", regs["arch"]},
         {"pc_location", location(session, pc)},
         {"location", location(session, address)},
         {"instruction_bytes", backend.memory(pc, 64)},
         {"code_bytes", backend.memory(address, static_cast<size_t>(size))},
         {"memory", J::array()},
         {"module_ids", J::array()}};
  data["code_bytes"]["read_interval_unix_ms"] = J::array({read_begin, now()});
  data["code_epoch"] = runtime_code_epoch(
      session, data["location"], data["code_bytes"],
      "stopped debugger read; backend thread-stop guarantees apply");
  data["capture_group_id"]=make_id("capture_group");
  data["code_regions"]=J::array();
  size_t code_total=size;
  for(const auto &region:request.value("code_regions",J::array())) {
    auto count=bounded(region,"size",64,65536),start=runtime_number(region.at("address"));
    code_total+=count;if(code_total>65536||start>UINT64_MAX-count)throw std::runtime_error("code regions exceed 64KiB/overflow");
    auto loc=location(session,start);auto begin=now();auto memory=backend.memory(start,static_cast<size_t>(count));memory["read_interval_unix_ms"]=J::array({begin,now()});
    auto epoch=runtime_code_epoch(session,loc,memory,"same stopped capture group; regions read sequentially");
    data["code_regions"].push_back({{"arch",regs["arch"]},{"location",loc},{"code_bytes",memory},{"code_epoch",epoch},{"capture_group_id",data["capture_group_id"]}});
    if(memory.value("status","partial")!="completed")data["status"]="partial";
  }
  data["coherence"]="single debugger stop, sequential reads; externally shared writable memory may still change";
  for (const auto &module : session.value("modules", J::array())) {
    if (data["module_ids"].size() >= 256) {
      data["module_ids_truncated"] = true;
      break;
    }
    data["module_ids"].push_back(module["id"]);
  }
  data["status"] = data["instruction_bytes"].value("status", "partial");
  if (data["code_bytes"].value("status", "partial") != "completed")
    data["status"] = "partial";
  std::size_t total = 0;
  auto ranges = request.value("memory", J::array());
  if (ranges.size() > 16)
    throw std::runtime_error("at most 16 memory ranges per capture");
  for (auto &r : ranges) {
    auto n = bounded(r, "size", 256, 65536);
    total += n;
    if (total > 65536)
      throw std::runtime_error("capture memory budget exceeds 64 KiB");
    if (runtime_number(r.at("address")) > UINT64_MAX - n)
      throw std::runtime_error("capture range overflow");
    data["memory"].push_back(backend.memory(runtime_number(r.at("address")),
                                            static_cast<std::size_t>(n)));
    if (data["memory"].back()["status"] != "completed")
      data["status"] = "partial";
  }
  return data;
}
int replay_worker(ProjectStore &store, Db &db, J &session) {
  const auto id=session.at("id").get<std::string>();
  session["state"]="running";session["backend"]="rr";session["heartbeat_ms"]=now();
  db.save(session);
  auto cancelled=[&] {
    if(now()-session.value("heartbeat_ms",std::int64_t{})>1000){session["heartbeat_ms"]=now();db.save(session);}
    return db.run("SELECT cancel FROM runtime_sessions WHERE id=?",{id})[0]["cancel"]!="0";
  };
  auto phase=[&](const J& data){session["phase"]=data.at("phase");session["heartbeat_ms"]=now();db.save(session);db.observe(id,"replay_phase",data);};
  auto result=run_rr_session(fs::absolute(store.root()/"runtime-artifacts"/id),session.at("request"),cancelled,phase);
  auto evidence=db.observe(id,"replay_summary",result,result.at("status"));
  session["summary_id"]=evidence["id"];session["result_status"]=result["status"];
  session["state"]=result["status"]=="cancelled"?"cancelled":result["status"]=="failed"?"failed":"exited";
  session["replay_ready"]=result.at("replay_ready");
  if(result.value("replay_ready",false)) {
    session["trace_manifest"]=result.at("trace_manifest");session["trace_directory"]=result.at("trace_directory");
    session["native_traceinfo"]=result.at("native_traceinfo");
  }
  if(result.contains("diagnostic"))session["diagnostic"]=result["diagnostic"];
  session["heartbeat_ms"]=now();db.save(session);
  return result["status"]=="failed"?1:result["status"]=="cancelled"?130:0;
}
int instrument_worker(ProjectStore &store, Db &db, J &session) {
  auto id = session.at("id").get<std::string>();
  try {
    auto r = session.at("request");
    const bool frida = r.value("backend", "dynamorio") == "frida";
    const std::string engine = frida ? "frida" : "dynamorio";
    auto file = fs::path(r.at("file").get<std::string>());
    if (sha256_file(file) != r.at("artifact_sha256").get<std::string>())
      throw std::runtime_error("instrument image changed after import");
    auto image = runtime_image(file);
    auto bits = image.at("arch") == "x86" ? "32" : "64";
    auto root = bundled_engines() / "dynamorio";
    auto host = root / (std::string("bin") + bits) /
#ifdef _WIN32
                "indago_dr_host.exe";
    auto client = root / (std::string("lib") + bits) / "indago_dr_client.dll";
#else
                "indago_dr_host";
    auto client = root / (std::string("lib") + bits) / "libindago_dr_client.so";
#endif
    if (frida) {
      root = bundled_engines() / "frida";
#ifdef _WIN32
      host = root / "indago_frida_host.exe";
#else
      host = root / "indago_frida_host";
#endif
      client = host;
    }
    if (!fs::exists(host) || !fs::exists(client))
      throw std::runtime_error("DynamoRIO payload missing; build runtime "
                               "engines and rebuild indago");
    auto directory = fs::absolute(store.root() / "runtime-artifacts" / id);
    fs::create_directories(directory / "config");
    auto events = directory / "events.jsonl",
         result = directory / "result.json", cancel = directory / "cancel";
    auto budget = bounded(r, "max_events", 1024, 10000),
         timeout = bounded(r, "timeout_ms", 5000, 60000);
    auto cwd = fs::absolute(r.value("cwd", file.parent_path().string()));
    std::vector<std::string> arguments{root.string(),
                                       client.string(),
                                       events.string(),
                                       result.string(),
                                       cancel.string(),
                                       std::to_string(budget),
                                       std::to_string(timeout),
                                       cwd.string(),
                                       (directory / "config").string(),
                                       r.value("telemetry","blocks"),
                                       r.value("code_scope","main"),
                                       file.string()};
    if (frida)
      arguments = {events.string(),         result.string(),
                   cancel.string(),         std::to_string(budget),
                   std::to_string(timeout), cwd.string(),
                   r.value("recipe", "io"), r.contains("pid")?"pid:"+std::to_string(runtime_number(r["pid"])):file.string()};
    for (auto &arg : r.value("argv", J::array()))
      arguments.push_back(arg.get<std::string>());
    auto generation = db.run("SELECT cancel FROM runtime_sessions WHERE id=?",
                             {id})[0]["cancel"];
    NativeProcessOptions options;
    options.wall_time_ms = timeout + 10000;
    options.max_output_bytes = 65536;
    auto task = std::async(std::launch::async, [&] {
      return run_native_process(host, arguments, options);
    });
    session["state"] = "running";
    session["backend"] = engine;
    session["arch"] = image["arch"];
    session["engine_version"] = frida ? "17.17.0" : "11.3.0";
    session["scope"] = "main-image basic-block execution; no child tracing or "
                       "memory-value trace";
    if (frida)
      session["scope"] = "bounded fixed Frida recipe; selected user-space "
                         "hooks; no children or direct syscall coverage";
    db.save(session);
    db.observe(
        id, "session_started",
        {{"process_id", session["process_id"]},
         {"address_space_id", session["address_space_id"]},
         {"backend", engine},
         {"coverage",
          "collector start; native process birth may precede first event"}});
    bool cancelled = false;
    while (task.wait_for(std::chrono::milliseconds(25)) !=
           std::future_status::ready) {
      auto current = db.run("SELECT cancel FROM runtime_sessions WHERE id=?",
                            {id})[0]["cancel"];
      if (current != generation && !cancelled) {
        atomic_write(cancel, "cancel\n");
        cancelled = true;
      }
      if (now() - session.value("heartbeat_ms", std::int64_t{}) > 1000) {
        session["heartbeat_ms"] = now();
        db.save(session);
      }
    }
    auto process = task.get();
    J summary{{"backend", engine},
              {"engine_version", session["engine_version"]},
              {"host_exit_code", process.exit_code},
              {"host_timed_out", process.timed_out},
              {"host_output_truncated", process.truncated},
              {"cancelled", cancelled},
              {"max_events", budget},
              {"scope", session["scope"]}};
    summary["host_output"] = process.output.substr(0, 4096);
    if (fs::exists(result) && fs::file_size(result) <= 65536) {
      std::ifstream stream(result);
      J native;
      stream >> native;
      summary["native_result"] = native;
      if (native.contains("pid"))
        session["pid"] = native["pid"];
    }
    bool partial = !frida, capped = false;
    std::size_t count = 0;
    if (fs::exists(events)) {
      if (fs::file_size(events) > 4 * 1024 * 1024)
        throw std::runtime_error("DynamoRIO event file exceeds 4MiB");
      std::ifstream stream(events);
      std::string line;
      std::size_t records = 0;
      uint64_t hashed_module_bytes=0;
      J sequence_observations=J::object();
      while (std::getline(stream, line) && records++ < budget + 260) {
        auto native = J::parse(line, nullptr, false);
        if (native.is_discarded() || !native.is_object()) {
          summary["malformed_tail"] = true;
          break;
        }
        auto kind = native.value("kind", "");
        if (frida) {
          auto envelope = native;
          if (native.value("type", "") != "send" ||
              !native.contains("payload")) {
            db.observe(id, "frida_diagnostic", {{"native", native}});
            partial = true;
            continue;
          }
          native = native["payload"];
          kind = native.value("kind", "");
          if (kind == "collection_limit") {
            capped = true;
            continue;
          }
          J data{{"backend", "frida"},
                 {"native", envelope},
                 {"process_id", session["process_id"]},
                 {"address_space_id", session["address_space_id"]}};
          if (kind == "module_loaded") {
            J module{
                {"id", id + "_" + native.at("instance").get<std::string>()},
                {"process_id", session["process_id"]},
                {"base", native.at("base")},
                {"size", native.at("size")},
                {"path", native.at("path")}};
            try {
              auto path = fs::path(native.at("path").get<std::string>());
              if (fs::file_size(path) > 512ULL * 1024 * 1024)
                throw std::runtime_error("hash budget");
              module["artifact_sha256"] = sha256_file(path);
              module["image"] = runtime_image(path);
            } catch (const std::exception &e) {
              module["identity_diagnostic"] = e.what();
            }
            if (!session.contains("modules"))
              session["modules"] = J::array();
            session["modules"].push_back(module);
            data["module"] = module;
          } else if (kind == "module_unloaded") {
            auto &mods = session["modules"];
            if (mods.is_array())
              for (auto it = mods.begin(); it != mods.end();) {
                if ((*it)["base"] == native["base"]) {
                  data["module"] = *it;
                  it = mods.erase(it);
                } else
                  ++it;
              }
          }
          if (kind == "thread_created" || kind == "thread_exited") {
            data["thread"] = {
                {"id", id + "_" + native.value("instance", "unknown")},
                {"thread_id", native.at("native_thread_id")},
                {"process_id", session["process_id"]}};
          }
          if (native.contains("caller"))
            data["location"] =
                location(session, runtime_number(native["caller"]));
          if (native.contains("socket") && native.at("socket").is_object()) {
            const auto &socket=native.at("socket");
            if (socket.contains("instance") && socket.at("instance").is_string()) {
              data["socket"]=socket;
              data["socket"]["id"]=id+"_"+socket.at("instance").get<std::string>();
              data["socket"]["process_id"]=session["process_id"];
              data["socket"]["address_space_id"]=session["address_space_id"];
              data["socket"]["identity_scope"]="Frida collection-local observed handle generation";
              data["socket_event"]=native.value("socket_event",std::string("observed"));
              data["socket_generation_race"]=native.value("socket_generation_race",false);
            } else partial=true;
          }
          if (native.contains("call_id") && native.at("call_id").is_string())
            data["call_id"]=id+"_"+native.at("call_id").get<std::string>();
          if (native.contains("network_outcome") || native.contains("network_completeness")) {
            data["network"]={{"api",native.at("api")},{"outcome",native.value("network_outcome",std::string("not_modeled"))},
                {"completeness",native.value("network_completeness",std::string("selected API return only"))},
                {"delivery_proven",false}};
            if (native.contains("transferred_bytes")) data["network"]["transferred_bytes"]=native.at("transferred_bytes");
          }
          if (kind == "code_capture") {
            data["arch"] = native.at("arch");
            data["code_bytes"] = native;
            data["location"] =
                location(session, runtime_number(native.at("address")));
            data["code_epoch"] = runtime_code_epoch(
                session, data["location"], native,
                "Frida API-return read; asynchronous, not stop-the-world");
          }
          if (kind == "hook_unavailable" || kind == "capture_unavailable")
            partial = true;
          db.observe(id, kind.empty() ? "frida_unknown" : kind, data);
          ++count;
          continue;
        }
        if (kind == "main_module") {
          J module{{"id", make_id("mod")},
                   {"base", native.at("base")},
                   {"size", image.at("image_size")},
                   {"path", file.string()},
                   {"artifact_sha256", r["artifact_sha256"]},
                   {"image", image},
                   {"process_id", session["process_id"]}};
          session["modules"] = J::array({module});
          session["pid"] = native["pid"];
          db.observe(id, "module_loaded", module);
        } else if(kind=="module_loaded"||kind=="module_unloaded") {
          auto base=native.at("base");auto &modules=session["modules"];if(!modules.is_array())modules=J::array();
          J prior;for(auto it=modules.begin();it!=modules.end();)if((*it)["base"]==base){prior=*it;it=modules.erase(it);}else ++it;
          if(kind=="module_unloaded"){if(prior.is_object())db.observe(id,"module_unloaded",prior);continue;}
          J module{{"id",prior.is_object()?prior["id"]:J(make_id("mod"))},{"base",base},{"size",runtime_number(native.at("end"))-runtime_number(base)},{"process_id",session["process_id"]},{"native",native}};
          try {
            auto hex=native.at("path_hex").get<std::string>();if(native.value("path_truncated",false)||hex.size()>4096||hex.size()%2||hex.find_first_not_of("0123456789abcdefABCDEF")!=std::string::npos)throw std::runtime_error("invalid/truncated module path");
            std::string path;for(size_t i=0;i<hex.size();i+=2)path+=static_cast<char>(std::stoul(hex.substr(i,2),nullptr,16));if(path.empty()||path.find('\0')!=std::string::npos)throw std::runtime_error("empty/invalid module path");module["path"]=path;
            auto size=fs::file_size(path);if(size>256ULL*1024*1024-hashed_module_bytes)throw std::runtime_error("aggregate module hash budget exceeded");hashed_module_bytes+=size;module["artifact_sha256"]=sha256_file(path);module["image"]=runtime_image(path);module["identity_method"]="post-run file hash; does not assert live-image byte equality";
          }catch(const std::exception &error){module["identity_diagnostic"]=error.what();}
          modules.push_back(module);db.observe(id,"module_loaded",module);
        } else if (kind == "basic_block" && count < budget) {
          auto pc = runtime_number(native.at("pc"));
          auto loc = location(session, pc);
          J record{{"backend", "dynamorio"},
                   {"native", native},
                   {"location", loc},
                   {"process_id", session["process_id"]},
                   {"semantic_completeness",
                    "observed block entry; instruction "
                    "semantics remain XAIR-owned"}};
          if(!native.value("bytes_hex","").empty()) {
            auto hex=native.at("bytes_hex").get<std::string>();record["arch"]=image["arch"];
            record["code_bytes"]={{"address",native["pc"]},{"requested",native["size"]},{"size",hex.size()/2},{"hex",hex},{"status",hex.size()/2==runtime_number(native["size"])?"completed":"partial"}};
            record["code_epoch"]=runtime_code_epoch(session,record["location"],record["code_bytes"],"DynamoRIO block entry read; bounded prefix; preceding write is an attempt, not a completed-write proof");
          }
          record["origin"]={{"kind",loc.contains("module_id")?"loaded_module_execution":"unmapped_execution"},{"source","DynamoRIO executed block entry"},{"generated_code_proven",false}};
          auto block_observation=db.observe(id, "instrumentation_block", record);
          if(native.value("prior_confirmed_write_sequence",uint64_t{})>0)db.observe(id,"write_execute",{{"block_observation",block_observation["id"]},{"write_sequence",native["prior_confirmed_write_sequence"]},{"write_observation",sequence_observations.value(std::to_string(runtime_number(native["prior_confirmed_write_sequence"])),J{})},{"location",loc},{"epoch_id",record.value("code_epoch",J::object()).value("id",J{})},{"scope","same process page previously written by completed native store; not proof that this write produced every executed byte"}});
          ++count;
        } else if ((kind=="memory_effect"||kind=="memory_effect_completed"||kind=="control_transfer"||kind=="control_transfer_taken")&&count<budget) {
          J record{{"backend","dynamorio"},{"native",native},{"location",location(session,runtime_number(native.at("pc")))},{"process_id",session["process_id"]}};
          if(native.contains("target")){record["target_location"]=location(session,runtime_number(native["target"]));for(const auto &module:session.value("modules",J::array())){if(record["location"].value("module_id",J{})==module["id"])record["source_module"]=module;if(record["target_location"].value("module_id",J{})==module["id"])record["target_module"]=module;}}
          if(native.contains("address"))record["memory_location"]=location(session,runtime_number(native["address"]));
          if(native.contains("attempt_sequence"))record["attempt_observation"]=sequence_observations.value(std::to_string(runtime_number(native["attempt_sequence"])),J{});
          auto observation=db.observe(id,kind,record);if(native.contains("sequence"))sequence_observations[std::to_string(runtime_number(native["sequence"]))]=observation["id"];++count;
        } else if (kind == "collection_limit")
          capped = true;
        else if (kind == "collection_end")
          partial = native.value("partial", true);
      }
      summary["raw_sha256"] = sha256_file(events);
      summary["raw_file"] = events.string();
    }
    summary["events"] = count;
    const auto native = summary.value("native_result", J::object());
    bool failed =
        process.exit_code != 0 || native.value("native_error", -1) != 0;
    bool incomplete = partial || capped || native.value("partial", false) ||
                      process.timed_out || native.value("timed_out", false);
    summary["status"] = cancelled    ? "cancelled"
                        : failed     ? "failed"
                        : incomplete ? "partial"
                                     : "completed";
    if (failed)
      summary["diagnostic"] = process.error.substr(0, 4096);
    auto evidence = db.observe(id, "instrumentation_summary", summary);
    session["summary_id"] = evidence["id"];
    session["result_status"] = summary["status"];
    session["state"] = cancelled ? "cancelled" : failed ? "failed" : "exited";
    session["heartbeat_ms"] = now();
    db.observe(
        id, "collection_closed",
        {{"state", session["state"]},
         {"coverage",
          "end of collection, not proof of every module/thread native exit"}});
    db.save(session);
    return failed ? 1 : 0;
  } catch (const std::exception &e) {
    session["state"] = "failed";
    session["diagnostic"] = e.what();
    session["heartbeat_ms"] = now();
    db.save(session);
    return 1;
  }
}
} // namespace
J runtime_capabilities() {
  return {{"schema", "indago.runtime-capabilities.v1"},
          {"backend",
#ifdef _WIN32
           "dbgeng"
#else
           "gdb-mi"
#endif
          },
          {"host_native_formats",
#ifdef _WIN32
           J::array({"PE"})
#else
           J::array({"ELF"})
#endif
          },
          {"architectures", {"x86", "x64"}},
          {"rr",{{"bundled",INDAGO_HAS_RR!=0},{"operations",{"record","replay"}},
                 {"scope","Linux user-space record/pack and autopilot replay; x86/x64; CPU/perf support required"},
                 {"interactive_reverse_debugging",false},{"harness_execution_enabled",false},
                 {"max_trace_bytes",134217728},{"max_wall_ms",60000}}},
          {"dynamorio",
           {{"bundled", INDAGO_HAS_DYNAMORIO != 0},
            {"operation", "instrument"},
            {"telemetry", {"blocks","effects"}},
            {"code_scope", {"main","all","application"}},
            {"scope", "bounded block entries, attempted memory effects and native call/return/indirect transfers; single process"}}},
          {"frida",
           {{"bundled", INDAGO_HAS_FRIDA != 0},
            {"recipes", {"io", "code", "modules", "config", "network"}},
            {"modes", {"spawn","attach"}},
            {"network",{{"socket_identities","collection-local observed generations; aliases/inheritance incomplete"},
                        {"tracked_sockets",1024},{"buffer_bytes",64},{"sockaddr_bytes",128},
                        {"packet_capture",false},{"protocol_decoding",false},{"async_completion",false},
                        {"remote_delivery_proven",false}}}}},
          {"capture_reanalysis", {"capture", "reanalyze", "feedback", "lineage"}},
          {"operations",
           {"launch",    "attach",     "instrument",   "sessions", "record", "replay",
            "status",    "modules",    "threads",      "continue",
            "pause",     "step",       "breakpoint",   "remove-breakpoint",
            "registers", "memory",     "capture",      "resolve",
            "trace",     "cancel",     "observations", "symbolic",
            "network",
            "payloads",
            "detach",    "terminate",  "request",      "reanalyze",
            "lineage",   "identities", "feedback", "recipes", "stack", "crash", "step-over", "step-out", "watchpoint", "breakpoints", "processes", "select-process", "validate-witness"}},
          {"software_breakpoints", "engine-owned; one-shot default; persistent, conditional and deferred options"},
          {"isolation", "host execution; no sandbox"},
          {"trace", "bounded debugger stepping; not DynamoRIO instrumentation"},
          {"symbolic",
           "XAIR/XAIR_SYM captured block or bounded selected path; no whole-process taint"}};
}
J runtime_command(ProjectStore &store, const fs::path &executable, J r) {
  if (r.dump().size() > 65536)
    throw std::runtime_error("runtime request exceeds 64 KiB");
  validate_contract("runtime-action", r);
  if (r.contains("thread") && runtime_number(r["thread"]) > 0x7fffffff)
    throw std::runtime_error("invalid thread ID");
  auto op = r.value("operation", "");
  if (op == "capabilities")
    return runtime_capabilities();
  if (op == "payloads")
    return bundled_payload_inventory();
  if (op == "recipes")
    return {{"recipes", {"io", "code", "modules", "config", "network"}},
            {"backend", "frida"},
            {"limits", "1..10000 events, 1..60000ms, code read <=4096 bytes, "
                       "buffers <=64 bytes"}};
  auto project = r.value("project", "");
  store.project_info(project);
  Db db(store);
  if (op == "sessions") {
    J list = J::array();
    for (auto &row : db.run("SELECT record FROM runtime_sessions WHERE "
                            "project=? ORDER BY rowid DESC LIMIT 100",
                            {project})) {
      auto s = J::parse(row["record"].get<std::string>());
      s["worker_alive"] = live_worker(s);
      s.erase("modules");
      s.erase("request");
      list.push_back(s);
    }
    return {{"sessions", list}};
  }
  if (op == "launch" || op == "attach" || op == "instrument" || op=="record" || op=="replay") {
    const bool rr=op=="record"||op=="replay";
    if(rr) {
      if(!INDAGO_HAS_RR)throw std::runtime_error("rr requires a Linux build with the replay payload");
      const std::set<std::string> allowed=op=="record"?
        std::set<std::string>{"schema","operation","project","backend","file","argv","cwd","timeout_ms","trace_bytes"}:
        std::set<std::string>{"schema","operation","project","backend","session","timeout_ms","trace_bytes"};
      for(auto it=r.begin();it!=r.end();++it)if(!allowed.contains(it.key()))throw std::runtime_error("Unsupported rr request field: "+it.key());
      if(r.contains("backend")&&r.at("backend")!="rr")throw std::runtime_error("record/replay backend must be rr");
      r["backend"]="rr";
      if(op=="replay") {
        const auto source=db.session(r.at("session"),project);
        if(source.value("backend","")!="rr"||!source.value("replay_ready",false)||source.at("request").at("operation")!="record")
          throw std::runtime_error("Replay requires a packed, identity-indexed rr recording in this project");
        r["recorded_session"]=source.at("id");r["recorded_trace_manifest"]=source.at("trace_manifest");
        r["recorded_trace_directory"]=fs::absolute(store.root()/"runtime-artifacts"/source.at("id").get<std::string>()/"trace").string();
        r["artifact_sha256"]=source.at("artifact_sha256");
      }
    } else if(r.value("backend","")=="rr")throw std::runtime_error("rr supports record and replay, not debugger launch/attach");
    const auto engine = r.value("backend", "dynamorio");
    if (op == "instrument" && engine != "dynamorio" && engine != "frida")
      throw std::runtime_error("instrument backend must be dynamorio or frida");
    if (op == "instrument" && engine == "frida" && !INDAGO_HAS_FRIDA)
      throw std::runtime_error("Frida is not bundled in this build");
    if (op == "instrument" && engine == "dynamorio" && !INDAGO_HAS_DYNAMORIO)
      throw std::runtime_error("DynamoRIO is not bundled in this build");
    if (op == "launch" || op == "instrument" || op=="record") {
      if(op=="instrument"&&r.contains("pid")) {
        if(r.value("backend","")!="frida")throw std::runtime_error("instrument attach requires Frida");
        auto pid=runtime_number(r.at("pid"));if(pid<=1||pid>0x7fffffff)throw std::runtime_error("invalid PID");
#ifdef _WIN32
        HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,static_cast<DWORD>(pid));wchar_t path[32768];DWORD size=32768;
        if(!process)throw std::runtime_error("cannot inspect attach target");bool ok=QueryFullProcessImageNameW(process,0,path,&size)!=0;CloseHandle(process);if(!ok)throw std::runtime_error("cannot resolve attach image");r["file"]=fs::path(path).string();
#else
        r["file"]=fs::read_symlink(fs::path("/proc")/std::to_string(pid)/"exe").string();
#endif
      }
      if (!r.contains("file"))
        throw std::runtime_error(
            "explicit executable file required for runtime launch");
      auto file = fs::canonical(r["file"].get<std::string>());
      auto image = runtime_image(file);
#ifdef _WIN32
      if (image["format"] != "PE")
        throw std::runtime_error(
            "launch ELF using the Linux indago binary in WSL");
#else
      if (image["format"] != "ELF")
        throw std::runtime_error(
            "launch PE using the Windows indago executable");
#endif
      auto target = store.import_target(project, file);
      r["file"] = file.string();
      r["artifact_sha256"] = target.sha256;
      r["target_id"] = target.id;
    } else if(op!="replay") {
      auto pid = runtime_number(r.at("pid"));
      if (pid <= 1 || pid > 0x7fffffff)
        throw std::runtime_error("invalid PID");
    }
    auto argv = r.value("argv", J::array());
    if (!argv.is_array() || argv.size() > 256 || argv.dump().size() > 16384)
      throw std::runtime_error("argv budget exceeded");
    for (auto &arg : argv)
      if (!arg.is_string() ||
          arg.get<std::string>().find('\0') != std::string::npos)
        throw std::runtime_error("invalid argv");
    bounded(r, "lifetime_ms", 1800000, 86400000);
    auto id = make_id("run");
    J s{{"schema", "indago.runtime-session.v1"},
        {"id", id},
        {"project", project},
        {"state", "starting"},
        {"process_id", make_id("proc")},
        {"address_space_id", make_id("as")},
        {"created_at", utc_timestamp()},
        {"heartbeat_ms", now()},
        {"request", r},
        {"artifact_sha256", r.value("artifact_sha256", "")}};
    db.run("INSERT INTO runtime_sessions(id,project,record) VALUES(?,?,?)",
           {id, project, s.dump()});
    try {
      spawn_runtime(self_executable(executable), store, id);
    } catch (const std::exception &e) {
      s["state"] = "failed";
      s["diagnostic"] = e.what();
      db.save(s);
      throw;
    }
    auto deadline = now() + 15000;
    do {
      std::this_thread::sleep_for(std::chrono::milliseconds(25));
      s = db.session(id, project);
      if (s["state"] != "starting") {
        s["status"] = s["state"] == "failed" ? "failed" : "completed";
        if (op == "instrument" || rr)
          s["status"] = s["state"] == "running"
                            ? J("pending")
                            : s.value("result_status", J("failed"));
        return s;
      }
    } while (now() < deadline);
    return {{"session_id", id},
            {"status", "pending"},
            {"diagnostic", "worker startup pending; use runtime status"}};
  }
  auto id = r.value("session", "");
  auto s = db.session(id, project);
  if (op == "request") {
    auto rows = db.run(
        "SELECT state,response FROM runtime_requests WHERE id=? AND session=?",
        {r.at("id"), id});
    if (rows.empty())
      throw std::runtime_error("runtime request not found");
    if (!rows[0]["response"].is_null())
      return J::parse(rows[0]["response"].get<std::string>());
    return {{"status", "pending"},
            {"request_id", r["id"]},
            {"state", rows[0]["state"]},
            {"worker_alive", live_worker(s)}};
  }
  if (op == "status") {
    s["worker_alive"] = live_worker(s);
    if (!live_worker(s) && s["state"] != "detached" && s["state"] != "exited" &&
        s["state"] != "terminated" && s["state"] != "cancelled" &&
        s["state"] != "failed")
      s["state"] = "interrupted";
    s.erase("request");
    return s;
  }
  if (op == "observations")
    return db.observations(id, r);
  if (op == "network") {
    auto result=db.network_observations(id,r);
    result["collection_state"]=s.at("state");
    result["collection_status"]=s.value("result_status",std::string("unknown_or_in_progress"));
    return result;
  }
  if(op=="feedback"){
    auto records=db.observations(id,{{"id",r.at("observation")},{"limit",1}})["observations"];
    if(records.empty())throw std::runtime_error("feedback observation not found");auto observation=records[0];auto data=observation.at("data");
    if(observation["kind"]=="write_execute"){auto blocks=db.observations(id,{{"id",data.at("block_observation")},{"limit",1}})["observations"];if(blocks.empty())throw std::runtime_error("write/execute block evidence missing");auto result=runtime_reanalyze(store,s,blocks[0],r);result["origin_observation"]=observation["id"];result["write_observation"]=data.value("write_observation",J{});auto record=db.observe(id,"runtime_feedback",result,"derived");record["status"]=result["status"];return record;}
    if(data.contains("code_epoch")&&!data["code_epoch"].is_null()){auto result=runtime_reanalyze(store,s,observation,r);result["origin_observation"]=observation["id"];auto record=db.observe(id,"runtime_feedback",result,"derived");record["status"]=result["status"];return record;}
    if(observation["kind"]=="module_loaded"){
      auto module=data.value("module",data);auto backend=r.value("backend","xair");if(backend!="xair"&&backend!="ghidra")throw std::runtime_error("module feedback backend must be xair or ghidra");
      auto path=fs::path(module.at("path").get<std::string>());if(fs::file_size(path)>512ULL*1024*1024||sha256_file(path)!=module.at("artifact_sha256").get<std::string>())throw std::runtime_error("module unavailable or changed since observation");
      auto target=store.import_target(project,path);if(target.sha256!=module["artifact_sha256"].get<std::string>())throw std::runtime_error("module changed during import");store.record_derivation(target,{{"kind","runtime_module_import"},{"session_id",id},{"observation_id",observation["id"]},{"observation_sha256",observation["sha256"]},{"module",module}});
      StaticService service(store.root());auto analysis=service.execute(service.prepare({{"project",project},{"target_id",target.id},{"backend",backend},{"operation",backend=="ghidra"?"functions":"inventory"},{"budget",{{"wall_ms",r.value("timeout_ms",10000)},{"max_items",256},{"output_bytes",1048576}}}}));
      analysis["origin_observation"]=observation["id"];db.observe(id,"runtime_feedback",analysis,"derived");return analysis;
    }
    if(observation["kind"]!="control_transfer_taken")throw std::runtime_error("feedback requires an executed target transfer or captured code epoch; transfer attempts alone are insufficient");
    auto source=data.at("location"),destination=data.at("target_location");
    if(!source.contains("artifact_sha256")||!destination.contains("artifact_sha256"))return {{"status","partial"},{"diagnostic","unmapped endpoint retained as runtime evidence; capture/reanalyze its code before static anchoring"},{"observation",observation["id"]}};
    if(r.value("backend","xair")!="xair"&&r.value("backend","xair")!="ghidra")throw std::runtime_error("transfer feedback backend must be xair or ghidra");
    auto import_module=[&](const J &module){auto path=fs::path(module.at("path").get<std::string>());if(fs::file_size(path)>512ULL*1024*1024||sha256_file(path)!=module.at("artifact_sha256").get<std::string>())throw std::runtime_error("module file changed or import budget exceeded");auto target=store.import_target(project,path);if(target.sha256!=module.at("artifact_sha256").get<std::string>())throw std::runtime_error("module changed during import");store.record_derivation(target,{{"kind","runtime_module_import"},{"session_id",id},{"observation_id",observation["id"]},{"module",module},{"scope","file identity observed after run; not proof that live bytes matched file"}});return target;};
    auto target=import_module(data.at("target_module"));auto source_target=import_module(data.at("source_module"));
    J request{{"project",project},{"target_id",source_target.id},{"artifact_sha256",source_target.sha256},{"backend","runtime"},{"operation","runtime_feedback:"+observation["id"].get<std::string>()}};
    J overlay{{"edges",J::array({{{"from",source["address"]},{"to",destination["address"]},{"from_location",source},{"to_location",destination},{"location",source},{"native_verdict","observed target entry"},{"runtime_observation_id",observation["id"]},{"runtime_observation_sha256",observation["sha256"]},{"session_id",id},{"semantics","observed execution relation; does not modify AIRECE or Ghidra CFG"}}})}};
    auto job=store.start_job(source_target,request);auto published=store.publish_result(source_target,job,"runtime",{0,"completed",overlay.dump()});
    StaticService service(store.root());J action{{"project",project},{"target_id",target.id},{"backend",r.value("backend","xair")},{"operation","cfg"},{"address",destination["address"]},{"budget",{{"wall_ms",r.value("timeout_ms",10000)},{"max_items",128},{"output_bytes",1048576}}}};
    if(action["backend"]!="xair"&&action["backend"]!="ghidra")throw std::runtime_error("transfer feedback backend must be xair or ghidra");
    auto analysis=service.execute(service.prepare(action));analysis.erase("data");J result{{"status",analysis.value("status","partial")},{"overlay",published},{"target_analysis",analysis}};db.observe(id,"runtime_feedback",result,"derived");return result;
  }
  if (op == "reanalyze") {
    auto records = db.observations(
        id, {{"id", r.at("observation")}, {"limit", 1}})["observations"];
    if (records.empty() || !records[0]["data"].contains("code_epoch") ||
        records[0]["data"]["code_epoch"].is_null())
      throw std::runtime_error("reanalysis requires an observation with "
                               "captured code bytes and epoch");
    auto result = runtime_reanalyze(store, s, records[0], r);
    auto record = db.observe(id, "reanalysis", result, "derived");
    record["status"] = result["status"];
    return record;
  }
  if (op == "lineage")
    return {{"derivations",
             store.derivations(project, r.at("artifact").get<std::string>())}};
  if (op == "identities") {
    const auto limit =
        std::clamp<uint64_t>(runtime_number(r.value("limit", J(100))), 1, 1000);
    const auto offset = runtime_number(r.value("offset", J(0)));
    const auto identity_kind=r.value("kind",std::string("epoch"));
    if (!std::set<std::string>{"epoch","lifetime","process","module","thread","socket","api_call"}.contains(identity_kind))
      throw std::runtime_error("unsupported runtime identity kind");
    const bool epochs = identity_kind == "epoch";
    const auto filter=identity_kind=="lifetime"?std::string{}:identity_kind;
    const auto identity_filter=r.value("id",std::string{});
    auto rows = epochs ? db.run("SELECT record,observation FROM runtime_code_epochs WHERE session=? AND (?='' OR id=?) ORDER BY rowid LIMIT ? OFFSET ?",
                    {id,identity_filter,identity_filter,std::to_string(limit+1),std::to_string(offset)})
        : db.run("SELECT record,kind,first_observation,last_observation FROM runtime_lifetimes WHERE session=? AND (?='' OR kind=?) AND (?='' OR id=?) ORDER BY rowid LIMIT ? OFFSET ?",
                    {id,filter,filter,identity_filter,identity_filter,std::to_string(limit+1),std::to_string(offset)});
    J out = J::array();
    size_t bytes = 0;
    for (auto &row : rows) {
      auto raw = row.at("record").get<std::string>();
      if (out.size() >= limit || bytes + raw.size() > 1048576)
        break;
      bytes += raw.size();
      row["record"] = J::parse(raw);
      out.push_back(row);
    }
    return {{"identities", out},
            {"next_offset",
             out.size() < rows.size() ? J(offset + out.size()) : J(nullptr)},
            {"coverage", "observed lifetimes, not guaranteed OS births/exits; "
                         "epochs are point reads"}};
  }
  if (op == "symbolic") {
    if (!r.contains("observation"))
      throw std::runtime_error("symbolic requires a capture observation ID");
    auto evidence = db.observations(
        id, {{"id", r["observation"]}, {"limit", 1}})["observations"];
    if (evidence.empty() || evidence[0]["kind"] != "capture")
      throw std::runtime_error("capture observation not found");
    auto data = runtime_symbolic(evidence[0], r);
    auto record = db.observe(id, "symbolic", data, "derived");
    record["status"] = data.value("status", "partial");
    return record;
  }
  if (op == "cancel") {
    db.run("UPDATE runtime_sessions SET cancel=cancel+1 WHERE id=?", {id});
    return {{"status", "cancel_requested"}, {"session_id", id}};
  }
  if (s.value("backend", "") == "dynamorio" ||
      s.value("backend", "") == "frida" || s.value("backend", "") == "rr")
    throw std::runtime_error("instrument runs support status, observations and "
                             "cancel; they are not debugger sessions");
  static const std::set<std::string> operations{
      "modules", "threads",    "continue",          "pause",
      "step",    "breakpoint", "remove-breakpoint", "registers",
      "memory",  "capture",    "resolve",           "trace",
      "detach",  "terminate", "stack", "crash", "step-over", "step-out", "watchpoint", "breakpoints", "processes", "select-process", "validate-witness"};
  if (!operations.contains(op))
    throw std::runtime_error("unknown runtime operation");
  if (!live_worker(s))
    throw std::runtime_error(
        "runtime worker unavailable; stored observations remain readable");
  if (s["state"] == "detached" || s["state"] == "exited" ||
      s["state"] == "terminated" || s["state"] == "failed")
    throw std::runtime_error("session is terminal");
  if (r.dump().size() > 65536)
    throw std::runtime_error("runtime request exceeds 64 KiB");
  auto wall = bounded(r, "timeout_ms", 5000, 60000);
  auto req = make_id("rtq");
  db.run("INSERT INTO runtime_requests(id,session,state,request) "
         "VALUES(?,?,'queued',?)",
         {req, id, r.dump()});
  auto deadline = now() + static_cast<std::int64_t>(wall) + 5000;
  do {
    auto rows =
        db.run("SELECT response FROM runtime_requests WHERE id=?", {req});
    if (!rows[0]["response"].is_null())
      return J::parse(rows[0]["response"].get<std::string>());
    if (!live_worker(db.session(id, project)))
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  } while (now() < deadline);
  return {{"status", "pending"},
          {"request_id", req},
          {"session_id", id},
          {"diagnostic", "command may still execute; do not blindly retry "
                         "state-changing commands"}};
}
int runtime_worker(ProjectStore &store, const std::string &id) {
  Db db(store);
  auto rows = db.run("SELECT record FROM runtime_sessions WHERE id=?", {id});
  if (rows.empty())
    return 2;
  auto session = J::parse(rows[0]["record"].get<std::string>());
  if (session["state"] != "starting")
    return 2;
  auto original = session.dump();
#ifdef _WIN32
  session["worker_pid"] = GetCurrentProcessId();
#else
  session["worker_pid"] = getpid();
#endif
  db.run("UPDATE runtime_sessions SET record=? WHERE id=? AND record=?",
         {session.dump(), id, original});
  if (sqlite3_changes(db.db) != 1)
    return 2;
  if (session["request"]["operation"] == "instrument")
    return instrument_worker(store, db, session);
  if (session["request"]["operation"] == "record" || session["request"]["operation"] == "replay")
    return replay_worker(store,db,session);
  auto backend = make_runtime_backend();
  bool terminal = false;
  auto started = now();
  auto last_save = now();
  bool initializing=true;
  auto save = [&] {
    session["heartbeat_ms"] = now();
    db.save(session);
    last_save = now();
  };
  auto select_context=[&](uint64_t pid) {
    auto &contexts=session["process_contexts"];if(!contexts.is_object())contexts=J::object();
    if(session.contains("pid")&&!session.value("current_process_exited",false)) {auto old=std::to_string(runtime_number(session["pid"]));contexts[old]={{"process_id",session["process_id"]},{"address_space_id",session["address_space_id"]},{"modules",session.value("modules",J::array())},{"threads",session.value("threads",J::array())}};}
    auto key=std::to_string(pid);
    if(!contexts.contains(key))contexts[key]={{"process_id",make_id("proc")},{"address_space_id",make_id("as")},{"modules",J::array()},{"threads",J::array()}};
    auto context=contexts[key];session.update(context);session["pid"]=pid;session["current_process_exited"]=false;
  };
  auto poll = [&](unsigned ms) {
    auto e = backend->poll(ms);
    if (!e.is_null()) {
      auto kind=e.value("kind","");
      auto &contexts=session["process_contexts"];if(!contexts.is_object())contexts=J::object();
      if(kind=="process_created"&&e.contains("event_pid")){
        auto child=runtime_number(e["event_pid"]),current=runtime_number(session.value("pid",J(0)));auto key=std::to_string(child);
        if(child!=current){
          if(contexts.contains(key))db.observe(id,"process_identity_retired",contexts[key]);
          contexts[key]={{"process_id",make_id("proc")},{"address_space_id",make_id("as")},{"modules",J::array()},{"threads",J::array()},{"created_at_ms",now()}};
        }else contexts[key]={{"process_id",session["process_id"]},{"address_space_id",session["address_space_id"]},{"modules",session.value("modules",J::array())},{"threads",session.value("threads",J::array())}};
        J relationship{{"pid",child},{"process_id",contexts[key]["process_id"]},{"address_space_id",contexts[key]["address_space_id"]},{"source","debugger process lifetime notification"}};
        if(e.contains("parent_pid")){auto parent=runtime_number(e["parent_pid"]);relationship["parent_pid"]=parent;if(parent==current)relationship["parent_process_id"]=session["process_id"];else if(contexts.contains(std::to_string(parent)))relationship["parent_process_id"]=contexts[std::to_string(parent)]["process_id"];}
        db.observe(id,"process_created",relationship);e["identity"]=relationship;
      }
      if(kind=="process_lifetime_exited"&&(e.contains("event_pid")||e.contains("exited_pid"))){auto exited=runtime_number(e.value("event_pid",e.value("exited_pid",J(0))));auto key=std::to_string(exited);if(contexts.contains(key)){e["retired_identity"]=contexts[key];db.observe(id,"process_identity_retired",contexts[key]);contexts.erase(key);}if(exited==runtime_number(session.value("pid",J(0))))session["current_process_exited"]=true;}
      if(backend->stopped()&&backend->pid()!=runtime_number(session.value("pid",J(0))))select_context(backend->pid());
      if (e.value("kind", "") == "thread_exited" ||
          e.value("kind", "") == "thread_created") {
        auto native_id = e.value("new_thread_id", e.value("thread_id", J{}));
        auto &threads = session["threads"];
        if (threads.is_array())
          for (auto it = threads.begin(); it != threads.end();) {
            if ((*it)["thread_id"] == native_id) {
              e["thread_instance_id"] = (*it).value("id", J{});
              db.observe(id, "thread_exited", *it);
              it = threads.erase(it);
            } else
              ++it;
          }
      }
      if (e.value("kind", "") == "module_unloaded") {
        auto &mods = session["modules"];
        if (mods.is_array())
          for (auto it = mods.begin(); it != mods.end();)
            if ((*it)["base"] == e["base"]) {
              db.observe(id, "module_unloaded", *it);
              it = mods.erase(it);
            } else
              ++it;
      }
      if (e.value("kind", "") == "exec") {
        session["modules"] = J::array();
        session["address_space_id"] = make_id("as");
      }
      session["last_event"] = e;
      session["thread_id"] = backend->thread();
      session["state"] = backend->alive()
                             ? (backend->stopped() ? "stopped" : initializing?"starting":"running")
                             : "exited";
      db.observe(id, "debug_event", e);
      if (backend->stopped())
        refresh_modules(*backend, session, db);
      save();
    }
    return e;
  };
  auto pause = [&] {
    if (backend->alive() && !backend->stopped()) {
      backend->pause();
      auto end = now() + 3000;
      while (backend->alive() && !backend->stopped() && now() < end)
        poll(10);
      if (backend->alive() && !backend->stopped())
        throw std::runtime_error("pause deadline exceeded");
    }
  };
  try {
    auto request = session["request"];
    if (request["operation"] == "launch" &&
        sha256_file(request["file"].get<std::string>()) !=
            request["artifact_sha256"].get<std::string>())
      throw std::runtime_error("launch image changed after import");
    auto info = backend->start(request);
    session.update(info);
    session["modules"] = J::array();
    auto startup_end = now() + 10000;
    while (backend->alive() && !backend->stopped() && now() < startup_end)
      poll(10);
    if (!backend->stopped() && backend->alive())
      throw std::runtime_error("initial debug stop timed out");
    initializing=false;
    session["state"] = backend->alive() ? "stopped" : "exited";
    save();
    db.observe(id, "session_started",
               {{"pid", backend->pid()},
                {"process_id", session["process_id"]},
                {"request", request}});
    while (backend->alive() && !terminal) {
      poll(0);
      if (now() - last_save > 1000)
        save();
      if (now() - started > static_cast<std::int64_t>(bounded(
                                request, "lifetime_ms", 1800000, 86400000))) {
        pause();
        backend->detach(false);
        session["state"] = "detached";
        session["reason"] = "session lifetime expired";
        save();
        break;
      }
      auto queue = db.run("SELECT id,request FROM runtime_requests WHERE "
                          "session=? AND state='queued' ORDER BY rowid LIMIT 1",
                          {id});
      if (queue.empty()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        continue;
      }
      auto qid = queue[0]["id"].get<std::string>();
      auto r = J::parse(queue[0]["request"].get<std::string>());
      db.run("UPDATE runtime_requests SET state='running' WHERE id=?", {qid});
      J response;
      try {
        auto op = r.at("operation").get<std::string>();
        auto timeout = bounded(r, "timeout_ms", 5000, 60000);
        auto thread = runtime_number(r.value("thread", J(0)));
        int signal = r.value("signal", 0);
        if (op == "modules") {
          refresh_modules(*backend, session, db);
          response = {{"modules", session["modules"]}};
        } else if (op == "threads") {
          refresh_modules(*backend, session, db);
          response = {{"threads", session["threads"]}};
        }
        else if (op == "resolve") {
          auto address = resolve_address(store, session, r);
          auto loc = location(session, address);
          response = {{"location", loc}};
          if (loc.contains("anchor_id"))
            response["static_entities"] =
                store.index_query(session["project"].get<std::string>(),
                                  {{"category", "entities"},
                                   {"anchor", loc["anchor_id"]},
                                   {"limit", 100}});
        } else if (op == "registers") {
          response = backend->registers(thread);
          response["observation_id"] =
              db.observe(id, "registers", response)["id"];
        } else if (op == "memory") {
          auto size = bounded(r, "size", 256, 65536);
          auto address = resolve_address(store, session, r);
          if (address > UINT64_MAX - size)
            throw std::runtime_error("memory range overflow");
          response = backend->memory(address, static_cast<std::size_t>(size));
          response["location"] = location(session, address);
          response["observation_id"] = db.observe(id, "memory", response)["id"];
        } else if (op == "capture") {
          refresh_modules(*backend, session, db);
          if (r.contains("static_address") || r.contains("rva") ||
              r.contains("function"))
            r["address"] = hex_address(resolve_address(store, session, r));
          response = db.observe(id, "capture", capture(*backend, session, r));
          response["region_observation_ids"]=J::array();
          for(const auto &region:response["data"].value("code_regions",J::array()))response["region_observation_ids"].push_back(db.observe(id,"code_capture",region)["id"]);
          response["status"] = response["data"].value("status", "partial");
        } else if (op == "validate-witness") {
          if(!backend->stopped())throw std::runtime_error("witness validation requires the original stopped capture state");
          auto records=db.observations(id,{{"id",r.at("observation")},{"limit",1}})["observations"];
          if(records.empty()||records[0]["kind"]!="symbolic")throw std::runtime_error("symbolic evidence required");
          const auto symbolic=records[0];auto captures=db.observations(id,{{"id",symbolic["data"].at("capture_id")},{"limit",1}})["observations"];
          if(captures.empty()||captures[0]["sha256"]!=symbolic["data"].at("capture_sha256"))throw std::runtime_error("capture identity mismatch");
          const auto original=captures[0]["data"];
          if(original.at("location").at("process_id")!=session.at("process_id")||original.at("location").at("address_space_id")!=session.at("address_space_id"))throw std::runtime_error("capture belongs to another process/address space");
          auto current=backend->registers(thread);
          if(current["thread_id"]!=original["registers"]["thread_id"]||current["values"]!=original["registers"]["values"])throw std::runtime_error("register state changed since capture");
          const auto branch=symbolic["data"].at("results").at(r.value("terminal_index",0)).at("branches").at(r.value("branch_index",0));
          if(branch.value("native_verdict","")!="sat"||branch["models"].empty())throw std::runtime_error("SAT witness with explicit inputs required");
          auto pc=runtime_number(current["values"][current["arch"]=="x86"?"eip":"rip"]);
          auto instruction=original.at("instruction_bytes");if(backend->memory(pc,runtime_number(instruction.at("size")))["hex"]!=instruction["hex"])throw std::runtime_error("code changed since capture");
          for(const auto &memory:original.value("memory",J::array()))if(backend->memory(runtime_number(memory.at("address")),runtime_number(memory.at("size")))["hex"]!=memory["hex"])throw std::runtime_error("captured memory changed");
          J code_ranges=original.value("code_regions",J::array());code_ranges.push_back({{"code_bytes",original.at("code_bytes")}});code_ranges.push_back({{"code_bytes",instruction}});
          for(const auto &region:code_ranges){const auto &bytes=region.at("code_bytes");if(backend->memory(runtime_number(bytes.at("address")),runtime_number(bytes.at("size")))["hex"]!=bytes["hex"])throw std::runtime_error("captured path code changed since capture");}
          for(const auto &model:branch["models"]){auto name=model.at("input").get<std::string>();if(name.starts_with("memory_")){auto address=runtime_number(name.substr(7));for(const auto &region:code_ranges){const auto &bytes=region.at("code_bytes");auto begin=runtime_number(bytes.at("address"));if(address>=begin&&address-begin<runtime_number(bytes.at("size")))throw std::runtime_error("witness input overlaps captured code; binary patching is not validation");}}}
          db.observe(id,"witness_validation_started",{{"symbolic_observation",symbolic["id"]},{"branch",branch},{"effect","applies model inputs and advances current target; not replay/restoration"}});
          backend->control("apply-inputs",{{"thread",thread},{"models",branch["models"]}});
          auto target=runtime_number(branch.at("target"));auto end=now()+static_cast<int64_t>(timeout);uint64_t steps=0,max=bounded(r,"max_steps",128,10000);bool reached=false;
          auto generation=db.run("SELECT cancel FROM runtime_sessions WHERE id=?",{id})[0]["cancel"];
          while(backend->alive()&&backend->stopped()&&steps<max&&now()<end){if(db.run("SELECT cancel FROM runtime_sessions WHERE id=?",{id})[0]["cancel"]!=generation)break;auto regs=backend->registers(thread);auto at=runtime_number(regs["values"][regs["arch"]=="x86"?"eip":"rip"]);if(steps&&at==target){reached=true;break;}backend->resume(true,thread,0);++steps;while(backend->alive()&&!backend->stopped()&&now()<end)poll(5);if(backend->stopped()&&session["last_event"].value("kind","")!="step")break;}
          if(backend->alive()&&!backend->stopped())pause();
          if(steps&&backend->alive()&&backend->stopped()){auto final_regs=backend->registers(thread);reached=runtime_number(final_regs["values"][final_regs["arch"]=="x86"?"eip":"rip"])==target;}
          response={{"status",reached?"completed":"partial"},{"verdict",reached?"predicted destination observed":"not reproduced within bounded current-state experiment"},{"steps",steps},{"target",branch["target"]},{"state_changed",true},{"scope","current-state oracle; not entry-point reachability or deterministic replay; uncaptured external state is not restored"}};
          response["observation_id"]=db.observe(id,"witness_validation",response,reached?"validated":"observed")["id"];
        } else if (op == "stack" || op == "breakpoints" || op == "processes") {
          response = backend->control(op,r);
          if(op=="stack")for(auto &frame:response["frames"]){auto address=frame.value("address",frame.value("addr",J{}));if(!address.is_null())frame["location"]=location(session,runtime_number(address));}
          if(op=="processes"){
            if(!response.contains("processes")){response["processes"]=J::array();for(auto group:response.value("groups",J::array()))if(group.contains("pid")){group["pid"]=runtime_number(group["pid"]);response["processes"].push_back(group);}}
            for(auto &process:response["processes"]){auto pid=runtime_number(process.at("pid"));auto key=std::to_string(pid);if(pid==runtime_number(session["pid"])){process["process_id"]=session["process_id"];process["address_space_id"]=session["address_space_id"];}else if(session.value("process_contexts",J::object()).contains(key)){process["process_id"]=session["process_contexts"][key]["process_id"];process["address_space_id"]=session["process_contexts"][key]["address_space_id"];}else process["identity_status"]="not yet observed in a process lifetime notification";}
          }
          response["observation_id"] = db.observe(id,op,response)["id"];
        } else if (op == "crash") {
          response={{"event",session.value("last_event",J{})},{"registers",backend->registers(thread)},{"stack",backend->control("stack",r)},{"scope","current stopped event; not every stop is a crash"}};
          response["observation_id"]=db.observe(id,"crash_inspection",response)["id"];
        } else if (op == "select-process") {
          response=backend->control(op,r);
          select_context(backend->pid());
          refresh_modules(*backend,session,db);db.observe(id,"process_selected",response);
        } else if (op == "breakpoint" || op == "remove-breakpoint" || op == "watchpoint") {
          if(!r.contains("expression")&&!r.contains("breakpoint_id"))r["address"]=hex_address(resolve_address(store,session,r));
          response=backend->control(op,r);
          if(r.contains("address"))response["location"]=location(session,runtime_number(r["address"]));
          db.observe(id, op, response);
        } else if (op == "pause") {
          pause();
          response = session;
        } else if (op == "detach" || op == "terminate") {
          pause();
          backend->detach(op == "terminate");
          terminal = true;
          session["state"] = op == "terminate" ? "terminated" : "detached";
          response = {{"state", session["state"]}};
          db.observe(id, op, response);
        } else if (op == "continue" || op == "step" || op == "step-over" || op == "step-out") {
          if(op=="step-over"||op=="step-out")backend->control(op,r);else backend->resume(op == "step", thread, signal);
          session["state"] = "running";
          if (op != "continue" || r.value("wait", false)) {
            auto end = now() + static_cast<std::int64_t>(timeout);
            while (backend->alive() && !backend->stopped() && now() < end)
              poll(5);
            if (!backend->stopped() && backend->alive()) {
              pause();
              response["status"] = "partial";
              response["reason"] = "wait budget exhausted; target paused";
            }
          }
          response["state"] = session["state"];
          response["last_event"] = session.value("last_event", J{});
        } else if (op == "trace") {
          if (!backend->stopped())
            throw std::runtime_error("trace requires a stopped session");
          auto steps = bounded(r, "max_steps", 128, 10000);
          auto end = now() + static_cast<std::int64_t>(timeout);
          auto generation =
              db.run("SELECT cancel FROM runtime_sessions WHERE id=?",
                     {id})[0]["cancel"];
          auto traceid = make_id("trace");
          J observations = J::array();
          std::string reason = "step_limit";
          std::uint64_t count = 0;
          for (; count < steps && backend->alive() && backend->stopped();) {
            if (now() >= end) {
              reason = "time_limit";
              break;
            }
            if (db.run("SELECT cancel FROM runtime_sessions WHERE id=?",
                       {id})[0]["cancel"] != generation) {
              reason = "cancelled";
              break;
            }
            auto regs = backend->registers(thread);
            auto pc = runtime_number(
                regs["values"][regs["arch"] == "x86" ? "eip" : "rip"]);
            if (r.contains("from") && pc < runtime_number(r["from"])) {
              reason = "outside_range";
              break;
            }
            if (r.contains("to") && pc >= runtime_number(r["to"])) {
              reason = "outside_range";
              break;
            }
            J data{{"trace_id", traceid},
                   {"step", count},
                   {"location", location(session, pc)},
                   {"registers", regs},
                   {"instruction_bytes", backend->memory(pc, 15)}};
            data["code_bytes"] = data["instruction_bytes"];
            data["arch"] = regs["arch"];
            data["code_epoch"] = runtime_code_epoch(
                session, data["location"], data["instruction_bytes"],
                "debugger step observation");
            auto observation = db.observe(id, "trace_step", data);
            ++count;
            if (observations.size() < 256)
              observations.push_back(observation["id"]);
            backend->resume(true, thread, 0);
            session["state"] = "running";
            while (backend->alive() && !backend->stopped() && now() < end) {
              poll(1);
              if (db.run("SELECT cancel FROM runtime_sessions WHERE id=?",
                         {id})[0]["cancel"] != generation) {
                reason = "cancelled";
                pause();
                break;
              }
            }
            if (reason == "cancelled")
              break;
            if (!backend->alive()) {
              reason = "process_exited";
              break;
            }
            if (!backend->stopped()) {
              pause();
              reason = "time_limit";
              break;
            }
            if (session["last_event"].value("kind", "") != "step") {
              reason = "debug_event";
              break;
            }
          }
          response = {
              {"trace_id", traceid},
              {"steps", count},
              {"observation_ids", observations},
              {"reason", reason},
              {"status", reason == "cancelled" ? "cancelled" : "partial"},
              {"scope", "bounded selected-thread stepping; not a complete "
                        "execution trace"}};
          db.observe(id, "trace_summary", response);
        }
        if (!response.contains("status"))
          response["status"] = "completed";
      } catch (const std::exception &e) {
        response = {{"status", "failed"}, {"diagnostic", e.what()}};
      }
      response["schema"] = "indago.runtime-result.v1";
      response["session_id"] = id;
      response["request_id"] = qid;
      save();
      if (response.dump().size() > 2 * 1024 * 1024)
        response = {
            {"status", "partial"},
            {"session_id", id},
            {"request_id", qid},
            {"diagnostic",
             "runtime response exceeds 2 MiB; use bounded observations"}};
      db.run(
          "UPDATE runtime_requests SET state='finished',response=? WHERE id=?",
          {response.dump(), qid});
    }
    if (!terminal && session["state"] != "detached")
      session["state"] = "exited";
    db.observe(
        id, "collection_closed",
        {{"state", session["state"]},
         {"coverage",
          "end of collection, not proof of every module/thread native exit"}});
    save();
    return 0;
  } catch (const std::exception &e) {
    session["state"] = "failed";
    session["diagnostic"] = e.what();
    try {
      pause();
      backend->detach(false);
    } catch (const std::exception &cleanup) {
      session["cleanup_diagnostic"] = cleanup.what();
    }
    save();
    return 1;
  }
}
} // namespace indago
