#include "indago/core.hpp"
#include "indago/contracts.hpp"
#include "indago/static_index.hpp"
#include "indago/storage_lease.hpp"
#include <sqlite3.h>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <random>
#include <sstream>
#include <stdexcept>

namespace indago {
using Json = nlohmann::json;
namespace {
std::int64_t epoch_ms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
void validate_name(std::string_view value) {
    if (value.empty() || value.size() > 128) throw std::runtime_error("invalid identifier length");
    for (unsigned char ch : value)
        if (!(std::isalnum(ch) || ch == '-' || ch == '_')) throw std::runtime_error("identifiers must contain letters, digits, '-' or '_'");
}
struct Db {
    StorageLease storage;
    sqlite3* p{};
    explicit Db(const fs::path& path):storage(path.parent_path()) {
        const auto utf8=path.u8string();
        if (sqlite3_open(reinterpret_cast<const char*>(utf8.c_str()), &p) != SQLITE_OK) {
            const std::string error = p ? sqlite3_errmsg(p) : "cannot open database";
            if (p) sqlite3_close(p);
            throw std::runtime_error(error);
        }
        sqlite3_busy_timeout(p, 10000);
        exec("PRAGMA foreign_keys=ON");
    }
    ~Db() { sqlite3_close(p); }
    void exec(const char* sql) {
        char* error{};
        if (sqlite3_exec(p, sql, nullptr, nullptr, &error) != SQLITE_OK) {
            std::string message = error ? error : sqlite3_errmsg(p);
            sqlite3_free(error);
            throw std::runtime_error(message);
        }
    }
};
struct Statement {
    sqlite3_stmt* p{};
    explicit Statement(Db& db, const char* sql) {
        if (sqlite3_prepare_v2(db.p, sql, -1, &p, nullptr) != SQLITE_OK) throw std::runtime_error(sqlite3_errmsg(db.p));
    }
    ~Statement() { sqlite3_finalize(p); }
    Statement& bind(int index, std::string_view value) {
        if (sqlite3_bind_text(p, index, value.empty() ? "" : value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK) throw std::runtime_error("SQL bind failed");
        return *this;
    }
    Statement& number(int index, std::int64_t value) { sqlite3_bind_int64(p, index, value); return *this; }
    bool row() {
        int code = sqlite3_step(p);
        if (code == SQLITE_ROW) return true;
        if (code == SQLITE_DONE) return false;
        throw std::runtime_error(sqlite3_errmsg(sqlite3_db_handle(p)));
    }
    std::string text(int index) const {
        const auto* value = sqlite3_column_text(p, index);
        return value ? reinterpret_cast<const char*>(value) : "";
    }
};
std::string read_text(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open " + path.string());
    return {std::istreambuf_iterator<char>(input), {}};
}
fs::path object_path(const fs::path& root, std::string_view hash) {
    if (hash.size() != 64 || hash.find_first_not_of("0123456789abcdef") != std::string_view::npos) throw std::runtime_error("invalid SHA-256");
    return root / "objects" / "sha256" / std::string(hash.substr(0,2)) / std::string(hash.substr(2));
}
std::string publish_blob(const fs::path& root, std::string_view bytes) {
    const auto staged = root / "staging" / make_id("blob");
    atomic_write(staged, bytes);
    const auto hash = sha256_file(staged);
    const auto dest = object_path(root, hash);
    fs::create_directories(dest.parent_path());
    if (!fs::exists(dest)) {
        std::error_code ec;
        fs::rename(staged, dest, ec);
        if (ec && !fs::exists(dest)) throw std::runtime_error("cannot publish content: " + ec.message());
    }
    fs::remove(staged);
    if (sha256_file(dest) != hash) throw std::runtime_error("content store integrity failure");
    return hash;
}
Json parse_json(std::string_view value) { return Json::parse(value); }
std::string canonical_address(const Json& value) {
    if (value.is_number_unsigned()) return hex_address(value.get<std::uint64_t>());
    if (!value.is_string()) return {};
    auto text = value.get<std::string>();
    if (text.starts_with("0x")) text.erase(0,2);
    std::uint64_t number{};
    auto result = std::from_chars(text.data(), text.data()+text.size(), number, 16);
    return result.ec == std::errc{} && result.ptr == text.data()+text.size() ? hex_address(number) : "";
}
void collect_functions(const Json& value, std::vector<Json>& result, unsigned depth=0) {
    if (depth > 12) return;
    if (value.is_object()) {
        if (value.contains("functions") && value["functions"].is_array()) {
            for (const auto& item : value["functions"]) if (item.is_object()) result.push_back(item);
        }
        if (value.contains("function") && value["function"].is_object()) result.push_back(value["function"]);
        for (auto it = value.begin(); it != value.end(); ++it) {
            if (it.key() != "functions" && it.key() != "function") collect_functions(it.value(), result, depth+1);
        }
    } else if (value.is_array()) for (const auto& item : value) collect_functions(item, result, depth+1);
}
void require_project(Db& db, std::string_view name) {
    validate_name(name);
    Statement query(db, "SELECT name FROM projects WHERE name=?");
    if (!query.bind(1,name).row()) throw std::runtime_error("unknown project: " + std::string(name));
}
Json persist_index(Db& db,const TargetRecord& target,const Json& job,std::string_view backend,std::string_view evidence,const Json& native,std::string_view source_status){
    Json layout=Json::object();Statement mapping(db,"SELECT record FROM artifact_layouts WHERE project=? AND artifact=? ORDER BY rowid DESC LIMIT 1");mapping.bind(1,target.project).bind(2,target.sha256);if(mapping.row())layout=parse_json(mapping.text(0));
    auto index=normalize_static(target,job,backend,evidence,native,layout);
    // Publication status is authoritative for this result, independently of any
    // backend-native status vocabulary. Never rewrite the immutable native JSON.
    const bool projection_partial=index.at("partial").get<bool>();
    const bool source_incomplete=source_status!="completed";
    index["partial"]=projection_partial||source_incomplete;
    for(const auto* collection:{"entities","relations","claims"})for(auto& record:index[collection]){
        record["source_status"]=source_status;record["source_result_incomplete"]=source_incomplete;
        record["projection_partial"]=projection_partial;record["partial"]=index["partial"];
    }
    const auto revision=job.at("revision").get<std::string>();
    const auto& request=job.at("request");
    const auto scope=sha256_text(Json::array({target.sha256,backend,request.at("operation"),request.value("address",std::string{}),request.value("view",std::string("compact")),request.value("arguments",Json::object())}).dump());
    Statement rev(db,"INSERT OR IGNORE INTO indexed_revisions VALUES(?,?,?,?,?,?,?)");rev.bind(1,revision).bind(2,target.project).bind(3,target.sha256).bind(4,backend).bind(5,evidence).bind(6,scope).bind(7,Json{{"revision",revision},{"artifact_sha256",target.sha256},{"producer",backend},{"evidence_id",evidence},{"scope",scope},{"request",request},{"provenance",native.value("provenance",Json::object())},{"partial",index["partial"]},{"source_status",source_status},{"source_result_incomplete",source_incomplete},{"projection_partial",projection_partial},{"backend_program_revision",native.value("program_revision",Json{})}}.dump()).row();
    // A failed retry is not new knowledge and must not hide an earlier view.
    if(source_status=="completed"||source_status=="partial"){
        if(native.contains("program")&&native["program"].contains("segments")){auto map=native["program"];map["mapping_evidence_id"]=evidence;Statement save(db,"INSERT OR IGNORE INTO artifact_layouts VALUES(?,?,?,?)");save.bind(1,target.project).bind(2,target.sha256).bind(3,revision).bind(4,map.dump()).row();}
        Statement head(db,"INSERT INTO analysis_heads VALUES(?,?,?) ON CONFLICT(project,scope) DO UPDATE SET revision=excluded.revision");head.bind(1,target.project).bind(2,scope).bind(3,revision).row();
    }
    for(const auto& e:index["entities"]){
        const auto loc=e["location"];Statement q(db,"INSERT OR IGNORE INTO static_entities VALUES(?,?,?,?,?,?,?,?,?,?,?)");
        q.bind(1,e["id"].get<std::string>()).bind(2,target.project).bind(3,target.sha256).bind(4,revision).bind(5,backend).bind(6,e["kind"].get<std::string>()).bind(7,e["name"].get<std::string>()).bind(8,loc.is_object()?loc.value("address",std::string{}):"").bind(9,loc.is_object()?loc.value("anchor_id",std::string{}):"").bind(10,evidence).bind(11,e.dump()).row();
    }
    for(const auto& e:index["relations"]){
        Statement q(db,"INSERT OR IGNORE INTO static_relations VALUES(?,?,?,?,?,?,?,?,?,?,?)");
        q.bind(1,e["id"].get<std::string>()).bind(2,target.project).bind(3,target.sha256).bind(4,revision).bind(5,backend).bind(6,e["kind"].get<std::string>()).bind(7,e["source_entity"].is_string()?e["source_entity"].get<std::string>():"").bind(8,e["target_entity"].is_string()?e["target_entity"].get<std::string>():"").bind(9,e["source_location"].is_object()?e["source_location"].value("anchor_id",std::string{}):"").bind(10,e["target_location"].is_object()?e["target_location"].value("anchor_id",std::string{}):"").bind(11,e.dump()).row();
    }
    for(const auto& e:index["claims"]){
        Statement q(db,"INSERT OR IGNORE INTO static_claims VALUES(?,?,?,?,?,?,?,?,?)");q.bind(1,e["id"].get<std::string>()).bind(2,target.project).bind(3,target.sha256).bind(4,revision).bind(5,backend).bind(6,e["subject"].get<std::string>()).bind(7,e["predicate"].get<std::string>()).bind(8,evidence).bind(9,e.dump()).row();
    }
    return {{"entities",index["entities"].size()},{"relations",index["relations"].size()},{"claims",index["claims"].size()},{"partial",index["partial"]}};
}
}

std::string json_escape(std::string_view value) {
    const auto encoded = Json(std::string(value)).dump(-1, ' ', false, Json::error_handler_t::replace);
    return encoded.substr(1, encoded.size()-2);
}
std::string quote(std::string_view value) { return Json(std::string(value)).dump(-1, ' ', false, Json::error_handler_t::replace); }
std::string hex_address(std::uint64_t value) { std::ostringstream out; out << "0x" << std::hex << value; return out.str(); }
std::string utc_timestamp() {
    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm time{};
#ifdef _WIN32
    gmtime_s(&time, &now);
#else
    gmtime_r(&now, &time);
#endif
    std::ostringstream out; out << std::put_time(&time, "%Y-%m-%dT%H:%M:%SZ"); return out.str();
}
std::string make_id(std::string_view prefix) {
    static std::mutex lock;
    static std::mt19937_64 generator(std::random_device{}());
    std::lock_guard guard(lock);
    std::ostringstream out; out << prefix << '_' << std::hex << std::setfill('0') << std::setw(16) << generator() << std::setw(16) << generator(); return out.str();
}
void atomic_write(const fs::path& destination, std::string_view content) {
    fs::create_directories(destination.parent_path());
    auto temp = destination;
    temp += ".tmp-" + make_id("write");
    try {
        { std::ofstream out(temp, std::ios::binary); out.write(content.data(), static_cast<std::streamsize>(content.size())); out.flush(); if (!out) throw std::runtime_error("cannot write staging file"); }
        fs::rename(temp, destination);
    } catch (...) { fs::remove(temp); throw; }
}
ProjectStore::ProjectStore(fs::path root): root_(fs::absolute(std::move(root)).lexically_normal()) {}
void ProjectStore::initialize() const {
    fs::create_directories(root_ / "objects" / "sha256");
    fs::create_directories(root_ / "projects"); fs::create_directories(root_ / "staging"); fs::create_directories(root_ / "jobs");
    Db db(root_ / "indago-native.sqlite3");
    {Statement version(db,"PRAGMA user_version");version.row();if(sqlite3_column_int(version.p,0)>7)throw std::runtime_error("workspace schema is newer than this executable");}
    db.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;");
    db.exec(R"sql(
      CREATE TABLE IF NOT EXISTS projects(name TEXT PRIMARY KEY,id TEXT UNIQUE NOT NULL,created TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS targets(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(name),sha TEXT NOT NULL,name TEXT NOT NULL,size INTEGER NOT NULL,created TEXT NOT NULL,UNIQUE(project,sha));
      CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(name),target TEXT NOT NULL REFERENCES targets(id),revision TEXT UNIQUE NOT NULL,status TEXT NOT NULL,request TEXT NOT NULL,created TEXT NOT NULL,finished TEXT,result TEXT);
      CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(name),job TEXT REFERENCES jobs(id),revision TEXT NOT NULL,backend TEXT NOT NULL,sha TEXT NOT NULL,status TEXT NOT NULL,record TEXT NOT NULL,created TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS functions(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(name),artifact TEXT NOT NULL,address TEXT NOT NULL,UNIQUE(project,artifact,address));
      CREATE TABLE IF NOT EXISTS function_views(function TEXT NOT NULL REFERENCES functions(id),evidence TEXT NOT NULL REFERENCES evidence(id),backend TEXT NOT NULL,record TEXT NOT NULL,PRIMARY KEY(function,evidence));
      CREATE INDEX IF NOT EXISTS evidence_project ON evidence(project,created);
      CREATE INDEX IF NOT EXISTS jobs_project ON jobs(project,created);
    )sql");
    db.exec(R"sql(
      BEGIN IMMEDIATE;
      CREATE TABLE IF NOT EXISTS idempotency(project TEXT NOT NULL REFERENCES projects(name),key TEXT NOT NULL,request TEXT NOT NULL,job TEXT NOT NULL REFERENCES jobs(id),PRIMARY KEY(project,key));
      CREATE TABLE IF NOT EXISTS job_leases(job TEXT PRIMARY KEY REFERENCES jobs(id),token TEXT NOT NULL,deadline INTEGER NOT NULL,heartbeat INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS job_events(sequence INTEGER PRIMARY KEY AUTOINCREMENT,job TEXT NOT NULL REFERENCES jobs(id),kind TEXT NOT NULL,at TEXT NOT NULL,detail TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS job_events_job ON job_events(job,sequence);
      CREATE TABLE IF NOT EXISTS indexed_revisions(revision TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(name),artifact TEXT NOT NULL,backend TEXT NOT NULL,evidence TEXT NOT NULL REFERENCES evidence(id),scope TEXT NOT NULL,record TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS artifact_layouts(project TEXT NOT NULL REFERENCES projects(name),artifact TEXT NOT NULL,revision TEXT NOT NULL REFERENCES indexed_revisions(revision),record TEXT NOT NULL,PRIMARY KEY(project,artifact,revision));
      CREATE TABLE IF NOT EXISTS analysis_heads(project TEXT NOT NULL REFERENCES projects(name),scope TEXT NOT NULL,revision TEXT NOT NULL REFERENCES indexed_revisions(revision),PRIMARY KEY(project,scope));
      CREATE TABLE IF NOT EXISTS static_entities(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(name),artifact TEXT NOT NULL,revision TEXT NOT NULL REFERENCES indexed_revisions(revision),backend TEXT NOT NULL,kind TEXT NOT NULL,name TEXT NOT NULL,address TEXT NOT NULL,anchor TEXT NOT NULL,evidence TEXT NOT NULL REFERENCES evidence(id),record TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS static_relations(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(name),artifact TEXT NOT NULL,revision TEXT NOT NULL REFERENCES indexed_revisions(revision),backend TEXT NOT NULL,kind TEXT NOT NULL,source TEXT NOT NULL,target TEXT NOT NULL,source_anchor TEXT NOT NULL,target_anchor TEXT NOT NULL,record TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS static_claims(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(name),artifact TEXT NOT NULL,revision TEXT NOT NULL REFERENCES indexed_revisions(revision),backend TEXT NOT NULL,subject TEXT NOT NULL REFERENCES static_entities(id),predicate TEXT NOT NULL,evidence TEXT NOT NULL REFERENCES evidence(id),record TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS entity_location ON static_entities(project,artifact,address,kind);
      CREATE INDEX IF NOT EXISTS entity_name ON static_entities(project,kind,name);
      CREATE INDEX IF NOT EXISTS entity_anchor ON static_entities(project,anchor);
      CREATE INDEX IF NOT EXISTS relation_source ON static_relations(project,source,kind);
      CREATE INDEX IF NOT EXISTS relation_target ON static_relations(project,target,kind);
      CREATE INDEX IF NOT EXISTS relation_source_anchor ON static_relations(project,source_anchor,kind);
      CREATE INDEX IF NOT EXISTS relation_target_anchor ON static_relations(project,target_anchor,kind);
      CREATE INDEX IF NOT EXISTS claims_subject ON static_claims(project,subject,predicate);
      CREATE TABLE IF NOT EXISTS artifact_derivations(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(name),artifact TEXT NOT NULL,record TEXT NOT NULL,sha TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS derivation_artifact ON artifact_derivations(project,artifact);
      PRAGMA user_version=7;
      COMMIT;
    )sql");
    // Import the previous native prototype's manifests without modifying them.
    for (const auto& entry : fs::directory_iterator(root_ / "projects")) {
        if (!entry.is_directory() || !fs::is_regular_file(entry.path()/"project.json")) continue;
        const auto project = parse_json(read_text(entry.path()/"project.json"));
        const auto name = project.at("name").get<std::string>(); validate_name(name);
        Statement insert(db,"INSERT OR IGNORE INTO projects VALUES(?,?,?)");
        insert.bind(1,name).bind(2,project.at("id").get<std::string>()).bind(3,project.value("created_at",utc_timestamp())).row();
        std::ifstream input(entry.path()/"targets.jsonl"); std::string line;
        while(std::getline(input,line)) {
            if(line.empty()) continue;
            const auto item = parse_json(line);
            const auto hash = item.at("sha256").get<std::string>();
            if (!fs::is_regular_file(object_path(root_,hash))) continue;
            Statement add(db,"INSERT OR IGNORE INTO targets VALUES(?,?,?,?,?,?)");
            add.bind(1,item.at("id").get<std::string>()).bind(2,name).bind(3,hash).bind(4,item.at("display_name").get<std::string>()).number(5,item.at("size").get<std::int64_t>()).bind(6,item.value("created_at",utc_timestamp())).row();
        }
    }
}
CommandResult ProjectStore::create_project(std::string_view name) const {
    validate_name(name); Db db(root_/"indago-native.sqlite3");
    Json record{{"schema","indago.project.v1"},{"name",name},{"id",make_id("prj")},{"created_at",utc_timestamp()}};
    Statement insert(db,"INSERT INTO projects VALUES(?,?,?)");
    insert.bind(1,name).bind(2,record["id"].get<std::string>()).bind(3,record["created_at"].get<std::string>()).row();
    fs::create_directories(root_/"projects"/std::string(name)/"analyses");
    return {0,"completed",record.dump()};
}
TargetRecord ProjectStore::import_target(std::string_view project,const fs::path& source) const {
    Db db(root_/"indago-native.sqlite3"); require_project(db,project);
    if (!fs::is_regular_file(source)) throw std::runtime_error("target is not a regular file");
    if (fs::file_size(source) > 512ULL*1024*1024) throw std::runtime_error("target exceeds 512 MiB import limit");
    const auto staged=root_/"staging"/make_id("input"); fs::copy_file(source,staged);
    if(fs::file_size(staged)>512ULL*1024*1024){fs::remove(staged);throw std::runtime_error("copied target exceeds import limit");}
    const auto hash=sha256_file(staged); const auto size=fs::file_size(staged); const auto dest=object_path(root_,hash);
    fs::create_directories(dest.parent_path());
    if (!fs::exists(dest)) { std::error_code ec; fs::rename(staged,dest,ec); if(ec && !fs::exists(dest)) throw std::runtime_error(ec.message()); }
    fs::remove(staged);
    if (sha256_file(dest)!=hash) throw std::runtime_error("content store corruption");
    Statement add(db,"INSERT OR IGNORE INTO targets VALUES(?,?,?,?,?,?)");
    add.bind(1,make_id("tgt")).bind(2,project).bind(3,hash).bind(4,source.filename().string()).number(5,static_cast<std::int64_t>(size)).bind(6,utc_timestamp()).row();
    Statement get(db,"SELECT id FROM targets WHERE project=? AND sha=?"); get.bind(1,project).bind(2,hash).row();
    return target(project,get.text(0));
}
TargetRecord ProjectStore::target(std::string_view project,std::string_view id,bool verify) const {
    Db db(root_/"indago-native.sqlite3"); require_project(db,project);
    Statement q(db,"SELECT id,sha,name,size FROM targets WHERE project=? AND (id=? OR ?='') ORDER BY rowid DESC LIMIT 1");
    q.bind(1,project).bind(2,id).bind(3,id); if(!q.row()) throw std::runtime_error("project has no matching target");
    TargetRecord result{q.text(0),std::string(project),q.text(1),q.text(2),static_cast<std::uintmax_t>(sqlite3_column_int64(q.p,3)),object_path(root_,q.text(1))};
    if(verify && sha256_file(result.object_path)!=result.sha256) throw std::runtime_error("artifact integrity check failed");
    return result;
}
TargetRecord ProjectStore::latest_target(std::string_view project) const { return target(project,{}); }
void ProjectStore::record_derivation(const TargetRecord& target,const Json& lineage) const {
    Db db(root_/"indago-native.sqlite3");require_project(db,target.project);
    auto raw=lineage.dump(), hash=sha256_text(raw);
    Statement add(db,"INSERT OR IGNORE INTO artifact_derivations VALUES(?,?,?,?,?)");
    add.bind(1,"der_"+hash).bind(2,target.project).bind(3,target.sha256).bind(4,raw).bind(5,hash).row();
}
Json ProjectStore::derivations(std::string_view project,std::string_view artifact) const {
    Db db(root_/"indago-native.sqlite3");require_project(db,project);
    Statement q(db,"SELECT record,sha FROM artifact_derivations WHERE project=? AND artifact=? ORDER BY rowid LIMIT 100");
    q.bind(1,project).bind(2,artifact);Json out=Json::array();
    while(q.row()){if(sha256_text(q.text(0))!=q.text(1))throw std::runtime_error("derivation integrity mismatch");out.push_back(Json::parse(q.text(0)));}
    return out;
}
fs::path ProjectStore::analysis_path(std::string_view project,std::string_view id) const { validate_name(project); validate_name(id); return root_/"projects"/std::string(project)/"analyses"/(std::string(id)+".json"); }
fs::path ProjectStore::cancellation_path(std::string_view job) const { validate_name(job); return root_/"jobs"/(std::string(job)+".cancel"); }
Json ProjectStore::project_info(std::string_view project) const {
    Db db(root_/"indago-native.sqlite3"); require_project(db,project);
    Statement q(db,"SELECT id,created FROM projects WHERE name=?"); q.bind(1,project).row();
    Json result{{"schema","indago.project.v1"},{"name",project},{"id",q.text(0)},{"created_at",q.text(1)},{"targets",Json::array()}};
    Statement t(db,"SELECT id,sha,name,size FROM targets WHERE project=? ORDER BY rowid"); t.bind(1,project);
    while(t.row()) result["targets"].push_back({{"id",t.text(0)},{"artifact_sha256",t.text(1)},{"name",t.text(2)},{"size",sqlite3_column_int64(t.p,3)}});
    return result;
}
Json ProjectStore::start_job(const TargetRecord& target,const Json& request) const {
    Db db(root_/"indago-native.sqlite3");
    db.exec("BEGIN IMMEDIATE");
    const auto key=request.value("idempotency_key",std::string{});
    if(!key.empty()){
        Statement old(db,"SELECT request,job FROM idempotency WHERE project=? AND key=?");old.bind(1,target.project).bind(2,key);
        if(old.row()){if(old.text(0)!=request.dump())throw std::runtime_error("idempotency key reused with different request");const auto id=old.text(1);db.exec("COMMIT");return job_info(target.project,id)["jobs"][0];}
    }
    Json job{{"id",make_id("job")},{"revision",make_id("rev")},{"status","queued"},{"request",request},{"created_at",utc_timestamp()}};
    Statement add(db,"INSERT INTO jobs(id,project,target,revision,status,request,created) VALUES(?,?,?,?,?,?,?)");
    add.bind(1,job["id"].get<std::string>()).bind(2,target.project).bind(3,target.id).bind(4,job["revision"].get<std::string>()).bind(5,"queued").bind(6,request.dump()).bind(7,job["created_at"].get<std::string>()).row();
    if(!key.empty()){Statement once(db,"INSERT INTO idempotency VALUES(?,?,?,?)");once.bind(1,target.project).bind(2,key).bind(3,request.dump()).bind(4,job["id"].get<std::string>()).row();}
    Statement event(db,"INSERT INTO job_events(job,kind,at,detail) VALUES(?,'queued',?,'{}')");event.bind(1,job["id"].get<std::string>()).bind(2,utc_timestamp()).row();
    db.exec("COMMIT");
    return job;
}
Json ProjectStore::claim_job(std::string_view project,std::string_view id) const {
    Db db(root_/"indago-native.sqlite3");db.exec("BEGIN IMMEDIATE");
    Statement q(db,"SELECT status FROM jobs WHERE project=? AND id=?");if(!q.bind(1,project).bind(2,id).row())throw std::runtime_error("unknown job");
    if(q.text(0)!="queued" && q.text(0)!="running")throw std::runtime_error("job is terminal; submit a new request to retry");
    const auto token=make_id("lease");Statement lease(db,"INSERT OR IGNORE INTO job_leases VALUES(?,?,?,?)");lease.bind(1,id).bind(2,token).number(3,epoch_ms()+30000).number(4,epoch_ms()).row();
    if(sqlite3_changes(db.p)!=1)throw std::runtime_error("job already has an owner; recover expired leases explicitly");
    Statement update(db,"UPDATE jobs SET status='running' WHERE id=?");update.bind(1,id).row();
    Statement ev(db,"INSERT INTO job_events(job,kind,at,detail) VALUES(?,'started',?,'{}')");ev.bind(1,id).bind(2,utc_timestamp()).row();db.exec("COMMIT");
    auto job=job_info(project,id)["jobs"][0];job["lease_token"]=token;return job;
}
void ProjectStore::heartbeat(std::string_view id,std::string_view token) const {
    Db db(root_/"indago-native.sqlite3");Statement q(db,"UPDATE job_leases SET heartbeat=?,deadline=? WHERE job=? AND token=?");q.number(1,epoch_ms()).number(2,epoch_ms()+30000).bind(3,id).bind(4,token).row();
    if(sqlite3_changes(db.p)!=1)throw std::runtime_error("job lease lost");
}
Json ProjectStore::recover_jobs(std::string_view project) const {
    Db db(root_/"indago-native.sqlite3");require_project(db,project);db.exec("BEGIN IMMEDIATE");
    Statement q(db,"SELECT jobs.id FROM jobs LEFT JOIN job_leases ON jobs.id=job_leases.job WHERE jobs.project=? AND jobs.status='running' AND (job_leases.deadline IS NULL OR job_leases.deadline<?)");q.bind(1,project).number(2,epoch_ms());Json ids=Json::array();while(q.row())ids.push_back(q.text(0));
    for(const auto& id:ids){Statement u(db,"UPDATE jobs SET status='interrupted',finished=? WHERE id=?");u.bind(1,utc_timestamp()).bind(2,id.get<std::string>()).row();Statement ev(db,"INSERT INTO job_events(job,kind,at,detail) VALUES(?,'interrupted',?,'{\"reason\":\"expired worker lease\"}')");ev.bind(1,id.get<std::string>()).bind(2,utc_timestamp()).row();Statement d(db,"DELETE FROM job_leases WHERE job=?");d.bind(1,id.get<std::string>()).row();}
    db.exec("COMMIT");return {{"schema","indago.recovery.v1"},{"interrupted_jobs",ids},{"replayed",false}};
}
Json ProjectStore::job_events(std::string_view project,std::string_view id) const {
    job_info(project,id);Db db(root_/"indago-native.sqlite3");Statement q(db,"SELECT sequence,kind,at,detail FROM job_events WHERE job=? ORDER BY sequence LIMIT 1000");q.bind(1,id);Json rows=Json::array();while(q.row())rows.push_back({{"sequence",sqlite3_column_int64(q.p,0)},{"kind",q.text(1)},{"at",q.text(2)},{"detail",parse_json(q.text(3))}});return {{"schema","indago.job-events.v1"},{"events",rows}};
}
Json ProjectStore::publish_result(const TargetRecord& target,const Json& job,std::string_view backend,const CommandResult& result) const {
    Db db(root_/"indago-native.sqlite3"); db.exec("BEGIN IMMEDIATE");
    Statement check(db,"SELECT request,result,status FROM jobs WHERE id=? AND project=? AND target=? AND revision=?");
    check.bind(1,job.at("id").get<std::string>()).bind(2,target.project).bind(3,target.id).bind(4,job.at("revision").get<std::string>());
    if(!check.row()||parse_json(check.text(0))!=job["request"]||job["request"]["backend"].get<std::string>()!=backend||job["request"]["artifact_sha256"]!=target.sha256)throw std::runtime_error("job publication identity mismatch");
    if(!check.text(1).empty()){auto prior=parse_json(check.text(1));db.exec("COMMIT");return prior;}
    if(check.text(2)!="queued"&&check.text(2)!="running")throw std::runtime_error("cannot publish into terminal job");
    Statement lease(db,"SELECT token,deadline FROM job_leases WHERE job=?");lease.bind(1,job.at("id").get<std::string>());
    if(lease.row()&&(lease.text(0)!=job.value("lease_token",std::string{})||sqlite3_column_int64(lease.p,1)<epoch_ms()))throw std::runtime_error("publication requires live owned lease");
    const auto native=parse_json(result.json);
    const auto hash=publish_blob(root_,result.json);
    const auto evidence_id=make_id("ev");
    const auto revision=job.at("revision").get<std::string>(); const auto job_id=job.at("id").get<std::string>();
    Json evidence{{"schema","indago.evidence.v1"},{"id",evidence_id},{"project",target.project},{"revision",revision},{"job_id",job_id},{"producer",backend},{"state","derived"},{"status",result.status},{"artifact_sha256",target.sha256},{"raw_sha256",hash},{"request",job["request"]},{"created_at",utc_timestamp()}};
    Json envelope{{"schema","indago.result.v1"},{"request_id",job_id},{"result_revision",revision},{"status",result.status},{"completeness",result.status=="completed" ? "complete" : (result.status=="partial" ? "partial":"unknown")},{"backend",backend},{"artifact_sha256",target.sha256},{"evidence_ids",Json::array({evidence_id})},{"raw_sha256",hash},{"data",native},{"diagnostics",Json::array()}};
    auto lineage=derivations(target.project,target.sha256);
    if(!lineage.empty()) evidence["artifact_derivations"]=lineage;
    validate_contract("evidence",evidence);validate_contract("result",envelope);
    // All publication rows share one transaction; raw objects are immutable.
    Statement ev(db,"INSERT INTO evidence(id,project,job,revision,backend,sha,status,record,created) VALUES(?,?,?,?,?,?,?,?,?)");
    ev.bind(1,evidence_id).bind(2,target.project).bind(3,job_id).bind(4,revision).bind(5,backend).bind(6,hash).bind(7,result.status).bind(8,evidence.dump()).bind(9,utc_timestamp()).row();
    envelope["index"]=persist_index(db,target,job,backend,evidence_id,native,result.status);
    std::vector<Json> discovered; collect_functions(native,discovered);
    for(const auto& function:discovered) {
        std::string address;
        for(const auto* key:{"entry","address","entry_address"}) if(function.contains(key)) { address=canonical_address(function[key]); if(!address.empty()) break; }
        if(address.empty() && function.contains("location") && function["location"].is_object() && function["location"].contains("address")) address=canonical_address(function["location"]["address"]);
        if(address.empty()) continue;
        if(function.contains("location")&&function["location"].is_object()){
            const auto space=function["location"].value("address_space",Json("program"));
            if(!space.is_null()&&space!="program"&&space!="ram"&&space!="virtual")continue;
        }
        Statement fn(db,"INSERT OR IGNORE INTO functions VALUES(?,?,?,?)");
        fn.bind(1,make_id("fn")).bind(2,target.project).bind(3,target.sha256).bind(4,address).row();
        Statement find(db,"SELECT id FROM functions WHERE project=? AND artifact=? AND address=?"); find.bind(1,target.project).bind(2,target.sha256).bind(3,address).row();
        Json view=function; view["normalized_location"]={{"artifact_sha256",target.sha256},{"address_space","program"},{"address",address}};
        Statement v(db,"INSERT OR REPLACE INTO function_views VALUES(?,?,?,?)"); v.bind(1,find.text(0)).bind(2,evidence_id).bind(3,backend).bind(4,view.dump()).row();
    }
    Statement finish(db,"UPDATE jobs SET status=?,finished=?,result=? WHERE id=? AND project=?");
    finish.bind(1,result.status).bind(2,utc_timestamp()).bind(3,envelope.dump()).bind(4,job_id).bind(5,target.project).row();
    Statement done(db,"INSERT INTO job_events(job,kind,at,detail) VALUES(?,?,?,?)");done.bind(1,job_id).bind(2,result.status).bind(3,utc_timestamp()).bind(4,Json{{"evidence_id",evidence_id}}.dump()).row();
    Statement release(db,"DELETE FROM job_leases WHERE job=?");release.bind(1,job_id).row();db.exec("COMMIT");
    // SQLite is authoritative. A crash while writing this convenience mirror
    // cannot leave a completed job unpublished or force repeated analysis.
    try{if(!fs::exists(analysis_path(target.project,revision)))atomic_write(analysis_path(target.project,revision),envelope.dump(2));}catch(const std::exception&){}
    return envelope;
}
void ProjectStore::append_evidence(std::string_view project,std::string_view record) const {
    validate_name(project);
    // Compatibility entrypoint keeps legacy callers' records; new actions use publish_result.
    auto value=parse_json(record); atomic_write(analysis_path(project,make_id("legacy")),value.dump());
}
Json ProjectStore::job_info(std::string_view project,std::string_view id) const {
    Db db(root_/"indago-native.sqlite3"); require_project(db,project);
    Statement q(db,"SELECT id,revision,status,request,created,finished,result FROM jobs WHERE project=? AND (id=? OR ?='') ORDER BY rowid DESC LIMIT 100"); q.bind(1,project).bind(2,id).bind(3,id);
    Json list=Json::array(); while(q.row()) { Json item{{"id",q.text(0)},{"revision",q.text(1)},{"status",q.text(2)},{"request",parse_json(q.text(3))},{"created_at",q.text(4)},{"finished_at",q.text(5)}}; if(!id.empty()&&!q.text(6).empty()) item["result"]=parse_json(q.text(6));if(id.empty()){item["request"].erase("arguments");item["details_omitted"]=true;}list.push_back(item); }
    if(!id.empty() && list.empty()) throw std::runtime_error("unknown job");
    return {{"schema","indago.jobs.v1"},{"jobs",list}};
}
Json ProjectStore::cancel_job(std::string_view project,std::string_view id) const {
    const auto jobs=job_info(project,id); const auto state=jobs["jobs"][0]["status"].get<std::string>();
    const bool active=state=="running"||state=="queued";
    if(active) { const auto file=cancellation_path(id); if(!fs::exists(file)) atomic_write(file,"cancel\n"); }
    return {{"schema","indago.cancel.v1"},{"job_id",id},{"status",active?"cancellation_requested":state}};
}
Json ProjectStore::evidence(std::string_view project,std::string_view id,std::size_t offset,std::size_t limit) const {
    Db db(root_/"indago-native.sqlite3"); require_project(db,project); limit=std::clamp<std::size_t>(limit,1,1000);
    Statement q(db,"SELECT record,sha FROM evidence WHERE project=? AND (id=? OR ?='') ORDER BY rowid LIMIT ? OFFSET ?"); q.bind(1,project).bind(2,id).bind(3,id).number(4,limit+1).number(5,offset);
    Json rows=Json::array(); bool more=false; while(q.row()) { if(rows.size()==limit){more=true;break;} auto row=parse_json(q.text(0)); if(!id.empty()) { const auto path=object_path(root_,q.text(1)); if(sha256_file(path)!=q.text(1)) throw std::runtime_error("evidence integrity failure"); row["native_result"]=parse_json(read_text(path)); } rows.push_back(row); }
    if(!id.empty() && rows.empty()) throw std::runtime_error("unknown evidence");
    return {{"schema","indago.evidence-list.v1"},{"evidence",rows},{"next_offset",more?Json(offset+limit):Json(nullptr)}};
}
Json ProjectStore::functions(std::string_view project,std::string_view artifact,std::size_t offset,std::size_t limit) const {
    Db db(root_/"indago-native.sqlite3"); require_project(db,project); limit=std::clamp<std::size_t>(limit,1,1000);
    Statement q(db,"SELECT id,artifact,address FROM functions WHERE project=? AND (artifact=? OR ?='') ORDER BY length(address),address LIMIT ? OFFSET ?"); q.bind(1,project).bind(2,artifact).bind(3,artifact).number(4,limit+1).number(5,offset);
    Json rows=Json::array(); bool more=false; while(q.row()) {if(rows.size()==limit){more=true;break;} rows.push_back({{"id",q.text(0)},{"artifact_sha256",q.text(1)},{"address",q.text(2)}});}
    return {{"schema","indago.functions.v1"},{"functions",rows},{"next_offset",more?Json(offset+limit):Json(nullptr)}};
}
Json ProjectStore::function_views(std::string_view project,std::string_view id,std::size_t offset,std::size_t limit) const {
    Db db(root_/"indago-native.sqlite3"); require_project(db,project);
    Statement f(db,"SELECT artifact,address FROM functions WHERE project=? AND id=?"); if(!f.bind(1,project).bind(2,id).row()) throw std::runtime_error("unknown function");
    Json result{{"schema","indago.function-views.v1"},{"id",id},{"location",{{"artifact_sha256",f.text(0)},{"address_space","program"},{"address",f.text(1)}}},{"views",Json::array()}};
    limit=std::clamp<std::size_t>(limit,1,1000);
    Statement q(db,"SELECT backend,evidence,record FROM function_views WHERE function=? ORDER BY rowid LIMIT ? OFFSET ?"); q.bind(1,id).number(2,limit+1).number(3,offset);
    result["claims"]=Json::array();
    result["next_offset"]=nullptr;std::size_t bytes=0;
    while(q.row()) {
        if(result["views"].size()==limit||(!result["views"].empty()&&bytes+q.text(2).size()*2>2*1024*1024)){result["next_offset"]=offset+result["views"].size();break;}
        auto native=parse_json(q.text(2));
        bytes+=q.text(2).size()*2;
        result["views"].push_back({{"backend",q.text(0)},{"evidence_id",q.text(1)},{"native",native}});
        result["claims"].push_back({{"producer",q.text(0)},{"evidence_id",q.text(1)},{"subject",id},{"predicate","backend_function_view"},{"value",native},{"authority","backend-native; not adjudicated"}});
    }
    return result;
}
Json ProjectStore::index_query(std::string_view project,const Json& filter) const {
    Db db(root_/"indago-native.sqlite3");require_project(db,project);
    const auto category=filter.value("category",std::string("entities"));
    if(category=="compare"){
        const auto anchor=filter.value("anchor",std::string{});if(anchor.empty())throw std::runtime_error("compare requires a location anchor");
        Statement q(db,R"sql(SELECT a.record,b.record FROM static_claims a
          JOIN static_entities ea ON ea.id=a.subject JOIN static_entities eb ON eb.project=ea.project AND eb.anchor=ea.anchor AND eb.kind=ea.kind
          JOIN static_claims b ON b.subject=eb.id AND b.predicate=a.predicate
          WHERE a.project=? AND ea.anchor=? AND a.backend<>b.backend AND a.id<b.id
          AND json_extract(a.record,'$.value') IS NOT json_extract(b.record,'$.value')
          AND EXISTS(SELECT 1 FROM analysis_heads h WHERE h.revision=a.revision)
          AND EXISTS(SELECT 1 FROM analysis_heads h WHERE h.revision=b.revision)
          ORDER BY a.id,b.id LIMIT 101)sql");q.bind(1,project).bind(2,anchor);Json pairs=Json::array();bool more=false;while(q.row()){if(pairs.size()==100){more=true;break;}pairs.push_back({{"view_a",parse_json(q.text(0))},{"view_b",parse_json(q.text(1))}});}
        return {{"schema","indago.comparison.v1"},{"anchor",anchor},{"disagreements",pairs},{"truncated",more},{"interpretation","Different backend assertions at one location; not an adjudication or semantic equivalence proof"}};
    }
    const std::map<std::string,std::string> tables{{"entities","static_entities"},{"relations","static_relations"},{"claims","static_claims"},{"revisions","indexed_revisions"}};
    if(!tables.contains(category))throw std::runtime_error("index category must be entities, relations, claims or revisions");
    const auto limit=std::clamp<std::size_t>(filter.value("limit",100ULL),1,1000);const auto offset=filter.value("offset",0ULL);
    std::string sql="SELECT t.record,EXISTS(SELECT 1 FROM analysis_heads h WHERE h.project=t.project AND h.revision=t.revision) FROM "+tables.at(category)+" t WHERE t.project=?";std::vector<std::string> values{std::string(project)};
    auto field=[&](const char* key,const char* column){if(filter.contains(key)&&!filter[key].get<std::string>().empty()){sql+=" AND t."+std::string(column)+"=?";values.push_back(filter[key]);}};
    field("artifact","artifact");field("backend","backend");field("revision","revision");
    if(category!="revisions")field("id","id");
    if(category=="entities"){
        field("kind","kind");field("anchor","anchor");field("name","name");
        if(filter.contains("address")){auto addr=canonical_address(filter["address"]);if(addr.empty())throw std::runtime_error("invalid address");sql+=" AND t.address=?";values.push_back(addr);}
        if(filter.contains("search")){sql+=" AND instr(lower(t.name),lower(?))>0";values.push_back(filter["search"]);}
    }
    if(category=="relations"){
        field("kind","kind");field("source","source");field("target","target");
        if(filter.contains("anchor")){sql+=" AND (t.source_anchor=? OR t.target_anchor=?)";values.push_back(filter["anchor"]);values.push_back(filter["anchor"]);}
    }
    if(category=="claims"){field("subject","subject");field("predicate","predicate");}
    if(!filter.value("history",false)&&!filter.contains("revision")&&!filter.contains("id"))sql+=" AND EXISTS(SELECT 1 FROM analysis_heads h WHERE h.project=t.project AND h.revision=t.revision)";
    sql+=" ORDER BY t.rowid LIMIT ? OFFSET ?";Statement q(db,sql.c_str());int i=1;for(const auto& value:values)q.bind(i++,value);q.number(i,limit+1);q.number(i+1,offset);
    Json rows=Json::array();bool more=false;std::size_t bytes=0;
    while(q.row()){
        auto row=parse_json(q.text(0));row["freshness"]=sqlite3_column_int(q.p,1)?"current":"superseded";
        if(row.dump().size()>1024*1024){row.erase("native");row.erase("value");row["name"]=row.value("name",std::string{}).substr(0,4096);row["payload_omitted"]=true;}
        const auto size=row.dump().size();if(rows.size()==limit||(!rows.empty()&&bytes+size>2*1024*1024)){more=true;break;}bytes+=size;rows.push_back(std::move(row));
    }
    return {{"schema","indago.index.v1"},{"category",category},{"records",rows},{"next_offset",more?Json(offset+rows.size()):Json(nullptr)},{"history",filter.value("history",false)}};
}
Json ProjectStore::reindex(std::string_view project) const {
    Db db(root_/"indago-native.sqlite3");require_project(db,project);db.exec("BEGIN IMMEDIATE");
    // This rebuild changes only derived indexes, never raw evidence or jobs.
    for(const auto* table:{"static_claims","static_relations","static_entities","analysis_heads","artifact_layouts","indexed_revisions"}){Statement d(db,("DELETE FROM "+std::string(table)+" WHERE project=?").c_str());d.bind(1,project).row();}
    Statement q(db,"SELECT evidence.id,evidence.sha,evidence.backend,jobs.id,jobs.revision,jobs.request,jobs.target,evidence.status FROM evidence JOIN jobs ON jobs.id=evidence.job WHERE evidence.project=? ORDER BY evidence.rowid");q.bind(1,project);std::size_t count=0;
    while(q.row()){
        const auto raw=object_path(root_,q.text(1));if(sha256_file(raw)!=q.text(1))throw std::runtime_error("evidence integrity failure during reindex");
        auto t=target(project,q.text(6),false);Json job{{"id",q.text(3)},{"revision",q.text(4)},{"request",parse_json(q.text(5))}};
        persist_index(db,t,job,q.text(2),q.text(0),parse_json(read_text(raw)),q.text(7));++count;
    }
    db.exec("COMMIT");return {{"schema","indago.reindex.v1"},{"evidence_records",count},{"status","completed"}};
}
}
