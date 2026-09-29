#include "app.hpp"

#include <nlohmann/json.hpp>

#include "indago/harness.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace tui {

using Json = nlohmann::json;

namespace {

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> out;
    std::string line = text;
    std::string::size_type pos = 0;
    while (pos < line.size()) {
        auto nl = line.find('\n', pos);
        if (nl == std::string::npos) {
            out.push_back(line.substr(pos));
            break;
        }
        out.push_back(line.substr(pos, nl - pos));
        pos = nl + 1;
    }
    if (line.empty()) out.emplace_back();
    return out;
}

Json action_request(App& app, const std::string& backend,
                    const std::string& operation,
                    const std::string& address,
                    const std::string& view) {
    const bool repair = app.target_id.empty() && !app.targets.empty();
    const std::string target = app.target_id.empty() ? app.targets.front().id : app.target_id;
    if (repair) app.target_id = target;
    Json request{
        {"schema", "indago.action.v1"},
        {"project", app.project},
        {"target_id", target},
        {"backend", backend},
        {"operation", operation},
        {"address", address},
        {"view", view},
        {"budget",
         {{"wall_ms", 120000},
          {"output_bytes", 2097152},
          {"memory_bytes", 2147483648LL},
          {"max_items", 2048}}},
        {"arguments", Json::object()},
    };
    return request;
}

std::string text_of(const Json& envelope) {
    const Json& data = envelope.value("data", Json::object());
    if (data.is_string()) return data.get<std::string>();
    if (data.is_object()) {
        if (data.contains("native_output") && data["native_output"].is_string())
            return data["native_output"].get<std::string>();
        if (data.contains("output") && data["output"].is_string())
            return data["output"].get<std::string>();
    }
    return data.dump(2);
}

std::string job_status(indago::StaticService& service, const std::string& project_name,
                       const std::string& id) {
    try {
        auto jobs = service.store().job_info(project_name, id);
        return jobs["jobs"][0].value("status", std::string{});
    } catch (...) {
        return "finished";
    }
}

}  // namespace

App::App(std::string ws) : workspace(std::move(ws)) {
    service_ = std::make_unique<indago::StaticService>(indago::fs::path(workspace));
    refresh_projects();
}

App::~App() {
    if (task) {
        task->cancel = true;
        task->set_job({});
        task.reset();
    }
}

void App::launch(const std::function<void()>& body) {
    auto t = std::make_shared<BackgroundTask>();
    task = t;
    t->label = "starting";
    t->runner = std::thread([t, body] {
        try {
            body();
        } catch (const std::exception& e) {
            t->error = e.what();
        }
        t->done = true;
    });
}

bool App::refresh_projects() {
    try {
        auto data = service_->store().list_projects();
        projects.clear();
        for (const auto& row : data["projects"]) {
            ProjectItem item;
            item.name = row.value("name", std::string{});
            item.id = row.value("id", std::string{});
            item.created = row.value("created_at", std::string{});
            item.targets = row.value("targets", 0);
            item.functions = row.value("functions", 0);
            projects.push_back(std::move(item));
        }
        if (proj_sel >= static_cast<int>(projects.size())) proj_sel = projects.empty() ? 0 : static_cast<int>(projects.size()) - 1;
        return true;
    } catch (const std::exception& e) {
        last_error = e.what();
        return false;
    }
}

bool App::create_project(const std::string& name) {
    try {
        auto result = service_->store().create_project(name);
        set_status("created project " + name);
        return refresh_projects();
    } catch (const std::exception& e) {
        last_error = e.what();
        return false;
    }
}

bool App::open_project(const std::string& name) {
    try {
        auto info = service_->store().project_info(name);
        project = name;
        project_id = info.value("id", std::string{});
        refresh_targets();
        if (!targets.empty()) pick_target(0);
        list_note.clear();
        return true;
    } catch (const std::exception& e) {
        last_error = e.what();
        return false;
    }
}

void App::refresh_targets() {
    try {
        auto info = service_->store().project_info(project);
        targets.clear();
        for (const auto& row : info["targets"]) {
            TargetItem item;
            item.id = row.value("id", std::string{});
            item.sha = row.value("artifact_sha256", std::string{});
            item.name = row.value("name", std::string{});
            item.size = row.value("size", Json(0)).get<std::uintmax_t>();
            targets.push_back(std::move(item));
        }
        if (tgt_sel >= static_cast<int>(targets.size())) tgt_sel = targets.empty() ? 0 : static_cast<int>(targets.size()) - 1;
    } catch (const std::exception& e) {
        last_error = e.what();
    }
}

void App::pick_target(std::size_t index) {
    if (index >= targets.size()) return;
    const auto& item = targets[index];
    target_id = item.id;
    artifact_sha = item.sha;
    target_name = item.name;
    set_status("active target: " + item.name + " (" + item.id + ")");
    refresh_functions();
}

void App::refresh_functions() {
    if (project.empty()) return;
    try {
        auto data = service_->store().functions(project, artifact_sha, 0, 1000);
        functions.clear();
        lists_truncated = data["functions"].size() >= 1000;
        for (const auto& row : data["functions"]) {
            FunctionItem item;
            item.id = row.value("id", std::string{});
            item.sha = row.value("artifact_sha256", std::string{});
            item.address = row.value("address", std::string{});
            try {
                auto views = service_->store().function_views(project, item.id, 0, 1);
                if (views.contains("views") && !views["views"].empty()) {
                    const auto& native = views["views"][0].value("native", Json::object());
                    if (native.is_object()) {
                        item.name = native.value("name", native.value("display_name", std::string{}));
                        if (native.contains("blocks"))
                            item.blocks = native["blocks"].is_number() ? std::to_string(native["blocks"].get<std::int64_t>()) : native["blocks"].dump();
                        item.coverage = native.value("coverage", std::string{});
                    }
                }
            } catch (...) {
            }
            if (!fn_filter.empty() &&
                item.address.find(fn_filter) == std::string::npos)
                continue;
            functions.push_back(std::move(item));
        }
        if (fn_sel >= static_cast<int>(functions.size())) fn_sel = functions.empty() ? 0 : static_cast<int>(functions.size()) - 1;
    } catch (const std::exception& e) {
        last_error = e.what();
    }
}

void App::refresh_evidence() {
    if (project.empty()) return;
    try {
        auto data = service_->store().evidence(project, {}, 0, 500);
        evidence_rows.clear();
        for (const auto& row : data["evidence"]) {
            EvidenceItem item;
            item.id = row.value("id", std::string{});
            item.backend = row.value("producer", std::string{});
            item.status = row.value("status", std::string{});
            item.revision = row.value("revision", std::string{});
            item.created = row.value("created_at", std::string{});
            evidence_rows.push_back(std::move(item));
        }
        if (ev_sel >= static_cast<int>(evidence_rows.size())) ev_sel = evidence_rows.empty() ? 0 : static_cast<int>(evidence_rows.size()) - 1;
    } catch (const std::exception& e) {
        last_error = e.what();
    }
}

void App::refresh_jobs() {
    if (project.empty()) return;
    try {
        auto data = service_->store().job_info(project, {});
        job_rows.clear();
        for (const auto& row : data["jobs"]) {
            JobItem item;
            item.id = row.value("id", std::string{});
            item.status = row.value("status", std::string{});
            item.created = row.value("created_at", std::string{});
            const auto& req = row.value("request", Json::object());
            item.backend = req.value("backend", std::string{});
            item.operation = req.value("operation", std::string{});
            item.address = req.value("address", std::string{});
            job_rows.push_back(std::move(item));
        }
        if (job_sel >= static_cast<int>(job_rows.size())) job_sel = job_rows.empty() ? 0 : static_cast<int>(job_rows.size()) - 1;
    } catch (const std::exception& e) {
        last_error = e.what();
    }
}

void App::refresh_current() {
    switch (page) {
        case Page::Projects: refresh_projects(); break;
        case Page::Targets: refresh_targets(); break;
        case Page::Functions: refresh_functions(); break;
        case Page::Evidence: refresh_evidence(); break;
        case Page::Jobs: refresh_jobs(); break;
        case Page::Harness: refresh_harness(); break;
        default: break;
    }
}

void App::refresh_harness() {
    harness_rows.clear();
    try {
        const auto db_path = service_->store().root() / "indago-native.sqlite3";
        sqlite3* db = nullptr;
        if (sqlite3_open(db_path.string().c_str(), &db) != SQLITE_OK) {
            if (db) sqlite3_close(db);
            return;
        }
        sqlite3_busy_timeout(db, 10000);
        sqlite3_stmt* stmt = nullptr;
        const char* sql =
            "SELECT id,record FROM wb_investigations WHERE project=? "
            "ORDER BY rowid DESC LIMIT 200";
        const bool ok = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK;
        if (ok) {
            sqlite3_bind_text(stmt, 1, project.c_str(), -1, SQLITE_TRANSIENT);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                HarnessItem item;
                item.id = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                try {
                    auto rec = Json::parse(
                        reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
                    item.status = rec.value("status", std::string{});
                    item.objective = rec.value("objective", std::string{});
                    item.created = rec.value("created_at", std::string{});
                } catch (...) {
                    item.status = "?";
                }
                harness_rows.push_back(std::move(item));
            }
        }
        if (stmt) sqlite3_finalize(stmt);
        sqlite3_close(db);
    } catch (...) {
    }
    if (hn_sel >= static_cast<int>(harness_rows.size()))
        hn_sel = harness_rows.empty() ? 0 : static_cast<int>(harness_rows.size()) - 1;
}

bool App::create_investigation(const std::string& objective,
                               const std::vector<std::string>& facts,
                               const std::string& mode,
                               const std::string& model,
                               const std::string& endpoint,
                               long max_actions) {
    try {
        Json owner{{"mode", mode}, {"name", "indago-tui"}};
        if (mode == "builtin") {
            Json profile{{"provider", "local"}, {"model", model}};
            if (!endpoint.empty()) profile["endpoint"] = endpoint;
            owner["profile"] = profile;
        } else {
            owner["model_declaration"] =
                "terminal workbench operator; no inference";
        }
        Json request{{"project", project},
                     {"objective", objective},
                     {"required_facts", facts},
                     {"owner", owner},
                     {"budget",
                      {{"max_actions", max_actions},
                       {"wall_ms", 3600000},
                       {"output_bytes", 2097152}}}};
        if (!target_id.empty()) request["target_id"] = target_id;
        auto record = indago::harness_action(*service_, "create", request);
        harness_token = record.value("owner_token", std::string{});
        harness_inv_id = record.value("id", std::string{});
        harness_revision = 1;
        refresh_harness();
        set_status("investigation " + harness_inv_id +
                   " created (owner lease acquired)");
        return true;
    } catch (const std::exception& e) {
        last_error = e.what();
        return false;
    }
}

void App::run_explore() {
    if (busy() || project.empty()) return;
    if (harness_rows.empty()) {
        set_status("[!] no investigations yet - press n to create one");
        return;
    }
    const auto& item = harness_rows[static_cast<std::size_t>(hn_sel)];
    if (harness_token.empty() || harness_inv_id != item.id) {
        set_status("[!] no owner lease for " + item.id +
                   " - create it from this page first");
        return;
    }
    const std::string id = item.id;
    const long revision = harness_revision;
    const std::string token = harness_token;
    launch([this, id, revision, token] {
        task->label = "harness explore";
        task->title = "explore " + id;
        Json request{{"project", project},
                     {"id", id},
                     {"owner_token", token},
                     {"expected_revision", revision},
                     {"allow_inference", true},
                     {"max_generations", 8},
                     {"recipe", "assisted_static"}};
        auto result = indago::harness_action(*service_, "explore", request);
        task->lines = split_lines(result.dump(2));
        task->raw = task->lines;
    });
}

std::vector<std::string> App::harness_show_lines(const HarnessItem& item) const {
    try {
        auto rec = indago::harness_action(*service_, "show",
                                          Json{{"project", project}, {"id", item.id}});
        return split_lines(rec.dump(2));
    } catch (const std::exception& e) {
        return {std::string("[!] ") + e.what()};
    }
}

std::vector<std::string> App::harness_records_lines(const std::string& op,
                                                    const HarnessItem& item) const {
    try {
        auto rec = indago::harness_action(
            *service_, op,
            Json{{"project", project}, {"id", item.id}, {"limit", 128}});
        if (rec.contains("records") && rec["records"].is_array()) {
            std::ostringstream out;
            out << rec["records"].size() << " " << op
                << (rec["records"].size() == 1 ? "" : " records") << "\n";
            for (const auto& r : rec["records"]) out << "---\n" << r.dump(2) << "\n";
            return split_lines(out.str());
        }
        return split_lines(rec.dump(2));
    } catch (const std::exception& e) {
        return {std::string("[!] ") + e.what()};
    }
}

bool App::import_target(const std::string& path) {
    try {
        auto record = service_->store().import_target(project, indago::fs::path(path));
        set_status("imported " + record.display_name + " -> " + record.id);
        refresh_targets();
        return true;
    } catch (const std::exception& e) {
        last_error = e.what();
        return false;
    }
}

void App::run_analysis() {
    if (busy() || project.empty() || target_id.empty()) return;
    const std::string project_name = project;
    const std::string target = target_id;
    launch([this, project_name, target] {
        const std::pair<const char*, const char*> steps[] = {
            {"xair", "inventory"}, {"airece", "inspect"},
            {"airece", "functions"}, {"xair", "cfg"}};
        std::vector<std::string> summary;
        summary.push_back("Analysis profile for " + target_name + " (" + target + ")");
        for (const auto& [backend, operation] : steps) {
            if (task->cancel.load()) {
                summary.push_back("cancelled by user");
                break;
            }
            task->label = backend + std::string(" ") + operation;
            try {
                auto request = action_request(*this, backend, operation, "", "compact");
                auto job = service().prepare(request);
                const auto job_id = job.at("id").get<std::string>();
                task->set_job(job_id);
                service().execute(job);
                const bool cancelled = task->cancel.load();
                auto status = job_status(service(), project_name, job_id);
                std::string line = "[-] " + std::string(backend) + " " + operation;
                line += cancelled ? "  (cancelled)" : ("  -> " + status);
                summary.push_back(line);
            } catch (const std::exception& e) {
                summary.push_back("[!] " + std::string(backend) + " " + operation + " failed: " + e.what());
            }
        }
        if (!task->error.empty()) summary.push_back("[!] " + task->error);
        task->title = "analysis profile";
        task->lines = std::move(summary);
        task->raw = split_lines(Json{{"steps", task->lines}}.dump(2));
    });
}

void App::run_query(const std::string& backend, const std::string& operation,
                    const std::string& address, const std::string& view) {
    if (busy()) return;
    launch([this, backend, operation, address, view] {
        task->label = backend + " " + operation + (address.empty() ? "" : (" " + address));
        task->title = backend + " " + operation + (address.empty() ? "" : (" @" + address));
        auto request = action_request(*this, backend, operation, address, view);
        if (backend == "ghidra") request["arguments"] = Json::object();
        auto job = service().prepare(request);
        const auto job_id = job.at("id").get<std::string>();
        task->set_job(job_id);
        auto envelope = service().execute(job);
        const auto status = envelope.value("status", std::string{});
        auto text = text_of(envelope);
        if (text.empty() && !status.empty()) text = envelope.dump(2);
        else if (text.empty()) text = "no result body";
        task->lines = split_lines(text);
        task->raw = split_lines(envelope.dump(2));
        task->title += " (" + std::to_string(task->raw.size()) + " bytes json)";
    });
}

void App::run_function_view(const std::string& address, const std::string& view,
                            const std::string& title) {
    if (busy()) return;
    launch([this, address, view, title] {
        task->label = "airece function " + address;
        task->title = title + " @" + address;
        auto request = action_request(*this, "airece", "function", address, view);
        auto job = service().prepare(request);
        const auto job_id = job.at("id").get<std::string>();
        task->set_job(job_id);
        auto envelope = service().execute(job);
        auto text = text_of(envelope);
        if (text.empty()) text = envelope.dump(2);
        task->lines = split_lines(text);
        task->raw = split_lines(envelope.dump(2));
    });
}

bool App::finish_task() {
    if (!task || !task->done.load()) return false;
    auto t = task;
    task.reset();
    show_task = t;
    detail_row = 0;
    detail_col = 0;
    detail_show_raw = false;
    detail_needle.clear();
    if (!t->error.empty() && t->lines.empty()) t->lines.push_back("[!] " + t->error);
    if (!t->error.empty()) last_error = t->error;
    set_status(t->title + " -> " + std::to_string(t->lines.size()) + " lines");
    refresh_current();
    return true;
}

void App::request_cancel() {
    if (!busy()) return;
    task->cancel = true;
    const auto id = task->get_job();
    if (!id.empty()) {
        try {
            service().store().cancel_job(project, id);
        } catch (...) {
        }
    }
    set_status("cancellation requested");
}

void App::go_back() {
    if (history.empty()) return;
    page = history.back();
    history.pop_back();
}

std::vector<std::string> App::project_json_lines() const {
    try {
        auto info = service_->store().project_info(project);
        return split_lines(info.dump(2));
    } catch (const std::exception& e) {
        return {std::string("[!] ") + e.what()};
    }
}

std::vector<std::string> App::job_detail_lines(const JobItem& item) const {
    try {
        auto jobs = service_->store().job_info(project, item.id);
        const auto& job = jobs["jobs"][0];
        std::ostringstream out;
        const auto& req = job.value("request", Json::object());
        out << "job      " << item.id << "\n";
        out << "status   " << item.status << "\n";
        out << "created  " << item.created << "\n";
        out << "backend  " << req.value("backend", std::string{}) << "\n";
        out << "op       " << req.value("operation", std::string{}) << "\n";
        out << "address  " << req.value("address", std::string{}) << "\n";
        out << "target   " << req.value("target_id", std::string{}) << "\n";
        if (job.contains("finished_at")) out << "finished " << job["finished_at"].get<std::string>() << "\n";
        if (job.contains("result")) {
            out << "\n" << job["result"]["status"].get<std::string>()
                << " evidence " << job["result"].value("evidence_ids", Json::array()).dump();
            out << "\n\n" << job["result"].dump(2);
        }
        return split_lines(out.str());
    } catch (const std::exception& e) {
        return {std::string("[!] ") + e.what()};
    }
}

std::vector<std::string> App::evidence_detail_lines(const EvidenceItem& item) const {
    try {
        auto rows = service_->store().evidence(project, item.id, 0, 1);
        const auto& row = rows["evidence"][0];
        std::ostringstream out;
        out << "evidence " << item.id << "\n";
        out << "producer " << item.backend << "\n";
        out << "status   " << item.status << "\n";
        out << "revision " << item.revision << "\n";
        out << "created  " << item.created << "\n";
        if (row.contains("native_result")) out << "\n" << row["native_result"].dump(2);
        else out << "\n" << Json{{"record", row}}.dump(2);
        return split_lines(out.str());
    } catch (const std::exception& e) {
        return {std::string("[!] ") + e.what()};
    }
}

std::vector<std::string> App::capabilities_lines() const {
    try {
        return split_lines(service_->capabilities().dump(2));
    } catch (const std::exception& e) {
        return {std::string("[!] ") + e.what()};
    }
}

}  // namespace tui