#pragma once

#include "indago/service.hpp"
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace tui {

struct ProjectItem {
    std::string name, id, created;
    int targets{0}, functions{0};
};

struct TargetItem {
    std::string id, name, sha;
    std::uintmax_t size{0};
};

struct FunctionItem {
    std::string id, sha, address;
    std::string name, blocks, coverage;
};

struct EvidenceItem {
    std::string id, backend, status, revision, created;
};

struct JobItem {
    std::string id, status, backend, operation, address, created;
};

struct HarnessItem {
    std::string id, status, objective, created;
};

struct BackgroundTask {
    std::atomic_bool cancel{false};
    std::atomic_bool done{false};
    std::string label;
    std::string title;
    std::vector<std::string> lines;
    std::vector<std::string> raw;
    std::string error;
    std::thread runner;
    ~BackgroundTask() { if (runner.joinable()) runner.join(); }

    void set_job(std::string id) {
        std::lock_guard<std::mutex> guard(job_mutex);
        current_job = std::move(id);
    }
    std::string get_job() const {
        std::lock_guard<std::mutex> guard(job_mutex);
        return current_job;
    }

private:
    mutable std::mutex job_mutex;
    std::string current_job;
};

enum class Page {
    Projects,
    Targets,
    Functions,
    Evidence,
    Jobs,
    QueryForm,
    Harness,
    Detail,
    Confirm,
};

class App {
public:
    explicit App(std::string workspace);
    ~App();

    indago::StaticService& service() { return *service_; }

    bool refresh_projects();
    void refresh_targets();
    void refresh_functions();
    void refresh_evidence();
    void refresh_jobs();
    void refresh_harness();
    void refresh_current();

    bool create_project(const std::string& name);
    bool open_project(const std::string& name);
    bool import_target(const std::string& path);
    void pick_target(std::size_t index);

    void run_analysis();
    void run_query(const std::string& backend, const std::string& operation,
                   const std::string& address, const std::string& view);
    void run_function_view(const std::string& address, const std::string& view,
                           const std::string& title);
    bool create_investigation(const std::string& objective,
                              const std::vector<std::string>& facts,
                              const std::string& mode,
                              const std::string& model,
                              const std::string& endpoint,
                              long max_actions);
    void run_explore();
    void request_cancel();
    bool busy() const { return task != nullptr && !task->done.load(); }
    bool finish_task();

    std::vector<std::string> project_json_lines() const;
    std::vector<std::string> job_detail_lines(const JobItem& item) const;
    std::vector<std::string> evidence_detail_lines(const EvidenceItem& item) const;
    std::vector<std::string> capabilities_lines() const;
    std::vector<std::string> harness_show_lines(const HarnessItem& item) const;
    std::vector<std::string> harness_records_lines(const std::string& op,
                                                   const HarnessItem& item) const;

    void push_page(Page p) { history.push_back(page); page = p; }
    void go_back();
    void show_static(const std::string& title, std::vector<std::string> lines) {
        show_task.reset();
        static_title = title;
        static_lines = std::move(lines);
        detail_row = 0;
        detail_col = 0;
        detail_show_raw = false;
        detail_needle.clear();
        push_page(Page::Detail);
    }
    void set_status(std::string message) { status_message = std::move(message); }

    std::string workspace;
    std::string project;
    std::string project_id;
    std::string target_id;
    std::string artifact_sha;
    std::string target_name;

    Page page{Page::Projects};
    std::vector<Page> history;

    std::vector<ProjectItem> projects;
    std::vector<TargetItem> targets;
    std::vector<FunctionItem> functions;
    std::vector<EvidenceItem> evidence_rows;
    std::vector<JobItem> job_rows;
    std::vector<HarnessItem> harness_rows;

    int proj_sel{0};
    int tgt_sel{0};
    int fn_sel{0};
    int ev_sel{0};
    int job_sel{0};
    int hn_sel{0};
    int proj_top{0};
    int tgt_top{0};
    int fn_top{0};
    int ev_top{0};
    int job_top{0};
    int hn_top{0};

    int detail_row{0};
    int detail_col{0};
    bool detail_show_raw{false};
    bool lists_truncated{false};
    std::string fn_filter;
    std::string list_note;
    std::string static_title;
    std::vector<std::string> static_lines;
    std::string detail_needle;

    std::string harness_token;
    std::string harness_inv_id;
    long harness_revision{1};

    std::shared_ptr<BackgroundTask> task;
    std::shared_ptr<BackgroundTask> show_task;
    std::string status_message;
    std::string last_error;

private:
    std::unique_ptr<indago::StaticService> service_;
    void launch(const std::function<void()>& body);
};

}  // namespace tui