#pragma once

#include "indago/service.hpp"
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace tui {

// One row on the Projects page.
struct ProjectItem {
    std::string name, id, created;
    int targets{0}, functions{0};
};

// One row on the Targets page.
struct TargetItem {
    std::string id, name, sha;
    std::uintmax_t size{0};
};

// One row on the Functions page, enriched from the first available view.
struct FunctionItem {
    std::string id, sha, address;
    std::string name, blocks, coverage;
};

// One row on the Evidence page.
struct EvidenceItem {
    std::string id, backend, status, revision, created;
};

// One row on the Jobs page.
struct JobItem {
    std::string id, status, backend, operation, address, created;
};

// One row on the Harness page.
struct HarnessItem {
    std::string id, status, objective, created;
};

// A unit of work run on a background thread so the UI stays responsive. The
// worker fills `lines`/`raw` and may publish the current job id; the UI thread
// reads them only after `done` is set. `set_job`/`get_job` are mutex-guarded
// because cancellation can race with the worker.
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

    // Records the id of the job currently executing so it can be cancelled.
    void set_job(std::string id) {
        std::lock_guard<std::mutex> guard(job_mutex);
        current_job = std::move(id);
    }
    // Returns the id of the job currently executing, if any.
    std::string get_job() const {
        std::lock_guard<std::mutex> guard(job_mutex);
        return current_job;
    }

private:
    mutable std::mutex job_mutex;
    std::string current_job;
};

// The seven browsable pages plus the shared detail and confirm overlays.
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

// Holds the workspace, the service used to read and write it, all page state,
// and the optional background task. The render/input loop in main.cpp drives it.
class App {
public:
    // Opens (creating if needed) the workspace at `workspace` and loads projects.
    explicit App(std::string workspace);
    // Cancels and joins any running task.
    ~App();

    // The service backing every store operation; mains use it for capabilities.
    indago::StaticService& service() { return *service_; }

    // Reloads the project list. Returns false and sets last_error on failure.
    bool refresh_projects();
    // Reloads targets for the open project, clamping the selection.
    void refresh_targets();
    // Reloads functions for the active artifact, applying fn_filter.
    void refresh_functions();
    // Reloads evidence for the open project.
    void refresh_evidence();
    // Reloads jobs for the open project.
    void refresh_jobs();
    // Reloads harness investigations for the open project.
    void refresh_harness();
    // Reloads whichever list belongs to the current page.
    void refresh_current();

    // Creates a project and refreshes the list. Sets last_error on failure.
    bool create_project(const std::string& name);
    // Opens `name`: loads its info, targets, and selects the first target.
    bool open_project(const std::string& name);
    // Copies `path` into the content store and adds it to the open project.
    bool import_target(const std::string& path);
    // Makes the target at `index` active and reloads its functions.
    void pick_target(std::size_t index);

    // Runs the fixed static analysis profile for the active target in the
    // background: XAIR inventory, AIRECE inspect/functions, and XAIR CFG.
    void run_analysis();
    // Runs one analysis operation in the background using the Query form.
    void run_query(const std::string& backend, const std::string& operation,
                   const std::string& address, const std::string& view);
    // Runs an AIRECE function view in the background with a display title.
    void run_function_view(const std::string& address, const std::string& view,
                           const std::string& title);
    // Creates a harness investigation and stores its owner lease. Returns false
    // and sets last_error when the harness rejects the request.
    bool create_investigation(const std::string& objective,
                              const std::vector<std::string>& facts,
                              const std::string& mode,
                              const std::string& model,
                              const std::string& endpoint,
                              long max_actions);
    // Runs harness explore for the selected investigation, which requires the
    // lease acquired by create_investigation() in this session.
    void run_explore();
    // Requests cancellation of the running task and its store job.
    void request_cancel();
    // True while a background task exists and has not finished.
    bool busy() const { return task != nullptr && !task->done.load(); }
    // Moves a finished task to show_task, records errors/status, and refreshes
    // the current list. Returns true when a task was consumed.
    bool finish_task();

    // Detail bodies built from store queries; each returns text lines.
    std::vector<std::string> project_json_lines() const;
    std::vector<std::string> job_detail_lines(const JobItem& item) const;
    std::vector<std::string> evidence_detail_lines(const EvidenceItem& item) const;
    std::vector<std::string> capabilities_lines() const;
    std::vector<std::string> harness_show_lines(const HarnessItem& item) const;
    // Renders the harness "actions" or "events" records for one investigation.
    std::vector<std::string> harness_records_lines(const std::string& op,
                                                   const HarnessItem& item) const;

    // Pushes the current page on the history stack and switches to `p`.
    void push_page(Page p) { history.push_back(page); page = p; }
    // Returns to the previous page, if any.
    void go_back();
    // Shows a static list of lines on the Detail page and resets its cursor and
    // search state.
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
    // Sets the success message shown on the status line.
    void set_status(std::string message) { status_message = std::move(message); }

    std::string workspace;
    std::string project;
    std::string project_id;
    std::string target_id;
    std::string artifact_sha;
    std::string target_name;

    Page page{Page::Projects};
    std::vector<Page> history;

    // Rows for each list page.
    std::vector<ProjectItem> projects;
    std::vector<TargetItem> targets;
    std::vector<FunctionItem> functions;
    std::vector<EvidenceItem> evidence_rows;
    std::vector<JobItem> job_rows;
    std::vector<HarnessItem> harness_rows;

    // Selection index and scroll offset for each list page.
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

    // Detail cursor, raw/text toggle, and active find needle.
    int detail_row{0};
    int detail_col{0};
    bool detail_show_raw{false};
    bool lists_truncated{false};
    std::string fn_filter;
    std::string list_note;
    std::string static_title;
    std::vector<std::string> static_lines;
    std::string detail_needle;

    // Owner lease for the investigation created from this session, used to
    // authorize explore.
    std::string harness_token;
    std::string harness_inv_id;
    long harness_revision{1};

    // The running task and the last finished task shown on the Detail page.
    std::shared_ptr<BackgroundTask> task;
    std::shared_ptr<BackgroundTask> show_task;
    // Success text and the most recent error (rendered in the error style).
    std::string status_message;
    std::string last_error;

private:
    std::unique_ptr<indago::StaticService> service_;
    // Runs `body` on a new background thread, installing it as `task`.
    void launch(const std::function<void()>& body);
};

}  // namespace tui
