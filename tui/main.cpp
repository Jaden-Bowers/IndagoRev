#include "app.hpp"
#include "ui.hpp"

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <sstream>
#include <string>

#ifndef INDAGO_TUI_VERSION
#define INDAGO_TUI_VERSION "0.1.0"
#endif

namespace {

using namespace tui;

struct QueryForm {
    struct Field {
        std::string label, value;
    };
    std::vector<Field> fields = {
        {"backend", "airece"},
        {"operation", "function"},
        {"address", ""},
        {"view", "disassembly"},
    };
    int sel{0};
} g_query;

const std::vector<std::string>* detail_main(const tui::App& app,
                                            const std::vector<std::string>** raw) {
    if (app.show_task) {
        if (raw) *raw = &app.show_task->raw;
        const bool want_raw = app.detail_show_raw && !app.show_task->raw.empty();
        return want_raw ? &app.show_task->raw : &app.show_task->lines;
    }
    if (raw) *raw = nullptr;
    return &app.static_lines;
}

std::string pos_note(int sel, std::size_t total) {
    return total == 0 ? std::string{} : (std::to_string(sel + 1) + "/" +
                                          std::to_string(total));
}

void render(tui::App& app, unsigned tick) {
    int lines = 0, cols = 0;
    getmaxyx(stdscr, lines, cols);
    if (lines < 8 || cols < 48) {
        erase();
        move(0, 0);
        clrtoeol();
        attrset(A_BOLD);
        std::string msg = "terminal too small (" + std::to_string(cols) + "x" +
                          std::to_string(lines) + ") - need at least 48x8";
        printw("%s", msg.c_str());
        if (lines > 2) {
            move(1, 0);
            attrset(A_DIM);
            printw("resize the terminal to continue");
        }
        attrset(A_NORMAL);
        refresh();
        return;
    }

    const std::string workspace = app.workspace;
    std::string right = app.project.empty() ? "no project" : app.project;
    if (!app.target_name.empty()) right += " :: " + app.target_name;
    std::string center;
    if (app.busy()) {
        static const char spinner[] = {'|', '/', '-', '\\'};
        center = " RUNNING " + app.task->label + " " + spinner[tick % 4];
    }
    draw_banner("IndagoRev " INDAGO_TUI_VERSION + std::string("  ") + workspace,
                center, right);

    const int first_row = 2;
    const int height = std::max(1, lines - 6);

    switch (app.page) {
        case tui::Page::Projects:
            draw_title("Projects", "workspace " + app.workspace + "   " +
                                  pos_note(app.proj_sel, app.projects.size()));
            draw_help("Enter open  n new  c capabilities  r refresh  q quit");
            {
                std::vector<std::string> rows;
                rows.reserve(app.projects.size());
                for (const auto& p : app.projects) {
                    rows.push_back(p.name + "   targets " +
                                   std::to_string(p.targets) + "  functions " +
                                   std::to_string(p.functions) +
                                   "   created " + p.created);
                }
                draw_list(rows, app.proj_sel, app.proj_top, first_row, height,
                          "no projects yet - press n to create one");
            }
            break;

        case tui::Page::Targets:
            draw_title("Targets", app.project + "   " +
                                  pos_note(app.tgt_sel, app.targets.size()));
            draw_help("Enter select  a analyze  i import  g functions  e evidence  J jobs  h harness  q query  p project  c capabilities  Esc back");
            {
                std::vector<std::string> rows;
                rows.reserve(app.targets.size());
                for (const auto& t : app.targets) {
                    std::string active = t.id == app.target_id ? " [active]" : "";
                    rows.push_back(t.name + active + "  " +
                                   std::to_string(t.size) + " bytes  sha " +
                                   (t.sha.size() > 16 ? t.sha.substr(0, 16) : t.sha));
                }
                draw_list(rows, app.tgt_sel, app.tgt_top, first_row, height,
                          "no targets imported yet - press i to import a file");
            }
            break;

        case tui::Page::Functions:
            draw_title("Functions", (app.target_name.empty() ? app.project : app.target_name) +
                                        (app.fn_filter.empty()
                                             ? ""
                                             : "  filter:" + app.fn_filter) +
                                        "   " + pos_note(app.fn_sel, app.functions.size()));
            draw_help("Enter/d disasm  p pseudocode  x xair cfg  f filter  F clear  t targets  e evidence  J jobs  q query  Esc back");
            {
                std::vector<std::string> rows;
                rows.reserve(app.functions.size());
                for (const auto& f : app.functions) {
                    std::string row = f.address;
                    if (!f.name.empty()) row += "  " + f.name;
                    if (!f.blocks.empty()) row += "  blocks=" + f.blocks;
                    if (!f.coverage.empty()) row += "  " + f.coverage;
                    rows.push_back(row);
                }
                draw_list(rows, app.fn_sel, app.fn_top, first_row, height,
                          "no functions - run analysis (targets > a)");
            }
            break;

        case tui::Page::Evidence:
            draw_title("Evidence", app.project + "   " +
                                  pos_note(app.ev_sel, app.evidence_rows.size()));
            draw_help("Enter inspect  t targets  g functions  J jobs  q query  Esc back");
            {
                std::vector<std::string> rows;
                rows.reserve(app.evidence_rows.size());
                for (const auto& e : app.evidence_rows) {
                    rows.push_back(e.id + "  " + e.backend + "  " + e.status +
                                   "  " + e.created);
                }
                draw_list(rows, app.ev_sel, app.ev_top, first_row, height,
                          "no evidence yet");
            }
            break;

        case tui::Page::Jobs:
            draw_title("Jobs", app.project + "   " +
                                  pos_note(app.job_sel, app.job_rows.size()));
            draw_help("Enter inspect  k cancel  t targets  g functions  e evidence  J jobs  q query  Esc back");
            {
                std::vector<std::string> rows;
                rows.reserve(app.job_rows.size());
                for (const auto& j : app.job_rows) {
                    std::string row = j.id + "  " + j.status + "  " + j.backend +
                                      "/" + j.operation;
                    if (!j.address.empty()) row += " @" + j.address;
                    row += "  " + j.created;
                    rows.push_back(row);
                }
                draw_list(rows, app.job_sel, app.job_top, first_row, height,
                          "no jobs yet");
            }
            break;

        case tui::Page::QueryForm: {
            draw_title("Query", "run a single analysis operation");
            draw_help("Up/Down select  Enter edit  r/R run  Esc back");
            for (std::size_t i = 0; i < g_query.fields.size(); ++i) {
                const bool sel = static_cast<int>(i) == g_query.sel;
                set_attr(sel ? tui::Attr::Select : tui::Attr::Normal);
                draw_fill(stdscr, first_row + static_cast<int>(i), 0, cols - 0, ' ',
                          sel ? tui::Attr::Select : tui::Attr::Normal);
                draw_clipped(stdscr, first_row + static_cast<int>(i), 2,
                             g_query.fields[i].label, 12);
                set_attr(tui::Attr::Title);
                draw_clipped(stdscr, first_row + static_cast<int>(i), 15,
                             g_query.fields[i].value, cols - 16);
            }
            const int run_row = first_row + static_cast<int>(g_query.fields.size());
            const bool run_sel = g_query.sel >= static_cast<int>(g_query.fields.size());
            set_attr(run_sel ? tui::Attr::Accent : tui::Attr::Dim);
            draw_fill(stdscr, run_row, 0, cols, ' ',
                      run_sel ? tui::Attr::Accent : tui::Attr::Dim);
            draw_clipped(stdscr, run_row, 2, "[Run query]", cols - 4);
            set_attr(tui::Attr::Normal);
            break;
        }

        case tui::Page::Harness: {
            draw_title("Harness", app.project + "   " +
                                  pos_note(app.hn_sel, app.harness_rows.size()));
            draw_help("Enter record  n new  r run explore  a actions  e events  R refresh  t targets  g functions  J jobs  q query  Esc back");
            {
                std::vector<std::string> rows;
                rows.reserve(app.harness_rows.size());
                for (const auto& h : app.harness_rows) {
                    std::string row = h.id + "  " + h.status + "  " + h.objective;
                    if (!h.created.empty()) row += "  " + h.created;
                    rows.push_back(row);
                }
                draw_list(rows, app.hn_sel, app.hn_top, first_row, height,
                          "no investigations yet - press n to create one");
            }
            break;
        }

        case tui::Page::Detail: {
            const std::vector<std::string>* raw = nullptr;
            const auto* lines = detail_main(app, &raw);
            // Clamp before computing the note so the line counter never shows
            // an out-of-range number for the frame after End / PgDn.
            const int total = static_cast<int>(lines->size());
            if (app.detail_row > total - 1) app.detail_row = total > 0 ? total - 1 : 0;
            if (app.detail_row < 0) app.detail_row = 0;
            if (app.detail_col < 0) app.detail_col = 0;
            std::string title = app.show_task ? app.show_task->title : app.static_title;
            std::string note = "line " + std::to_string(app.detail_row + 1) + "/" +
                               std::to_string(total) + "  col " +
                               std::to_string(app.detail_col);
            if (app.show_task)
                note += app.detail_show_raw ? "  [raw json]" : "  [text]  J raw";
            if (!app.detail_needle.empty()) note += "  find:" + app.detail_needle;
            draw_title(title, note);
            draw_help("Up/Down/PgUp/PgDn scroll  Left/Right pan  Home/End  / find  n next  J raw json  Esc/b back");
            draw_textview(*lines, app.detail_row, app.detail_col, first_row, height, cols);
            break;
        }

        case tui::Page::Confirm:
            break;
    }

    set_attr(tui::Attr::Normal);
    const bool error = !app.last_error.empty();
    draw_status(error ? app.last_error : app.status_message, error);
    set_attr(tui::Attr::Normal);
    refresh();
}

void handle_arrow(int key, int& sel, std::size_t total) {
    const int count = static_cast<int>(total);
    if (count == 0) return;
    if (key == KEY_UP || key == 'k') sel = sel > 0 ? sel - 1 : 0;
    else if (key == KEY_DOWN || key == 'j') sel = sel < count - 1 ? sel + 1 : count - 1;
    else if (key == KEY_PPAGE || key == KEY_BACKSPACE) sel = std::max(0, sel - 10);
    else if (key == KEY_NPAGE || key == ' ') sel = std::min(count - 1, sel + 10);
    else if (key == KEY_HOME) sel = 0;
    else if (key == KEY_END || key == 'G') sel = count - 1;
}

void open_function(tui::App& app, const std::string& view) {
    if (app.functions.empty()) return;
    const auto& f = app.functions[static_cast<std::size_t>(app.fn_sel)];
    const std::string title = "function " + f.address +
                              (f.name.empty() ? "" : (" " + f.name));
    app.run_function_view(f.address, view, title);
}

std::string expand_home(const std::string& path) {
    if (path.empty() || path.front() != '~') return path;
    if (path.size() == 1 || path[1] == '/') {
        const char* home = std::getenv("HOME");
        if (home && *home) {
            std::string out = home;
            if (path.size() > 1) out += path.substr(1);
            return out;
        }
    }
    return path;
}

void try_import(tui::App& app) {
    const auto path = tui::prompt_line("target file path", "");
    if (!path || path->empty()) return;
    std::string expanded = expand_home(*path);
    if (!app.import_target(expanded)) app.set_status("[!] " + app.last_error);
    else app.set_status("imported " + expanded);
}

void handle_query_form(tui::App& app, int key) {
    const int field_count = static_cast<int>(g_query.fields.size());
    const auto run = [&app] {
        app.run_query(g_query.fields[0].value, g_query.fields[1].value,
                      g_query.fields[2].value, g_query.fields[3].value);
    };
    if (key == KEY_UP || key == 'k') g_query.sel = std::max(0, g_query.sel - 1);
    else if (key == KEY_DOWN || key == 'j') g_query.sel = std::min(field_count, g_query.sel + 1);
    else if (key == 'r' || key == 'R') {
        run();
    } else if (key == KEY_ENTER || key == '\n' || key == '\r') {
        if (g_query.sel >= field_count) {
            run();
        } else {
            const int field = g_query.sel;
            auto& f = g_query.fields[static_cast<std::size_t>(field)];
            const auto edited = tui::prompt_line(f.label, f.value);
            if (edited) f.value = *edited;
            g_query.sel = std::min(field_count, g_query.sel + 1);
        }
    } else if (key == 27 || key == 'b' || key == 'B') {
        app.go_back();
    }
}

}  // namespace

int main(int argc, char** argv) {
    std::string workspace = ".indago";
    std::string open_project;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--workspace" && i + 1 < argc) workspace = argv[++i];
        else if (arg == "--project" && i + 1 < argc) open_project = argv[++i];
        else if (arg == "--help") {
            std::cout << "IndagoRev terminal workbench\n"
                      << "  indago-tui [--workspace DIR] [--project NAME]\n";
            return 0;
        }
    }

    if (!tui::ui_init()) {
        std::cerr << "indago-tui: cannot initialize the terminal\n";
        return 1;
    }

    tui::App app(workspace);

    if (!open_project.empty()) {
        if (app.open_project(open_project)) {
            app.push_page(tui::Page::Targets);
        } else if (!app.last_error.empty()) {
            app.set_status("[!] " + app.last_error);
        }
    }

    bool quitting = false;
    unsigned tick = 0;
    render(app, tick);
    while (true) {
        if (quitting) break;
        if (app.task) timeout(120);
        else timeout(-1);

        const int key = getch();
        ++tick;

        if (app.finish_task()) {
            if (quitting) break;
            app.push_page(tui::Page::Detail);
            render(app, tick);
            continue;
        }

        if (key == ERR) {
            if (app.task) render(app, tick);
            continue;
        }

        if (key == KEY_RESIZE) {
            erase();
            render(app, tick);
            continue;
        }

        if (app.busy()) {
            if ((key == 'q' || key == 'Q') && tui::confirm_yesno("Cancel running job and quit?")) {
                app.request_cancel();
                quitting = true;
            } else if (key == 27) {
                app.request_cancel();
                app.set_status("cancellation requested");
            }
            render(app, tick);
            continue;
        }

        // Each user action starts from a clean slate so a previous failure
        // cannot mask a later success on the status line.
        app.last_error.clear();

        const bool global_back =
            key == 27 || key == 'b' || key == 'B' || key == KEY_LEFT;

        switch (app.page) {
            case tui::Page::Projects:
                if (key == 'q' || key == 'Q') {
                    if (tui::confirm_yesno("Quit IndagoRev TUI?")) quitting = true;
                } else if (key == KEY_ENTER || key == '\n' || key == '\r' || key == KEY_RIGHT) {
                    if (!app.projects.empty()) {
                        const auto& p = app.projects[static_cast<std::size_t>(app.proj_sel)];
                        if (app.open_project(p.name)) {
                            app.push_page(tui::Page::Targets);
                            app.set_status("project " + p.name + " opened");
                        } else if (!app.last_error.empty()) {
                            app.set_status("[!] " + app.last_error);
                        }
                    }
                } else if (key == 'n') {
                    const auto name = tui::prompt_line("new project name", "");
                    if (name && !name->empty()) {
                        if (!app.create_project(*name)) app.set_status("[!] " + app.last_error);
                    }
                } else if (key == 'i') {
                    if (app.project.empty()) {
                        if (app.projects.empty()) {
                            app.set_status("no projects yet - press n to create one");
                        } else {
                            const auto& p = app.projects[static_cast<std::size_t>(app.proj_sel)];
                            if (app.open_project(p.name)) {
                                app.push_page(tui::Page::Targets);
                                app.refresh_targets();
                                app.set_status("project " + p.name +
                                               " opened - choose a target file to import");
                            } else if (!app.last_error.empty()) {
                                app.set_status("[!] " + app.last_error);
                            }
                        }
                    } else {
                        try_import(app);
                    }
                } else if (key == 'c' || key == 'C') {
                    app.show_static("capabilities", app.capabilities_lines());
                } else if (key == 'r' || key == 'R' || key == KEY_F(5)) {
                    app.refresh_projects();
                } else handle_arrow(key, app.proj_sel, app.projects.size());
                break;

            case tui::Page::Targets:
                if (key == 'a' || key == 'A') {
                    app.run_analysis();
                    app.set_status("analysis submitted");
                } else if (key == 'i') {
                    try_import(app);
                } else if (key == KEY_ENTER || key == '\n' || key == '\r' || key == KEY_RIGHT) {
                    if (!app.targets.empty()) {
                        app.pick_target(static_cast<std::size_t>(app.tgt_sel));
                        app.set_status("active target: " + app.targets[static_cast<std::size_t>(app.tgt_sel)].name);
                    }
                } else if (key == 'g') {
                    app.refresh_functions();
                    app.push_page(tui::Page::Functions);
                } else if (key == 'e') {
                    app.refresh_evidence();
                    app.push_page(tui::Page::Evidence);
                } else if (key == 'J') {
                    app.refresh_jobs();
                    app.push_page(tui::Page::Jobs);
                } else if (key == 'h') {
                    app.refresh_harness();
                    app.push_page(tui::Page::Harness);
                } else if (key == 'q') {
                    app.push_page(tui::Page::QueryForm);
                } else if (key == 'p' || key == 'P') {
                    app.show_static("project info", app.project_json_lines());
                } else if (key == 'c' || key == 'C') {
                    app.show_static("capabilities", app.capabilities_lines());
                } else if (key == 'r' || key == 'R' || key == KEY_F(5)) {
                    app.refresh_targets();
                } else if (global_back) {
                    app.go_back();
                } else handle_arrow(key, app.tgt_sel, app.targets.size());
                break;

            case tui::Page::Functions:
                if (key == KEY_ENTER || key == '\n' || key == '\r') {
                    open_function(app, "disassembly");
                } else if (key == 'd' || key == 'D') {
                    open_function(app, "disassembly");
                } else if (key == 'p' || key == 'P') {
                    open_function(app, "pseudocode");
                } else if (key == 'x' || key == 'X') {
                    if (!app.functions.empty()) {
                        const auto& f = app.functions[static_cast<std::size_t>(app.fn_sel)];
                        app.run_query("xair", "cfg", f.address, "compact");
                    }
                } else if (key == 'f') {
                    const auto filter = tui::prompt_line("filter by address substring", app.fn_filter);
                    if (filter) {
                        app.fn_filter = *filter;
                        app.refresh_functions();
                        app.set_status(app.fn_filter.empty() ? "filter cleared" : "filter: " + app.fn_filter);
                    }
                } else if (key == 'F') {
                    app.fn_filter.clear();
                    app.refresh_functions();
                } else if (key == 't') {
                    app.push_page(tui::Page::Targets);
                } else if (key == 'e') {
                    app.refresh_evidence();
                    app.push_page(tui::Page::Evidence);
                } else if (key == 'J') {
                    app.refresh_jobs();
                    app.push_page(tui::Page::Jobs);
                } else if (key == 'q') {
                    app.push_page(tui::Page::QueryForm);
                } else if (global_back) {
                    app.go_back();
                } else handle_arrow(key, app.fn_sel, app.functions.size());
                break;

            case tui::Page::Evidence:
                if (key == KEY_ENTER || key == '\n' || key == '\r') {
                    if (!app.evidence_rows.empty()) {
                        const auto& e = app.evidence_rows[static_cast<std::size_t>(app.ev_sel)];
                        app.show_static("evidence " + e.id, app.evidence_detail_lines(e));
                    }
                } else if (key == 't') {
                    app.push_page(tui::Page::Targets);
                } else if (key == 'g') {
                    app.refresh_functions();
                    app.push_page(tui::Page::Functions);
                } else if (key == 'J') {
                    app.refresh_jobs();
                    app.push_page(tui::Page::Jobs);
                } else if (key == 'q') {
                    app.push_page(tui::Page::QueryForm);
                } else if (key == 'r' || key == KEY_F(5)) {
                    app.refresh_evidence();
                } else if (global_back) {
                    app.go_back();
                } else handle_arrow(key, app.ev_sel, app.evidence_rows.size());
                break;

            case tui::Page::Jobs:
                if (key == KEY_ENTER || key == '\n' || key == '\r') {
                    if (!app.job_rows.empty()) {
                        const auto& j = app.job_rows[static_cast<std::size_t>(app.job_sel)];
                        app.show_static("job " + j.id, app.job_detail_lines(j));
                    }
                } else if (key == 'k' || key == 'K') {
                    if (!app.job_rows.empty() && tui::confirm_yesno("Cancel selected job?")) {
                        const auto& j = app.job_rows[static_cast<std::size_t>(app.job_sel)];
                        try {
                            auto r = app.service().store().cancel_job(app.project, j.id);
                            app.set_status("job " + j.id + " -> " + r.value("status", std::string{}));
                        } catch (const std::exception& e) {
                            app.set_status("[!] " + std::string(e.what()));
                        }
                        app.refresh_jobs();
                    }
                } else if (key == 't') {
                    app.push_page(tui::Page::Targets);
                } else if (key == 'g') {
                    app.refresh_functions();
                    app.push_page(tui::Page::Functions);
                } else if (key == 'e') {
                    app.refresh_evidence();
                    app.push_page(tui::Page::Evidence);
                } else if (key == 'r' || key == KEY_F(5)) {
                    app.refresh_jobs();
                } else if (key == 'q') {
                    app.push_page(tui::Page::QueryForm);
                } else if (global_back) {
                    app.go_back();
                } else handle_arrow(key, app.job_sel, app.job_rows.size());
                break;

            case tui::Page::Harness:
                if (key == KEY_ENTER || key == '\n' || key == '\r') {
                    if (!app.harness_rows.empty()) {
                        const auto& h = app.harness_rows[static_cast<std::size_t>(app.hn_sel)];
                        app.show_static("investigation " + h.id, app.harness_show_lines(h));
                    }
                } else if (key == 'n') {
                    const auto objective = tui::prompt_line("objective", "");
                    if (objective && !objective->empty()) {
                        std::string mode = "builtin";
                        std::string model;
                        std::string endpoint;
                        if (app.project.empty()) {
                            app.set_status("[!] open a project first");
                        } else {
                            const auto mode_in = tui::prompt_line("owner mode [builtin/external]", "builtin");
                            if (mode_in && !mode_in->empty()) mode = *mode_in;
                            if (mode == "builtin") {
                                const auto model_in = tui::prompt_line("model", "qwen2.5-coder:14b");
                                if (model_in && !model_in->empty()) model = *model_in;
                                const auto endpoint_in =
                                    tui::prompt_line("endpoint",
                                                     "http://127.0.0.1:8080/v1/chat/completions");
                                if (endpoint_in && !endpoint_in->empty()) endpoint = *endpoint_in;
                            }
                            std::vector<std::string> facts;
                            const auto facts_in = tui::prompt_line("required facts (comma separated)", "");
                            if (facts_in) {
                                std::stringstream fs(*facts_in);
                                std::string fact;
                                while (std::getline(fs, fact, ',')) {
                                    const auto b = fact.find_first_not_of(" \t");
                                    if (b == std::string::npos) continue;
                                    const auto e = fact.find_last_not_of(" \t");
                                    facts.push_back(fact.substr(b, e - b + 1));
                                }
                            }
                            long max_actions = 8;
                            const auto max_in = tui::prompt_line("max actions", "8");
                            if (max_in && !max_in->empty()) {
                                try {
                                    max_actions = std::stol(*max_in);
                                } catch (...) {
                                    max_actions = 8;
                                }
                            }
                            if (!app.create_investigation(*objective, facts, mode, model,
                                                          endpoint, max_actions)) {
                                if (!app.last_error.empty())
                                    app.set_status("[!] " + app.last_error);
                            }
                        }
                    }
                } else if (key == 'r') {
                    app.run_explore();
                } else if (key == 'a') {
                    if (!app.harness_rows.empty()) {
                        const auto& h = app.harness_rows[static_cast<std::size_t>(app.hn_sel)];
                        app.show_static("actions " + h.id, app.harness_records_lines("actions", h));
                    }
                } else if (key == 'e') {
                    if (!app.harness_rows.empty()) {
                        const auto& h = app.harness_rows[static_cast<std::size_t>(app.hn_sel)];
                        app.show_static("events " + h.id, app.harness_records_lines("events", h));
                    }
                } else if (key == 'R' || key == KEY_F(5)) {
                    app.refresh_harness();
                } else if (key == 't') {
                    app.push_page(tui::Page::Targets);
                } else if (key == 'g') {
                    app.refresh_functions();
                    app.push_page(tui::Page::Functions);
                } else if (key == 'e') {
                    app.refresh_evidence();
                    app.push_page(tui::Page::Evidence);
                } else if (key == 'J') {
                    app.refresh_jobs();
                    app.push_page(tui::Page::Jobs);
                } else if (key == 'q') {
                    app.push_page(tui::Page::QueryForm);
                } else if (global_back) {
                    app.go_back();
                } else handle_arrow(key, app.hn_sel, app.harness_rows.size());
                break;

            case tui::Page::QueryForm:
                handle_query_form(app, key);
                break;

            case tui::Page::Detail:
                if (key == KEY_UP || key == 'k') {
                    if (app.detail_row > 0) --app.detail_row;
                } else if (key == KEY_DOWN || key == 'j') {
                    ++app.detail_row;
                } else if (key == KEY_PPAGE || key == '-') {
                    app.detail_row = std::max(0, app.detail_row - 20);
                } else if (key == KEY_NPAGE || key == ' ') {
                    app.detail_row += 20;
                } else if (key == KEY_HOME) {
                    app.detail_row = 0;
                } else if (key == KEY_END) {
                    app.detail_row = 1000000000;
                } else if (key == KEY_LEFT || key == 'h') {
                    app.detail_col = std::max(0, app.detail_col - 8);
                } else if (key == KEY_RIGHT || key == 'l') {
                    app.detail_col += 8;
                } else if (key == 'J') {
                    const std::vector<std::string>* raw = nullptr;
                    detail_main(app, &raw);
                    if (raw) app.detail_show_raw = !app.detail_show_raw;
                    app.detail_row = 0;
                    app.detail_col = 0;
                } else if (key == '/') {
                    const auto needle = tui::prompt_line("find", "");
                    if (needle) {
                        app.detail_needle = *needle;
                        if (needle->empty()) {
                            app.set_status("find cleared");
                        } else {
                            const auto* lines = detail_main(app, nullptr);
                            int total = 0;
                            int first = -1;
                            for (std::size_t i = 0; i < lines->size(); ++i) {
                                if (lines->at(i).find(*needle) != std::string::npos) {
                                    ++total;
                                    if (first < 0) first = static_cast<int>(i);
                                }
                            }
                            if (total == 0) {
                                app.set_status("[!] no match for " + *needle);
                            } else {
                                app.detail_row = first;
                                app.detail_col = 0;
                                app.set_status("found " + std::to_string(total) +
                                               " match" + (total == 1 ? "" : "es") +
                                               " for " + *needle + "  (n next)");
                            }
                        }
                    }
                } else if (key == 'n') {
                    if (app.detail_needle.empty()) {
                        app.set_status("press / to search");
                    } else {
                        const auto* lines = detail_main(app, nullptr);
                        const int total_lines = static_cast<int>(lines->size());
                        int hit = -1;
                        for (int i = app.detail_row + 1; i < total_lines; ++i) {
                            if (lines->at(static_cast<std::size_t>(i)).find(app.detail_needle) !=
                                std::string::npos) {
                                hit = i;
                                break;
                            }
                        }
                        if (hit < 0) {
                            for (int i = 0; i <= app.detail_row && i < total_lines; ++i) {
                                if (lines->at(static_cast<std::size_t>(i)).find(app.detail_needle) !=
                                    std::string::npos) {
                                    hit = i;
                                    break;
                                }
                            }
                        }
                        if (hit < 0) {
                            app.set_status("[!] no match for " + app.detail_needle);
                        } else {
                            app.detail_row = hit;
                            app.set_status("line " + std::to_string(hit + 1) + ": " +
                                           app.detail_needle);
                        }
                    }
                } else if (global_back) {
                    app.go_back();
                }
                break;

            case tui::Page::Confirm:
                break;
        }

        render(app, tick);
    }

    tui::ui_end();
    return 0;
}