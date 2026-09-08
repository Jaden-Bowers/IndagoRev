#include "indago/sym.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <chrono>
#include <regex>
#include <set>
namespace indago {
CommandResult query_sym(const TargetRecord& target, const SymOptions& options) {
    using Json = nlohmann::ordered_json;
    auto invalid = [](const std::string& message) {
        return CommandResult{2, "invalid_request", Json{{"schema", "indago.sym-result.v1"}, {"status", "invalid_request"}, {"diagnostic", message}}.dump()};
    };
    if (!options.max_states || !options.max_queries || !options.max_paths || !options.solver_time_ms || !options.wall_time_ms || options.max_output_bytes < 4096)
        return invalid("symbolic budgets must be positive and output budget at least 4096 bytes");
    AireceOptions request;
    request.wall_time_ms = options.wall_time_ms;
    request.max_output_bytes = options.max_output_bytes / 2;
    request.cancel_file = options.cancel_file;
    request.executable = options.executable;
    request.address = options.address;
    request.view = "json";
    request.arguments = {{"max-states", std::to_string(options.max_states)}, {"max-queries", std::to_string(options.max_queries)}, {"symbolic-timeout-ms", std::to_string(std::min(options.solver_time_ms, options.wall_time_ms))}};
    std::string scope;
    if (options.operation == "solve_branch") {
        if (options.address.empty()) return invalid("solve_branch requires a containing function address");
        request.operation = "function"; request.arguments["symbolic"] = "";
        if (!options.function.empty()) request.address = options.function;
        scope = "expression-local branch satisfiability; no predecessor constraints or reachability proof";
    } else if (options.operation == "source_to_sink" || options.operation == "path_condition") {
        if (options.source.empty() || options.sink.empty()) return invalid("source and sink native selectors are required");
        request.operation = "flow"; request.address.clear();
        request.arguments["source"] = options.source; request.arguments["target"] = options.sink;
        request.arguments["mode"] = "symbolic";
        request.arguments["function-depth"] = std::to_string(options.function_depth);
        request.arguments["max-paths"] = std::to_string(options.max_paths);
        scope = options.operation == "path_condition" ? "native bounded path and constraints in AIRECE flow result" : "native bounded directed symbolic flow";
    } else if (options.operation == "taint") {
        if (!options.source.empty() && !options.sink.empty()) {
            request.operation = "flow"; request.address.clear();
            request.arguments["source"] = options.source; request.arguments["target"] = options.sink;
            request.arguments["mode"] = "taint-symbolic";
            request.arguments["function-depth"] = std::to_string(options.function_depth);
            request.arguments["max-paths"] = std::to_string(options.max_paths);
            scope = "native bounded directed taint with symbolic refinement";
        } else {
            if (options.address.empty()) return invalid("taint requires function address or source and sink selectors");
            request.operation = "taint"; request.arguments["symbolic"] = "";
            scope = "native function-local XAIR_SYM taint enrichment";
        }
    } else if (options.operation == "symbolic_slice") {
        if (options.address.empty() || options.function.empty()) return invalid("symbolic_slice requires seed address and containing function address");
        request.operation = "slice"; request.arguments.clear();
        scope = "native backward dependence slice with symbolic findings joined by XAIR value/evidence IDs; conservative, not a path-sensitive slice proof";
    } else return invalid("unsupported symbolic operation");
    const auto started = std::chrono::steady_clock::now();
    auto result = run_airece(target, request);
    if (result.status == "complete") result.status = "completed";
    Json out{{"schema", "indago.sym-result.v1"}, {"producer", "AIRECE/XAIR_SYM"}, {"operation", options.operation}, {"status", result.status}, {"scope", scope}, {"native", Json::parse(result.json)}};
    if (options.operation == "solve_branch" && out["native"].contains("native")) {
        const auto native = out["native"]["native"];
        out["branch_findings"] = Json::array();
        std::set<std::string> evidence;
        for (const auto& statement : native.value("statements", Json::array()))
            if (statement.value("kind", "") == "branch" && (options.function.empty() || statement.value("address", "") == options.address)) evidence.insert(statement.value("evidence", ""));
        if (native.contains("enrichment")) for (const auto& finding : native["enrichment"].value("symbolic", Json::array()))
            if (evidence.count(finding.value("evidence", ""))) out["branch_findings"].push_back(finding);
        out["requested_branch"] = options.function.empty() ? Json(nullptr) : Json(options.address);
        if (out["branch_findings"].empty()) { result.exit_code = 3; result.status = "partial"; out["status"] = result.status; out["diagnostic"] = "no matching native branch finding; result is unknown"; }
    }
    if (options.operation == "symbolic_slice" && (result.exit_code == 0 || result.exit_code == 3)) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
        if (static_cast<std::uint64_t>(elapsed) >= options.wall_time_ms) {
            result.exit_code = 3; result.status = "partial";
            out["symbolic_findings"] = {{"status", "timeout"}};
        } else {
            request.operation = "function"; request.address = options.function;
            request.wall_time_ms = options.wall_time_ms - static_cast<std::uint64_t>(elapsed);
            request.arguments = {{"symbolic", ""}, {"max-states", std::to_string(options.max_states)}, {"max-queries", std::to_string(options.max_queries)}, {"symbolic-timeout-ms", std::to_string(std::min(options.solver_time_ms, request.wall_time_ms))}};
            auto enrichment = run_airece(target, request);
            const auto envelope = Json::parse(enrichment.json);
            out["symbolic_findings"] = Json::array();
            const std::string slice = out["native"].value("native_output", "");
            std::set<std::uint64_t> values;
            const std::regex value_pattern("\\bv([0-9]+)\\b");
            for (std::sregex_iterator i(slice.begin(), slice.end(), value_pattern), end; i != end; ++i) values.insert(std::stoull((*i)[1].str()));
            if (envelope.contains("native") && envelope["native"].contains("enrichment")) {
                const auto& native = envelope["native"]["enrichment"];
                out["enrichment_completion"] = native.value("completion", "unknown");
                out["solver_initialized"] = native.value("solver_initialized", false);
                for (const auto& finding : native.value("symbolic", Json::array())) {
                    const auto evidence = finding.value("evidence", "");
                    if (values.count(finding.value("value", std::uint64_t(-1))) || (!evidence.empty() && slice.find(evidence) != std::string::npos)) out["symbolic_findings"].push_back(finding);
                }
            }
            if (out["symbolic_findings"].empty()) { result.exit_code = 3; result.status = "partial"; out["diagnostic"] = "no symbolic findings for slice; native dependence slice retained"; }
            if (enrichment.exit_code != 0) { result.exit_code = 3; result.status = "partial"; }
        }
        out["status"] = result.status;
    }
    auto json = out.dump();
    if (json.size() > options.max_output_bytes) {
        return {3, "partial", Json{{"schema", "indago.sym-result.v1"}, {"operation", options.operation}, {"status", "partial"}, {"truncated", true}, {"diagnostic", "symbolic response exceeded output budget"}}.dump()};
    }
    return {result.exit_code, result.status, std::move(json)};
}
}
