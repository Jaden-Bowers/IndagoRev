#include "indago/contracts.hpp"
#include "workbench_db.hpp"

namespace indago {
nlohmann::json workbench_capabilities() {
  return {{"schema", "indago.workbench-capabilities.v1"},
          {"native", true},
          {"model_calls", false},
          {"target_execution", false},
          {"families",
           {{"knowledge", {"put", "show", "list", "refresh", "impact"}},
            {"graph", {"search", "neighborhood", "packet", "event"}},
            {"coverage", {"report"}},
            {"system", {"create", "show", "list", "preflight"}},
            {"recognize", {"scan"}},
            {"transform", {"run"}},
            {"validate", {"compare", "transform"}},
            {"batch", {"create", "show", "run", "cancel", "events"}},
            {"bundle", {"export", "import"}},
            {"retention", {"plan", "quarantine"}}}},
          {"limits",
           {{"request_bytes", 1048576},
            {"knowledge_record_bytes", 262144},
            {"dependency_count", 128},
            {"graph_hops", 8},
            {"graph_nodes", 1000},
            {"batch_steps", 64},
            {"batch_execution", "sequential read analysis only"},
            {"transform_input_bytes", 4194304},
            {"validation_cases", 64}}},
          {"semantics", "No automatic semantic entailment, universal recovery, "
                        "whole-program equivalence, or sandbox is claimed"}};
}
static nlohmann::json dispatch_workbench(StaticService &service,
                                         std::string_view family,
                                         std::string_view operation,
                                         const nlohmann::json &request) {
  using namespace wb;
  if (!request.is_object() || request.dump().size() > 1024 * 1024)
    throw std::runtime_error("workbench request must be an object <=1 MiB");
  auto op = std::string(operation);
  if (family == "workbench" && op == "capabilities")
    return workbench_capabilities();
  const auto &store = service.store();
  if (family == "knowledge")
    return knowledge(store, op, request);
  if (family == "system")
    return system_manifest(store, op, request);
  if (family == "graph")
    return graph(store, op, request);
  if (family == "coverage" && op == "report")
    return coverage(store, request);
  if (family == "recognize" || family == "transform" || family == "validate")
    return artifacts(store, std::string(family), op, request);
  if (family == "batch")
    return batch(service, op, request);
  if (family == "bundle")
    return bundles(store, op, request);
  if (family == "retention" && (op == "plan" || op == "quarantine")) {
    auto r = request;
    r["apply"] = op == "quarantine";
    return bundles(store, "retention", r);
  }
  throw std::runtime_error("unknown workbench operation");
}
nlohmann::json workbench_action(StaticService &service, std::string_view family,
                                std::string_view operation,
                                const nlohmann::json &request) {
  try {
    validate_contract(
        "workbench",
        {{"family", family}, {"operation", operation}, {"request", request}});
    auto result = dispatch_workbench(service, family, operation, request);
    const auto ceiling = family == "graph" ? wb::bound(request, "output_bytes",
                                                       262144, 2 * 1024 * 1024)
                                           : 2 * 1024 * 1024;
    while (result.dump().size() > ceiling) {
      bool removed = false;
      for (const char *field :
           {"records", "findings", "gaps", "events", "disagreements", "claims",
            "relationships", "nodes", "steps"})
        if (result.contains(field) && result[field].is_array() &&
            !result[field].empty()) {
          result[field].erase(result[field].end() - 1);
          result["partial"] = true;
          result["output_limited"] = true;
          removed = true;
          if (std::string_view(field) == "records" && operation != "impact")
            result["next_offset"] =
                request.value("offset", 0ULL) + result[field].size();
          break;
        }
      if (!removed) {
        result = {{"schema", "indago.workbench-output.v1"},
                  {"partial", true},
                  {"output_limited", true},
                  {"id", result.value("id", wb::J{})},
                  {"diagnostic",
                   "Result persisted or query completed; payload exceeds "
                   "output budget. Retrieve a narrower page or record."}};
        break;
      }
    }
    return result;
  } catch (const std::exception &error) {
    std::string message = error.what(), code = "invalid_request";
    if (message.find("revision_conflict") != message.npos ||
        message.find("pin is stale") != message.npos)
      code = "revision_conflict";
    else if (message.find("integrity") != message.npos ||
             message.find("hash mismatch") != message.npos)
      code = "integrity_failure";
    else if (message.find("ownership") != message.npos ||
             message.find("active owner") != message.npos ||
             message.find("storage busy") != message.npos ||
             message.find("database is locked") != message.npos)
      code = "busy_or_ownership_lost";
    else if (message.find("budget") != message.npos ||
             message.find("exceeds") != message.npos)
      code = "resource_limit";
    else if (message.find("unknown project") != message.npos ||
             message.find("unknown knowledge") != message.npos ||
             message.find("unknown batch") != message.npos)
      code = "not_found";
    throw WorkbenchError(code, message);
  }
}
} // namespace indago
