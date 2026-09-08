#include "indago/core.hpp"

#if INDAGO_HAS_XAIR
#include <xair/xair_binary.h>
#include <xair_cfg/xair_cfg.h>
#endif

#include <sstream>

namespace indago {

CommandResult analyze_xair(const TargetRecord& target, const XairOptions& requested) {
#if !INDAGO_HAS_XAIR
    return {3, "unavailable", "{\"schema\":\"indago.xair-result.v1\",\"status\":\"unavailable\"}"};
#else
    xair_cfg_profile profile = XAIR_CFG_PROFILE_BALANCED;
    if (requested.profile == "fast") profile = XAIR_CFG_PROFILE_FAST;
    else if (requested.profile == "exhaustive") profile = XAIR_CFG_PROFILE_EXHAUSTIVE;

    xair_binary_load_options load_options{};
    xair_binary_load_options_init(&load_options);
    load_options.analysis.max_bytes = target.size;
    load_options.analysis.max_memory = static_cast<std::size_t>(requested.memory_bytes);
    load_options.analysis.max_wall_time = requested.wall_time_ms;
    xair_binary_view binary{};
    xair_analysis_result load_result{};
    xair_diagnostic diagnostic{};
    const auto load_status = xair_binary_view_load_path_ex(
        target.object_path.string().c_str(), &load_options, &binary, &load_result, &diagnostic);
    if (load_status != XAIR_OK) {
        std::ostringstream out;
        out << "{\"schema\":\"indago.xair-result.v1\",\"status\":\"failed\","
            << "\"stage\":\"load\",\"xair_status\":" << quote(xair_status_name(load_status))
            << ",\"diagnostic\":" << quote(diagnostic.message ? diagnostic.message : "binary load failed") << "}";
        return {1, "failed", out.str()};
    }

    xair_cfg_options options{};
    xair_cfg_options_init(&options, profile);
    options.analysis.max_memory = static_cast<std::size_t>(requested.memory_bytes);
    options.analysis.max_wall_time = requested.wall_time_ms;
    xair_cfg_builder* builder = nullptr;
    xair_cfg* cfg = nullptr;
    xair_cfg_stats stats{};
    xair_error error{};
    auto status = xair_cfg_builder_create(&binary, &options, &builder);
    if (status == XAIR_OK) status = xair_cfg_add_binary_roots(builder, &error);
    if (status == XAIR_OK) status = xair_cfg_build(builder, &cfg, &stats, &error);

    if (status != XAIR_OK) {
        std::ostringstream out;
        out << "{\"schema\":\"indago.xair-result.v1\",\"status\":\"failed\","
            << "\"stage\":\"cfg\",\"xair_status\":" << quote(xair_status_name(status))
            << ",\"block\":" << error.block
            << ",\"diagnostic\":" << quote(error.message) << "}";
        if (builder) xair_cfg_builder_destroy(builder);
        xair_binary_view_destroy(&binary);
        return {1, "failed", out.str()};
    }

    const auto* completeness = xair_cfg_completeness_summary(cfg);
    const bool complete = completeness != nullptr && completeness->complete != 0;
    std::ostringstream out;
    out << "{\"schema\":\"indago.xair-result.v1\",\"status\":"
        << quote(complete ? "completed" : "partial")
        << ",\"producer\":\"XAIR/XAIR_CFG\",\"artifact_sha256\":" << quote(target.sha256)
        << ",\"format\":" << quote(xair_binary_format_name(binary.format))
        << ",\"architecture\":" << quote(xair_arch_name(binary.arch))
        << ",\"image_base\":" << quote(hex_address(binary.image_base))
        << ",\"entry\":" << quote(hex_address(binary.entry))
        << ",\"statistics\":{\"blocks\":" << stats.final_blocks
        << ",\"edges\":" << stats.final_edges << ",\"functions\":" << stats.final_functions
        << ",\"calls\":" << stats.call_sites << ",\"instructions\":" << stats.instructions_decoded
        << ",\"memory_bytes\":" << stats.memory_bytes << "},\"completeness\":{";
    if (completeness) {
        out << "\"complete\":" << (complete ? "true" : "false")
            << ",\"exact_blocks\":" << completeness->nodes_exact
            << ",\"partial_blocks\":" << completeness->nodes_partial
            << ",\"opaque_blocks\":" << completeness->nodes_opaque
            << ",\"unresolved_indirects\":" << completeness->unresolved_indirects
            << ",\"skipped_items\":" << completeness->skipped_items;
    }
    out << "},\"functions\":[";
    const auto count = xair_cfg_function_count(cfg);
    for (std::size_t index = 0; index < count; ++index) {
        const auto* function = xair_cfg_get_function(cfg, static_cast<xair_function_id>(index));
        if (!function) continue;
        if (index != 0) out << ',';
        const char* coverage = function->semantic_coverage == XAIR_CFG_SEMANTICS_EXACT ? "exact" :
            (function->semantic_coverage == XAIR_CFG_SEMANTICS_PARTIAL ? "partial" : "opaque");
        out << "{\"id\":" << quote("xair_fn_" + std::to_string(index))
            << ",\"address\":" << quote(hex_address(function->entry))
            << ",\"name\":" << quote(function->name ? function->name : "")
            << ",\"blocks\":" << function->node_count
            << ",\"calls\":" << function->call_edge_count
            << ",\"semantic_coverage\":" << quote(coverage) << '}';
    }
    out << "]}";

    xair_cfg_destroy(cfg);
    xair_cfg_builder_destroy(builder);
    xair_binary_view_destroy(&binary);
    return {complete ? 0 : 3, complete ? "completed" : "partial", out.str()};
#endif
}

} // namespace indago
