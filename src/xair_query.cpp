#include "indago/xair.hpp"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <chrono>
#include <set>
#include <thread>
#if INDAGO_HAS_XAIR
#include <xair_cfg/xair_cfg.h>
#endif

namespace indago {
using Json = nlohmann::ordered_json;
#if INDAGO_HAS_XAIR
namespace {
struct Analysis {
    xair_binary_view binary{};
    xair_cfg_builder* builder{};
    xair_cfg* cfg{};
    xair_cancel_token* cancel{};
    ~Analysis() {
        if (cfg) xair_cfg_destroy(cfg);
        if (builder) xair_cfg_builder_destroy(builder);
        xair_binary_view_destroy(&binary);
        if (cancel) xair_cancel_token_destroy(cancel);
    }
};
const char* coverage(xair_cfg_semantic_coverage v) {
    return v == XAIR_CFG_SEMANTICS_EXACT ? "exact" : v == XAIR_CFG_SEMANTICS_PARTIAL ? "partial" : "opaque";
}
Json location(const TargetRecord& target, std::uint64_t address) {
    return {{"artifact_sha256", target.sha256}, {"address", hex_address(address)}, {"address_space", "virtual"}};
}
struct Budget {
    std::size_t items{}, bytes{}, maximum_items{}, maximum_bytes{};
    bool truncated{};
    const xair_cancel_token* cancel{};
    bool add(Json& array, Json item) {
        if (xair_cancel_token_requested(cancel)) { truncated = true; return false; }
        const auto size = item.dump().size() + 1;
        if (items >= maximum_items || bytes + size > maximum_bytes) { truncated = true; return false; }
        ++items; bytes += size; array.push_back(std::move(item)); return true;
    }
};
}
#endif

CommandResult query_xair(const TargetRecord& target, const XairQuery& query) {
#if !INDAGO_HAS_XAIR
    return {3, "unavailable", "{\"status\":\"unavailable\",\"producer\":\"XAIR\"}"};
#else
    if (query.operation != "cfg" && query.operation != "semantic" && query.operation != "inventory")
        return {2, "invalid_request", "{\"status\":\"invalid_request\",\"diagnostic\":\"operation must be cfg or semantic\"}"};
    if (query.max_output_bytes < 2048 || !query.max_items || !query.analysis.wall_time_ms || !query.analysis.memory_bytes)
        return {2, "invalid_request", "{\"status\":\"invalid_request\",\"diagnostic\":\"max_output_bytes >= 2048 and max_items > 0 required\"}"};
    Analysis a;
    xair_cancel_token_create(&a.cancel);
    const auto started = std::chrono::steady_clock::now();
    std::atomic_bool timed_out{false};
    if (query.cancellation && query.cancellation->load()) xair_cancel_token_request(a.cancel);
    std::jthread watcher([&](std::stop_token stop) {
        while (!stop.stop_requested()) {
            if (query.cancellation && query.cancellation->load()) { xair_cancel_token_request(a.cancel); return; }
            if (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count() >= query.analysis.wall_time_ms) {
                timed_out = true; xair_cancel_token_request(a.cancel); return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    });
    xair_binary_load_options load{}; xair_binary_load_options_init(&load);
    load.analysis.max_bytes = target.size;
    load.analysis.max_memory = static_cast<std::size_t>(query.analysis.memory_bytes);
    load.analysis.max_wall_time = query.analysis.wall_time_ms;
    load.analysis.cancel_token = a.cancel;
    xair_analysis_result native{}; xair_diagnostic diagnostic{};
    auto status = xair_binary_view_load_path_ex(target.object_path.string().c_str(), &load, &a.binary, &native, &diagnostic);
    Json program{{"image_base",hex_address(a.binary.image_base)},{"entry",hex_address(a.binary.entry)},{"native_format",a.binary.format},{"native_arch",a.binary.arch},{"segments",Json::array()}};
    // Human/model-readable names for the upstream enum values, not another
    // executable loader or semantic layer. Preserve the native numbers too.
    program["format"]=a.binary.format==XAIR_BINARY_FORMAT_PE?"PE":a.binary.format==XAIR_BINARY_FORMAT_ELF?"ELF":"unknown";
    program["architecture"]=a.binary.arch==XAIR_ARCH_X86_32?"x86":a.binary.arch==XAIR_ARCH_X86_64?"x64":"unknown";
    for(std::size_t i=0;i<std::min<std::size_t>(a.binary.segment_count,128);++i){const auto& s=a.binary.segments[i];program["segments"].push_back({{"va",hex_address(s.va)},{"mem_size",s.mem_size},{"file_size",s.file_size},{"file_offset",hex_address(s.file_offset)},{"permissions",s.perms},{"section_id",s.section_id}});}
    if(a.binary.segment_count>128)program["segments_truncated"]=true;
    if(query.operation=="inventory"){
        Json inventory{{"schema","indago.xair-query.v1"},{"producer","XAIR"},{"operation","inventory"},{"artifact_sha256",target.sha256},{"program",program},{"native_status",xair_status_name(status)},{"symbols",Json::array()},{"metadata",Json::array()},{"strings",Json::array()}};
        Budget b{0,0,query.max_items,query.max_output_bytes-2048,false,a.cancel};
        for(std::size_t i=0;i<a.binary.symbol_count&&!b.truncated;++i){const auto& s=a.binary.symbols[i];b.add(inventory["symbols"],{{"location",location(target,s.va)},{"name",s.name?s.name:""},{"library",s.library?s.library:""},{"size",s.size},{"native_flags",s.flags},{"ordinal",s.ordinal}});}
        for(std::size_t i=0;i<a.binary.metadata_count&&!b.truncated;++i){const auto& m=a.binary.metadata[i];b.add(inventory["metadata"],{{"id",m.id},{"native_kind",m.kind},{"native_source",m.source},{"native_confidence",m.confidence},{"location",location(target,m.va)},{"file_offset",hex_address(m.file_offset)},{"size",m.size},{"name",m.name?m.name:""},{"module",m.module?m.module:""}});}
        for(std::size_t i=0;i<a.binary.segment_count&&!b.truncated;++i){const auto& s=a.binary.segments[i];std::size_t p=0;while(p<s.file_size&&!b.truncated){if(xair_cancel_token_requested(a.cancel))break;auto start=p;while(p<s.file_size&&s.bytes[p]>=32&&s.bytes[p]<=126&&p-start<4096)++p;if(p-start>=4)b.add(inventory["strings"],{{"location",location(target,s.va+start)},{"value",std::string(reinterpret_cast<const char*>(s.bytes+start),p-start)},{"encoding","ascii"},{"terminated",p<s.file_size&&s.bytes[p]==0},{"length",p-start}});if(p==start)++p;}}
        const auto state=timed_out?"timeout":xair_cancel_token_requested(a.cancel)?"cancelled":status!=XAIR_OK?"failed":b.truncated||a.binary.segment_count>128?"partial":"completed";
        inventory["status"]=state;inventory["truncated"]=b.truncated;auto encoded=inventory.dump();if(encoded.size()>query.max_output_bytes)return {3,"partial",Json{{"schema","indago.xair-query.v1"},{"status","partial"},{"diagnostic","inventory byte limit exceeded"}}.dump()};
        return {std::string(state)=="completed"?0:std::string(state)=="partial"?3:1,state,encoded};
    }
    xair_cfg_options options{};
    xair_cfg_options_init(&options, query.analysis.profile == "fast" ? XAIR_CFG_PROFILE_FAST : query.analysis.profile == "exhaustive" ? XAIR_CFG_PROFILE_EXHAUSTIVE : XAIR_CFG_PROFILE_BALANCED);
    options.analysis.max_memory = load.analysis.max_memory;
    options.analysis.max_wall_time = load.analysis.max_wall_time;
    options.analysis.cancel_token = a.cancel;
    xair_cfg_stats stats{}; xair_error error{};
    if (status == XAIR_OK) status = xair_cfg_builder_create(&a.binary, &options, &a.builder);
    if (status == XAIR_OK) status = xair_cfg_add_binary_roots(a.builder, &error);
    if (status == XAIR_OK) status = xair_cfg_build_ex(a.builder, &a.cfg, &stats, &native, &diagnostic);
    Json out{{"schema", "indago.xair-query.v1"}, {"producer", "XAIR/XAIR_CFG"}, {"operation", query.operation}, {"artifact_sha256", target.sha256}, {"native_status", xair_status_name(status)}, {"native_state", xair_analysis_state_name(native.state)}};
    out["program"]=program;
    if (!a.cfg) {
        const std::string state = timed_out ? "timeout" : xair_cancel_token_requested(a.cancel) ? "cancelled" : "failed";
        out["status"] = state; out["diagnostic"] = diagnostic.message ? diagnostic.message : error.message;
        return {state == "cancelled" || state == "timeout" ? 3 : 1, state, out.dump()};
    }
    Budget budget{0, 0, query.max_items, query.max_output_bytes - 2048, false, a.cancel};
    bool incomplete = status != XAIR_OK;
    const auto* completeness = xair_cfg_completeness_summary(a.cfg);
    if (completeness) {
        incomplete |= !completeness->complete;
        out["semantic_completeness"] = {{"complete", completeness->complete != 0}, {"exact_blocks", completeness->nodes_exact}, {"partial_blocks", completeness->nodes_partial}, {"opaque_blocks", completeness->nodes_opaque}, {"unresolved_indirects", completeness->unresolved_indirects}, {"skipped_items", completeness->skipped_items}};
    }
    std::set<xair_cfg_node_id> nodes;
    out["functions"] = Json::array();
    bool found = !query.function;
    for (std::size_t i = 0; i < xair_cfg_function_count(a.cfg) && !budget.truncated; ++i) {
        const auto* f = xair_cfg_get_function(a.cfg, static_cast<xair_function_id>(i));
        if (query.function && f->entry != *query.function) continue;
        found = true;
        std::size_t count{}; const auto* members = xair_cfg_function_nodes(a.cfg, static_cast<xair_function_id>(i), &count);
        Json item{{"id", i}, {"location", location(target, f->entry)}, {"name", f->name ? f->name : ""}, {"semantic_completeness", coverage(f->semantic_coverage)}, {"blocks", Json::array()}};
        for (std::size_t j = 0; j < count; ++j) {
            nodes.insert(members[j]);
            if (j < query.max_items) item["blocks"].push_back(members[j]); else { incomplete = true; }
        }
        if (!budget.add(out["functions"], std::move(item))) break;
    }
    if (!found) { out["status"] = "not_found"; return {2, "not_found", out.dump()}; }
    if (!query.function) for (std::size_t i = 0; i < xair_cfg_node_count(a.cfg); ++i) nodes.insert(static_cast<xair_cfg_node_id>(i));
    out["blocks"] = Json::array(); out["edges"] = Json::array(); out["calls"] = Json::array(); out["indirect_flow_candidates"] = Json::array();
    for (auto id : nodes) {
        const auto* n = xair_cfg_get_node(a.cfg, id);
        if (!budget.add(out["blocks"], {{"id", id}, {"location", location(target, n->start)}, {"end", hex_address(n->end)}, {"ir_block", n->ir_block}, {"semantic_completeness", coverage(n->semantic_coverage)}, {"opaque_instructions", n->opaque_instruction_count}, {"incomplete_address", hex_address(n->incomplete_address)}})) break;
    }
    for (std::size_t i = 0; i < xair_cfg_edge_count(a.cfg) && !budget.truncated; ++i) {
        const auto* e = xair_cfg_get_edge(a.cfg, static_cast<xair_cfg_edge_id>(i)); if (!nodes.count(e->src)) continue;
        budget.add(out["edges"], {{"id", i}, {"source", e->src}, {"destination", e->dst}, {"kind", xair_cfg_edge_kind_name(e->kind)}, {"confidence", xair_cfg_edge_confidence_name(e->confidence)}, {"condition", e->condition}, {"target_expression", e->target_expr}, {"target", hex_address(e->raw_target)}});
    }
    for (std::size_t i = 0; i < xair_cfg_call_site_count(a.cfg) && !budget.truncated; ++i) {
        const auto* c = xair_cfg_get_call_site(a.cfg, i); if (!nodes.count(c->node)) continue;
        budget.add(out["calls"], {{"node", c->node}, {"edge", c->edge}, {"ir_op", c->ir_op}, {"native_kind", c->kind}, {"native_flags", c->flags}, {"confidence", xair_cfg_edge_confidence_name(c->confidence)}, {"target", hex_address(c->target)}, {"continuation", hex_address(c->continuation)}, {"import_module", c->import_module ? c->import_module : ""}, {"import_name", c->import_name ? c->import_name : ""}});
    }
    for (std::size_t i = 0; i < xair_cfg_indirect_count(a.cfg) && !budget.truncated; ++i) {
        const auto* r = xair_cfg_get_indirect(a.cfg, i); const auto* edge = xair_cfg_get_edge(a.cfg, r->edge); if (!edge || !nodes.count(edge->src)) continue;
        std::size_t count{}; const auto* candidates = xair_cfg_indirect_candidates(a.cfg, i, &count);
        Json item{{"edge", r->edge}, {"native_method", r->method}, {"native_flags", r->flags}, {"confidence", xair_cfg_edge_confidence_name(r->confidence)}, {"total_candidates", count}, {"candidates", Json::array()}};
        for (std::size_t j = 0; j < std::min(count, query.max_items); ++j) item["candidates"].push_back(hex_address(candidates[j]));
        if (count > query.max_items) incomplete = true;
        budget.add(out["indirect_flow_candidates"], std::move(item));
    }
    if (query.operation == "cfg") {
        out["function_analysis"] = Json::array();
        for (std::size_t i = 0; i < xair_cfg_function_count(a.cfg) && !budget.truncated; ++i) {
            const auto* f = xair_cfg_get_function(a.cfg, static_cast<xair_function_id>(i)); if (query.function && f->entry != *query.function) continue;
            xair_cfg_function_analysis* graph{};
            auto result = xair_cfg_analyze_function_ex(a.cfg, static_cast<xair_function_id>(i), &options.analysis, &graph);
            if (result != XAIR_OK) { incomplete = true; budget.add(out["function_analysis"], {{"function", i}, {"native_status", xair_status_name(result)}}); continue; }
            std::size_t count{}; const auto* members = xair_cfg_function_nodes(a.cfg, static_cast<xair_function_id>(i), &count);
            for (std::size_t j = 0; j < count && !budget.truncated; ++j) budget.add(out["function_analysis"], {{"function", i}, {"node", members[j]}, {"reachable", xair_cfg_analysis_is_reachable(graph, members[j]) != 0}, {"immediate_dominator", xair_cfg_analysis_immediate_dominator(graph, members[j])}, {"immediate_postdominator", xair_cfg_analysis_immediate_postdominator(graph, members[j])}});
            const xair_cfg_loop* loops{}; const xair_cfg_node_id* loop_nodes{};
            auto loop_count = xair_cfg_analysis_loops(graph, &loops, &loop_nodes);
            for (std::size_t j = 0; j < loop_count && !budget.truncated; ++j) {
                Json loop{{"function", i}, {"loop_header", loops[j].header}, {"irreducible", loops[j].irreducible != 0}, {"nodes", Json::array()}};
                for (std::size_t k = 0; k < std::min<std::size_t>(loops[j].node_count, query.max_items); ++k) loop["nodes"].push_back(loop_nodes[loops[j].node_offset + k]);
                if (loops[j].node_count > query.max_items) incomplete = true;
                budget.add(out["function_analysis"], std::move(loop));
            }
            xair_cfg_function_analysis_destroy(graph);
        }
    } else {
        out["instructions"] = Json::array(); out["operations"] = Json::array(); out["ssa_values"] = Json::array();
        const auto* module = xair_cfg_module(a.cfg);
        std::set<xair_value_id> values;
        for (auto node : nodes) {
            if (budget.truncated) break;
            const auto* block = xair_cfg_get_node(a.cfg, node);
            for (auto address = block->start; address < block->end && !budget.truncated;) {
                xair_x86_decoded_inst decoded{};
                const auto decoded_status = xair_decode_instruction(&a.binary, address, &decoded);
                if (decoded_status != XAIR_OK || !decoded.length) { incomplete = true; break; }
                std::string bytes;
                constexpr char digits[] = "0123456789abcdef";
                for (std::size_t k = 0; k < decoded.length; ++k) { bytes += digits[decoded.bytes[k] >> 4]; bytes += digits[decoded.bytes[k] & 15]; }
                budget.add(out["instructions"], {{"block", node}, {"source_locations", Json::array({location(target, address)})}, {"bytes", bytes}, {"length", decoded.length}, {"mnemonic", xair_x86_decoder_mnemonic_name(decoded.decoder_mnemonic)}, {"native_flow", decoded.flow}, {"flags", {{"reads", decoded.flags_read}, {"writes", decoded.flags_written}, {"undefined", decoded.flags_undefined}}}});
                address += decoded.length;
            }
            for (std::size_t j = 0; j < xair_block_param_count(module, block->ir_block); ++j) {
                xair_value_id param{};
                if (xair_block_param_value(module, block->ir_block, j, &param) == XAIR_OK) values.insert(param);
            }
            const xair_op_id* ops{}; std::size_t count{};
            if (xair_block_ops(module, block->ir_block, &ops, &count) != XAIR_OK) { incomplete = true; continue; }
            for (std::size_t j = 0; j < count && !budget.truncated; ++j) {
                xair_op_view_v3 op{}; xair_module_get_op_v3(module, ops[j], &op);
                Json item{{"ir_op", ops[j]}, {"block", node}, {"opcode", xair_opcode_name(op.opcode)}, {"definitions", Json::array()}, {"uses", Json::array()}, {"source_locations", Json::array()}};
                if(op.opcode==XAIR_OP_CONST_U64||op.opcode==XAIR_OP_CONST_WIDE){std::uint64_t low{},high{};if(xair_op_immediate_wide(module,ops[j],&low,&high)==XAIR_OK)item["constants"]={{"low",hex_address(low)},{"high",hex_address(high)}};}
                const xair_value_id* ids{}; std::size_t n{};
                xair_op_inputs(module, ops[j], &ids, &n);
                for (std::size_t k = 0; k < n; ++k) { item["uses"].push_back(ids[k]); values.insert(ids[k]); }
                xair_op_results(module, ops[j], &ids, &n);
                for (std::size_t k = 0; k < n; ++k) { item["definitions"].push_back(ids[k]); values.insert(ids[k]); }
                const xair_source_id* sources{}; xair_op_sources(module, ops[j], &sources, &n);
                for (std::size_t k = 0; k < n; ++k) {
                    xair_source_record source{}; if (xair_module_get_source(module, sources[k], &source) != XAIR_OK) continue;
                    auto loc = location(target, source.location.instruction_va);
                    loc["instruction_length"] = source.location.instruction_length; loc["micro_op_index"] = source.location.micro_op_index; loc["native_flags"] = source.location.flags;
                    loc["semantic_id"] = source.semantic_id ? source.semantic_id : "";
                    item["source_locations"].push_back(std::move(loc));
                }
                xair_op_attributes attrs{};
                if (xair_op_attributes_get(module, ops[j], &attrs) == XAIR_OK) {
                    item["flags"] = {{"reads", attrs.flag_reads}, {"writes", attrs.flag_writes}};
                    item["memory_effects"] = {{"native_effects", attrs.effects}, {"read", (attrs.effects & XAIR_EFFECT_READ_MEMORY) != 0}, {"write", (attrs.effects & XAIR_EFFECT_WRITE_MEMORY) != 0}, {"width_bits", attrs.width_bits}, {"address_space", attrs.address_space}, {"native_category", attrs.access_category}};
                    item["native_attribute_kind"] = attrs.kind;
                }
                budget.add(out["operations"], std::move(item));
            }
        }
        for (auto id : values) {
            if (budget.truncated) break;
            const auto type = xair_value_type(module, id); xair_op_id definition = XAIR_INVALID_ID;
            const auto def_status = xair_value_definition(module, id, &definition);
            std::size_t count{}; xair_value_uses(module, id, nullptr, 0, &count);
            std::vector<xair_op_id> uses(std::min(count, query.max_items));
            if (!uses.empty()) xair_value_uses(module, id, uses.data(), uses.size(), &count);
            if (count > uses.size()) incomplete = true;
            const auto* name = xair_value_name(module, id);
            budget.add(out["ssa_values"], {{"id", id}, {"name", name ? name : ""}, {"native_type", type.kind}, {"bits", type.bits}, {"type_aux", type.aux}, {"definition", definition}, {"definition_status", xair_status_name(def_status)}, {"uses", uses}, {"total_uses", count}});
        }
    }
    const bool canceled = xair_cancel_token_requested(a.cancel) != 0;
    const std::string state = timed_out ? "timeout" : canceled ? "cancelled" : incomplete || budget.truncated ? "partial" : "completed";
    out["status"] = state; out["truncated"] = budget.truncated; out["emitted_items"] = budget.items;
    auto json = out.dump();
    if (json.size() > query.max_output_bytes) {
        out = {{"schema", "indago.xair-query.v1"}, {"producer", "XAIR/XAIR_CFG"}, {"status", "partial"}, {"truncated", true}, {"native_status", xair_status_name(status)}, {"diagnostic", "output byte budget exceeded"}};
        return {3, "partial", out.dump()};
    }
    return {state == "completed" ? 0 : 3, state, std::move(json)};
#endif
}
}
