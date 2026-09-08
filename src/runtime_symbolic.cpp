#include "indago/runtime.hpp"
#include <array>
#include <set>
#include <map>
#include <thread>
#if INDAGO_HAS_XAIR
#include <xair/xair_frontend.h>
#include <xair_sym/xair_sym.h>
#endif

namespace indago {
#if INDAGO_HAS_XAIR
namespace {
using J = RuntimeJson;
void need(xair_sym_status s) {
  if (s != XAIR_SYM_OK)
    throw std::runtime_error(xair_sym_status_name(s));
}
void need(xair_status s) {
  if (s != XAIR_OK)
    throw std::runtime_error(xair_status_name(s));
}
struct Resources {
  xair_module *module{};
  xair_sym_context *context{};
  xair_sym_state *state{};
  xair_cancel_token *cancel{};
  ~Resources() {
    if (state)
      xair_sym_state_destroy(state);
    if (context)
      xair_sym_context_destroy(context);
    if (module)
      xair_module_destroy(module);
    if (cancel)
      xair_cancel_token_destroy(cancel);
  }
};
std::vector<std::uint8_t> bytes(const std::string &hex) {
  if (hex.size() % 2 || hex.size() > 131072)
    throw std::runtime_error("invalid captured bytes");
  std::vector<std::uint8_t> v;
  for (std::size_t i = 0; i < hex.size(); i += 2)
    v.push_back(
        static_cast<std::uint8_t>(runtime_number("0x" + hex.substr(i, 2))));
  return v;
}
struct Callback {
  Resources *r;
  xair_lift_result *lift;
  J results = J::array();
  J symbols = J::array();
  std::string error;
  const std::vector<xair_lift_result>* path{};
  J expression(xair_sym_expr_id id, unsigned depth = 0) {
    if (depth > 8)
      return {{"id", id}, {"truncated", true}};
    xair_sym_expr_view v{};
    need(xair_sym_expr_get(r->context, id, &v));
    J j{{"id", id}, {"bits", v.bits}, {"native_kind", v.kind}};
    if (v.kind == XAIR_SYM_EXPR_CONST) {
      j["low"] = hex_address(v.immediate);
      j["high"] = hex_address(v.immediate_hi);
    } else if (v.kind == XAIR_SYM_EXPR_SYMBOL)
      j["symbol"] = v.symbol ? v.symbol : "";
    else {
      j["opcode"] = xair_opcode_name(v.opcode);
      j["arguments"] = J::array();
      for (unsigned i = 0; i < v.arg_count; ++i)
        j["arguments"].push_back(expression(v.args[i], depth + 1));
    }
    return j;
  }
  static xair_sym_status terminal(xair_sym_state *state, void *opaque) {
    auto &c = *static_cast<Callback *>(opaque);
    if(xair_sym_state_block(state)!=c.lift->block)return XAIR_SYM_OK;
    try {
      J result{{"outputs", J::array()}};
      result["selected_path_conditions"]=J::array();
      if(c.path)for(size_t i=0;i+1<c.path->size();++i){const auto &block=(*c.path)[i];if(block.branch_condition!=XAIR_INVALID_ID){xair_sym_expr_id expr{};if(xair_sym_state_get_value(state,block.branch_condition,&expr)==XAIR_SYM_OK)result["selected_path_conditions"].push_back({{"address",hex_address(block.start)},{"condition",c.expression(expr)},{"taken",(*c.path)[i+1].start==block.target}});}}
      for (std::size_t i = 0; i < c.lift->output_reg_count; ++i) {
        auto out = c.lift->output_regs[i];
        xair_sym_expr_id expr{};
        auto status = xair_sym_state_get_value(state, out.value, &expr);
        if (status != XAIR_SYM_OK)
          continue;
        xair_sym_taint_id taint{};
        auto ts = xair_sym_state_get_taint(state, out.value, &taint);
        result["outputs"].push_back(
            {{"register", xair_x86_reg_name(out.reg)},
             {"value_id", out.value},
             {"expression", c.expression(expr)},
             {"native_taint_id", ts == XAIR_SYM_OK ? J(taint) : J(nullptr)}});
      }
      if (c.lift->branch_condition != XAIR_INVALID_ID) {
        xair_sym_expr_id condition{};
        need(xair_sym_state_get_value(state, c.lift->branch_condition,
                                      &condition));
        result["path_condition"] = c.expression(condition);
        xair_sym_taint_id condition_taint{};
        auto taint_status = xair_sym_state_get_taint(
            state, c.lift->branch_condition, &condition_taint);
        result["condition_native_taint_id"] =
            taint_status == XAIR_SYM_OK ? J(condition_taint) : J(nullptr);
        result["branches"] = J::array();
        for (bool taken : {true, false}) {
          auto expr = condition;
          if (!taken) {
            xair_sym_expr_id one{};
            need(xair_sym_const(c.r->context, 1, 1, &one));
            need(xair_sym_binary(c.r->context, XAIR_OP_XOR, 1, condition, one,
                                 &expr));
          }
          xair_sym_sat sat = XAIR_SYM_UNKNOWN;
          xair_sym_state *branch_state{};
          need(xair_sym_state_clone(state, &branch_state));
          std::unique_ptr<xair_sym_state, decltype(&xair_sym_state_destroy)>
              guard(branch_state, xair_sym_state_destroy);
          need(xair_sym_state_assume(branch_state, expr));
          auto status = xair_sym_check(branch_state, XAIR_SYM_INVALID_ID, &sat);
          J branch{{"taken", taken},
                   {"target",
                    hex_address(taken ? c.lift->target : c.lift->fallthrough)},
                   {"native_status", xair_sym_status_name(status)},
                   {"native_verdict", sat == XAIR_SYM_SAT     ? "sat"
                                      : sat == XAIR_SYM_UNSAT ? "unsat"
                                                              : "unknown"},
                   {"models", J::array()}};
          if (status == XAIR_SYM_OK && sat == XAIR_SYM_SAT)
            for (auto &symbol : c.symbols) {
              std::uint64_t value{};
              auto ms = xair_sym_model_u64(
                  branch_state, symbol["expression_id"].get<xair_sym_expr_id>(),
                  &value);
              if (ms == XAIR_SYM_OK)
                branch["models"].push_back({{"input", symbol["input"]},
                                            {"value", hex_address(value)}});
            }
          result["branches"].push_back(branch);
        }
      }
      c.results.push_back(result);
      return XAIR_SYM_OK;
    } catch (const std::exception &e) {
      c.error = e.what();
      return XAIR_SYM_ERR_INTERNAL;
    }
  }
};
} // namespace
#endif
RuntimeJson runtime_symbolic(const RuntimeJson &observation,
                             const RuntimeJson &request) {
#if !INDAGO_HAS_XAIR
  return {{"status", "unavailable"}, {"diagnostic", "XAIR_SYM not compiled"}};
#else
  using J = RuntimeJson;
  const auto &capture = observation.at("data");
  auto mode = request.value("mode", "solve_branch");
  if (!std::set<std::string>{"solve_branch", "path_condition", "symbolic_slice",
                             "taint", "source_to_sink"}
           .contains(mode))
    throw std::runtime_error("unknown captured symbolic mode");
  auto timeout = runtime_number(request.value("timeout_ms", J(1000)));
  if (!timeout || timeout > 10000)
    throw std::runtime_error("symbolic timeout must be 1..10000 ms");
  auto path=request.value("path",J::array());
  if(!path.is_array()||path.size()>16)throw std::runtime_error("path must contain at most 16 block addresses");
  const auto &code_record=path.empty()?capture.at("instruction_bytes"):capture.at("code_bytes");
  auto code = bytes(code_record.at("hex"));
  if (code.empty())
    throw std::runtime_error("capture contains no instruction bytes");
  auto address = runtime_number(capture.value("pc_location", capture.at("location")).at("runtime_address"));
  if(!path.empty()&&runtime_number(path[0])!=address)throw std::runtime_error("selected path must start at captured PC");
  auto arch = capture["registers"]["arch"] == "x86" ? XAIR_ARCH_X86_32
                                                    : XAIR_ARCH_X86_64;
  Resources r;
  need(xair_module_create(&r.module));
  need(xair_cancel_token_create(&r.cancel));
  std::jthread timer([&](std::stop_token stop) {
    auto end =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    while (!stop.stop_requested() && std::chrono::steady_clock::now() < end)
      std::this_thread::sleep_for(std::chrono::milliseconds(5));
    if (!stop.stop_requested())
      xair_cancel_token_request(r.cancel);
  });
  xair_image image{};
  std::vector<std::pair<uint64_t,std::vector<uint8_t>>> regions;
  regions.emplace_back(runtime_number(code_record.at("address")),std::move(code));
  size_t total_code=regions.front().second.size();
  if(!path.empty())for(const auto &region:capture.value("code_regions",J::array())){
    if(!capture.contains("capture_group_id")||region.value("capture_group_id",J{})!=capture["capture_group_id"])throw std::runtime_error("symbolic regions must share a capture group");
    auto data=bytes(region.at("code_bytes").at("hex"));total_code+=data.size();
    if(regions.size()>=17||total_code>65536)throw std::runtime_error("symbolic code region budget exceeded");
    auto start=runtime_number(region.at("code_bytes").at("address"));if(data.empty()||start>UINT64_MAX-data.size())throw std::runtime_error("invalid symbolic code region");
    for(auto &[base,existing]:regions)if(start<base+existing.size()&&base<start+data.size())throw std::runtime_error("overlapping symbolic code regions");
    regions.emplace_back(start,std::move(data));
  }
  auto select_image=[&](uint64_t pc){for(auto &[base,data]:regions)if(pc>=base&&pc-base<data.size()){need(xair_image_init(&image,data.data(),data.size(),base));return;}throw std::runtime_error("selected path leaves captured code regions");};
  select_image(address);
  xair_lift_options options{};
  xair_analysis_options_init(&options.analysis);
  options.analysis.max_wall_time = timeout;
  options.analysis.max_memory = 64 * 1024 * 1024;
  options.analysis.cancel_token = r.cancel;
  options.arch = arch;
  options.address = address;
  options.max_instructions = 32;
  options.block_name = "captured_block";
  xair_lift_result lift{};
  xair_analysis_result native{};
  xair_diagnostic diagnostic{};
  auto lifted = xair_lift_basic_block_ex(r.module, &image, &options, &lift,
                                         &native, &diagnostic);
  J out{{"schema", "indago.runtime-symbolic.v1"},
        {"producer", "XAIR/XAIR_SYM"},
        {"mode", mode},
        {"request", request},
        {"binding_model", "captured-native-block.v1"},
        {"capture_id", observation["id"]},
        {"capture_sha256", observation["sha256"]},
        {"location", capture["location"]},
        {"native_lift_status", xair_status_name(lifted)},
        {"native_end_kind", xair_lift_end_kind_name(lift.end_kind)},
        {"opaque_instructions", lift.opaque_instruction_count},
        {"status", "partial"},
        {"scope",
         "single captured basic block; expression-local branch checks, "
         "not predecessor reachability or whole-process taint"},
        {"assumptions",
         {"general-purpose registers and flags fixed to capture unless "
          "explicitly symbolized",
          "only explicitly captured memory bytes available",
          "SIMD/FPU, TLS, external calls and uncaptured memory are not "
          "reconstructed",
          "no automatic target mutation or concrete replay"}}};
  if (lifted != XAIR_OK) {
    out["diagnostic"] = diagnostic.message ? diagnostic.message
                                           : "captured block lifting failed";
    return out;
  }
  std::vector<xair_lift_result> blocks{lift};
  for(size_t i=1;i<path.size();++i){xair_lift_result next{};options.address=runtime_number(path[i]);std::string name="captured_path_"+std::to_string(i);options.block_name=name.c_str();
    select_image(options.address);
    auto status=xair_lift_basic_block_ex(r.module,&image,&options,&next,&native,&diagnostic);
    if(status!=XAIR_OK)throw std::runtime_error("selected path leaves captured/liftable code");
    blocks.push_back(next);
  }
  if(blocks.size()>1) {
    // Bind backend-native register/flag SSA parameters across a caller-selected
    // path. The lifter and executor retain all instruction/memory semantics.
    std::map<xair_x86_reg,unsigned> registers;std::set<unsigned> flags;
    for(const auto &b:blocks){if(b.input_vector_count||b.output_vector_count)throw std::runtime_error("vector path binding unavailable");for(size_t i=0;i<b.input_reg_count;++i)registers[b.input_regs[i].reg]=xair_value_type(r.module,b.input_regs[i].value).bits;for(size_t i=0;i<b.input_flag_count;++i)flags.insert(b.input_flags[i].bit);}
    for(auto &b:blocks){
      need(xair_block_reopen(r.module,b.block));
      for(auto [reg,bits]:registers){bool found=false;for(size_t i=0;i<b.input_reg_count;++i)if(b.input_regs[i].reg==reg)found=true;if(!found){if(b.input_reg_count>=XAIR_LIFT_MAX_REG_OUTPUTS)throw std::runtime_error("path register budget");xair_value_id v{};need(xair_block_add_param(r.module,b.block,xair_type_i(bits),xair_x86_reg_name(reg),&v));b.input_regs[b.input_reg_count++]={reg,v};}}
      for(auto flag:flags){bool found=false;for(size_t i=0;i<b.input_flag_count;++i)if(b.input_flags[i].bit==flag)found=true;if(!found){xair_value_id v{};need(xair_block_add_param(r.module,b.block,xair_type_i(1),"carried_flag",&v));b.input_flags[b.input_flag_count++]={static_cast<uint8_t>(flag),v};}}
      if(b.memory_in==XAIR_INVALID_ID){need(xair_block_add_param(r.module,b.block,xair_type_mem(0,arch==XAIR_ARCH_X86_32?32:64),"carried_memory",&b.memory_in));b.memory_out=b.memory_in;}
    }
    xair_block_id off_path{};need(xair_block_create(r.module,"outside_selected_path",&off_path));need(xair_set_return(r.module,off_path,nullptr,0));
    need(xair_set_return(r.module,blocks.back().block,blocks.back().return_values,blocks.back().return_count));
    for(size_t index=0;index+1<blocks.size();++index){auto &b=blocks[index];auto &next=blocks[index+1];std::map<xair_value_id,xair_value_id> bindings;
      for(size_t n=0;n<next.input_reg_count;++n){auto reg=next.input_regs[n].reg;xair_value_id value=XAIR_INVALID_ID;for(size_t i=0;i<b.input_reg_count;++i)if(b.input_regs[i].reg==reg)value=b.input_regs[i].value;for(size_t i=0;i<b.output_reg_count;++i)if(b.output_regs[i].reg==reg)value=b.output_regs[i].value;bindings[next.input_regs[n].value]=value;}
      for(size_t n=0;n<next.input_flag_count;++n){auto flag=next.input_flags[n].bit;xair_value_id value=XAIR_INVALID_ID;for(size_t i=0;i<b.input_flag_count;++i)if(b.input_flags[i].bit==flag)value=b.input_flags[i].value;for(size_t i=0;i<b.output_flag_count;++i)if(b.output_flags[i].bit==flag)value=b.output_flags[i].value;bindings[next.input_flags[n].value]=value;}
      bindings[next.memory_in]=b.memory_out;std::vector<xair_value_id> args;
      for(size_t i=0;i<xair_block_param_count(r.module,next.block);++i){xair_value_id parameter{};need(xair_block_param_value(r.module,next.block,i,&parameter));if(!bindings.contains(parameter)||bindings[parameter]==XAIR_INVALID_ID)throw std::runtime_error("unbound native path parameter");args.push_back(bindings[parameter]);}
      if(b.end_kind==XAIR_LIFT_END_DIRECT_CBRANCH){bool taken=next.start==b.target;if(!taken&&next.start!=b.fallthrough)throw std::runtime_error("selected block is not a native branch successor");need(xair_set_cbranch(r.module,b.block,b.branch_condition,taken?next.block:off_path,taken?args.data():nullptr,taken?args.size():0,taken?off_path:next.block,taken?nullptr:args.data(),taken?0:args.size()));}
      else if((b.end_kind==XAIR_LIFT_END_DIRECT_JUMP&&next.start==b.target)||(b.end_kind==XAIR_LIFT_END_FALLTHROUGH&&next.start==b.next))need(xair_set_jump(r.module,b.block,next.block,args.data(),args.size()));
      else throw std::runtime_error("selected edge requires an unresolved/native call model; not silently assumed");
    }
    lift=blocks.front();out["binding_model"]="captured-selected-path.v1";out["scope"]="bounded selected native block path; off-path states excluded; not whole-program reachability";out["path"]=path;out["external_call_policy"]="native unresolved/partial; no implicit external-call success assumption";
  }
  // The native basic-block lifter already returns its outputs and branch
  // expression.
  need(xair_sym_context_create(&r.context));
  xair_sym_context_set_analysis_options(r.context, &options.analysis);
  need(xair_sym_state_create(r.context, r.module, lift.block, &r.state));
  Callback callback{&r, &blocks.back()};
  callback.path=&blocks;
  auto symbolic = request.value("symbolic_registers", J::array());
  if (!symbolic.is_array() || symbolic.size() > 16)
    throw std::runtime_error(
        "symbolic_registers must be an array of at most 16 register names");
  std::set<std::string> requested;
  for (auto &name : symbolic)
    requested.insert(name.get<std::string>());
  std::set<std::string> bound;
  for (std::size_t i = 0; i < lift.input_reg_count; ++i) {
    auto input = lift.input_regs[i];
    std::string name = xair_x86_reg_name(input.reg);
    if (arch == XAIR_ARCH_X86_32 && name.size() == 3 && name[0] == 'r')
      name[0] = 'e';
    auto values = capture["registers"]["values"];
    if (!values.contains(name))
      throw std::runtime_error("captured register missing: " + name);
    xair_sym_expr_id expr{};
    auto bits = xair_value_type(r.module, input.value).bits;
    if (requested.contains(name)) {
      need(xair_sym_symbol(r.context, static_cast<std::uint16_t>(bits),
                           name.c_str(), &expr));
      xair_sym_taint_id taint{};
      need(xair_sym_taint_source(r.context, name.c_str(), &taint));
      need(xair_sym_state_set_taint(r.state, input.value, taint));
      callback.symbols.push_back({{"input", name},
                                  {"expression_id", expr},
                                  {"captured_value", values[name]}});
      bound.insert(name);
    } else
      need(xair_sym_const(r.context, static_cast<std::uint16_t>(bits),
                          runtime_number(values[name]), &expr));
    need(xair_sym_state_set_value(r.state, input.value, expr));
  }
  for (const auto &name : requested)
    if (!bound.contains(name))
      throw std::runtime_error(
          "symbolic register is not a native input to captured block: " + name);
  auto flags = runtime_number(capture["registers"]["values"]["eflags"]);
  for (std::size_t i = 0; i < lift.input_flag_count; ++i) {
    xair_sym_expr_id expr{};
    need(xair_sym_const(r.context, 1,
                        (flags >> std::array<unsigned, 6>{0, 2, 4, 6, 7, 11}.at(
                                      lift.input_flags[i].bit)) &
                            1,
                        &expr));
    need(xair_sym_state_set_value(r.state, lift.input_flags[i].value, expr));
  }
  std::set<std::uint64_t> symbolic_bytes, seeded_bytes;
  for (const auto &range : request.value("symbolic_memory", J::array())) {
    auto base = runtime_number(range.at("address"));
    auto count = runtime_number(range.at("size"));
    if (!count || count > 256 || base > UINT64_MAX - count)
      throw std::runtime_error("symbolic memory range exceeds budget");
    for (std::uint64_t i = 0; i < count; ++i)
      symbolic_bytes.insert(base + i);
    if (symbolic_bytes.size() > 256)
      throw std::runtime_error("at most 256 symbolic memory bytes");
  }
  for (const auto &memory : capture.value("memory", J::array())) {
    auto data = bytes(memory["hex"]);
    if (data.empty())
      continue;
    auto base = runtime_number(memory["address"]);
    xair_sym_object_id object{};
    need(xair_sym_object_add(r.state, base, data.size(), 3, &object));
    for (std::size_t i = 0; i < data.size(); ++i) {
      xair_sym_expr_id expr{};
      if (symbolic_bytes.contains(base + i)) {
        auto name = "memory_" + hex_address(base + i);
        need(xair_sym_symbol(r.context, 8, name.c_str(), &expr));
        xair_sym_taint_id taint{};
        need(xair_sym_taint_source(r.context, name.c_str(), &taint));
        need(xair_sym_memory_store_taint8(r.state, base + i, taint));
        callback.symbols.push_back({{"input", name},
                                    {"expression_id", expr},
                                    {"captured_value", hex_address(data[i])}});
        seeded_bytes.insert(base + i);
      } else
        need(xair_sym_const(r.context, 8, data[i], &expr));
      need(xair_sym_memory_store8(r.state, base + i, expr));
    }
  }
  if (seeded_bytes != symbolic_bytes)
    throw std::runtime_error(
        "symbolic memory must be present in the referenced capture");
  xair_sym_explore_options explore{};
  xair_sym_explore_options_init(&explore);
  explore.analysis = options.analysis;
  explore.max_states = 32;
  explore.max_block_steps = blocks.size()+2;
  explore.max_symbolic_forks = 16;
  explore.cancel_token = r.cancel;
  xair_sym_explore_result result{};
  auto status = xair_sym_explore_detailed(r.state, &explore, Callback::terminal,
                                          &callback, &result, &diagnostic);
  out["native_status"] = xair_sym_status_name(status);
  out["native_completion"] = result.completion_reason;
  out["unresolved_operations"] = result.unresolved_operations;
  out["symbolic_inputs"] = callback.symbols;
  out["results"] = callback.results;
  out["instructions"] = lift.instructions;
  out["bytes_read"] = lift.bytes_read;
  out["symbolic_memory_bytes"] = symbolic_bytes.size();
  if (mode == "symbolic_slice")
    out["slice_scope"] = "native output expression DAGs and their input "
                         "dependencies within this block";
  if (mode == "source_to_sink") {
    auto sink = request.value("sink", "");
    if (sink.empty() || callback.symbols.empty())
      throw std::runtime_error("source_to_sink requires symbolic inputs and an "
                               "output register sink");
    if (arch == XAIR_ARCH_X86_32 && sink.size() == 3 && sink[0] == 'e')
      sink[0] = 'r';
    out["sink"] = sink;
    out["sink_findings"] = J::array();
    for (const auto &terminal : callback.results)
      for (const auto &output : terminal["outputs"])
        if (output["register"] == sink)
          out["sink_findings"].push_back(output);
  }
  if (!callback.error.empty())
    out["diagnostic"] = callback.error;
  bool complete =
      status == XAIR_SYM_OK && result.completion_reason == XAIR_SYM_COMPLETED &&
      std::all_of(blocks.begin(),blocks.end(),[](const auto &b){return !b.opaque_instruction_count;}) && !result.unresolved_operations &&
      !callback.results.empty() && lift.input_vector_count == 0;
  out["status"] = complete ? "completed" : "partial";
  if (mode == "source_to_sink" && out["sink_findings"].empty()) {
    out["status"] = "partial";
    out["diagnostic"] = "sink was not a native output of the captured block";
  }
  if ((mode == "solve_branch" || mode == "path_condition") &&
      blocks.back().branch_condition == XAIR_INVALID_ID) {
    out["status"] = "partial";
    out["diagnostic"] = "no conditional branch within captured block";
  }
  if (out.dump().size() > 1024 * 1024) {
    out.erase("results");
    out["status"] = "partial";
    out["diagnostic"] = "symbolic expression output exceeded 1 MiB";
  }
  return out;
#endif
}
} // namespace indago
