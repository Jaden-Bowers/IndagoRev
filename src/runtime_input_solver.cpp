#include "indago/runtime.hpp"
#if INDAGO_HAS_XAIR
#include <xair/xair.h>
#include <xair/xair_frontend.h>
#include <xair_sym/xair_sym.h>
#endif
#include <memory>
namespace indago {
namespace {
using J=RuntimeJson;
std::vector<uint8_t> input_bytes(const J &v,size_t cap=256) {
  const auto s=v.get<std::string>();
  if(s.empty()||s.size()>cap*2||s.size()%2||s.find_first_not_of("0123456789abcdef")!=s.npos)throw std::runtime_error("invalid observed input bytes");
  std::vector<uint8_t> b;for(size_t i=0;i<s.size();i+=2)b.push_back(static_cast<uint8_t>(runtime_number("0x"+s.substr(i,2))));return b;
}
#if INDAGO_HAS_XAIR
void need(xair_sym_status s){if(s!=XAIR_SYM_OK)throw std::runtime_error(xair_sym_status_name(s));}
void need(xair_status s){if(s!=XAIR_OK)throw std::runtime_error(xair_status_name(s));}
struct InputSolve {
  xair_sym_context *context{}; xair_value_id output{};std::vector<xair_sym_expr_id> symbols;
  J mapping,results=J::array();std::string error;
  xair_value_id branch_condition=XAIR_INVALID_ID;uint64_t branch_target{},branch_fallthrough{};
  static xair_sym_status terminal(xair_sym_state *state,void *opaque) {
    auto &f=*static_cast<InputSolve *>(opaque);
    try {J result{{"branches",J::array()}};xair_sym_expr_id output{},zero{},condition{};
      need(xair_sym_state_get_value(state,f.output,&output));need(xair_sym_const(f.context,32,0,&zero));
      for(bool equal:{true,false}) {
        need(xair_sym_binary(f.context,equal?XAIR_OP_EQ:XAIR_OP_NE,1,output,zero,&condition));
        xair_sym_state *copy{};need(xair_sym_state_clone(state,&copy));std::unique_ptr<xair_sym_state,decltype(&xair_sym_state_destroy)> guard(copy,xair_sym_state_destroy);
        need(xair_sym_state_assume(copy,condition));xair_sym_sat sat=XAIR_SYM_UNKNOWN;
        const auto status=xair_sym_check(copy,XAIR_SYM_INVALID_ID,&sat);
        J branch{{"comparison_equal",equal},{"native_status",xair_sym_status_name(status)},
          {"native_verdict",sat==XAIR_SYM_SAT?"sat":sat==XAIR_SYM_UNSAT?"unsat":"unknown"},{"input_candidates",J::array()}};
        if(status==XAIR_SYM_OK&&sat==XAIR_SYM_SAT) {
          if(f.branch_condition!=XAIR_INVALID_ID) {
            xair_sym_expr_id condition{};uint64_t taken{};
            need(xair_sym_state_get_value(copy,f.branch_condition,&condition));need(xair_sym_model_u64(copy,condition,&taken));
            xair_sym_expr_id opposite{},one{};need(xair_sym_const(f.context,1,1,&one));
            if(taken)need(xair_sym_binary(f.context,XAIR_OP_XOR,1,condition,one,&opposite));else opposite=condition;
            xair_sym_sat alternative=XAIR_SYM_UNKNOWN;const auto alternate_status=xair_sym_check(copy,opposite,&alternative);
            branch["caller_branch"]={{"taken",taken!=0},{"target",hex_address(taken?f.branch_target:f.branch_fallthrough)},
              {"entailed_by_comparison",alternate_status==XAIR_SYM_OK&&alternative==XAIR_SYM_UNSAT},
              {"scope","native caller condition under modeled API return; replay required"}};
          }
          std::vector<uint8_t> values(f.symbols.size());need(xair_sym_model_bytes(copy,f.symbols.data(),f.symbols.size(),values.data()));
          std::string hex;const char *digits="0123456789abcdef";for(auto b:values){hex+=digits[b>>4];hex+=digits[b&15];}
          branch["input_candidates"].push_back({{"mapping",f.mapping},{"source","stdin"},{"offset",f.mapping.at("offset")},
            {"hex",hex},{"complete",true},{"validation","comparison candidate; original-target acceptance and negative control required"}});
        }
        result["branches"].push_back(branch);
      }f.results.push_back(result);return XAIR_SYM_OK;
    }catch(const std::exception &e){f.error=e.what();return XAIR_SYM_ERR_INTERNAL;}
  }
};
#endif
}
RuntimeJson runtime_solve_input(const J &comparison,const J &delivery,const J &session) {
#if !INDAGO_HAS_XAIR
  return {{"status","unavailable"},{"diagnostic","XAIR_SYM unavailable"}};
#else
  const auto &c=comparison.at("data").at("native").at("payload"),&d=delivery.at("data").at("native").at("payload");
  if(c.at("api")!="memcmp"||d.at("source")!="stdin"||c.at("input").at("input_id")!=d.at("input_id")||!d.at("complete").get<bool>())throw std::runtime_error("comparison has no completed native input provenance");
  const auto offset=runtime_number(c.at("input").at("offset")),start=runtime_number(d.at("offset"));
  const auto input=input_bytes(c.at("input_hex")),expected=input_bytes(c.at("expected_hex")),received=input_bytes(d.at("hex"));
  int observed_sign=0;for(size_t i=0;i<std::min(input.size(),expected.size());++i)if(input[i]!=expected[i]){observed_sign=input[i]<expected[i]?-1:1;break;}
  if(c.at("input_side")=="right")observed_sign=-observed_sign;
  const auto actual=c.at("return_value").get<int>();
  if((actual<0?-1:actual>0?1:0)!=observed_sign)throw std::runtime_error("observed call contradicts memcmp model");
  if(input.size()!=expected.size()||offset<start||offset-start>received.size()||input.size()>received.size()-(offset-start)||!std::equal(input.begin(),input.end(),received.begin()+static_cast<size_t>(offset-start)))throw std::runtime_error("input comparison differs from delivered bytes");
  const auto baseline=session.at("request").value("input_hex",std::string{});
  if(start>baseline.size()/2||received.size()>(baseline.size()/2-start)||baseline.substr(start*2,received.size()*2)!=d.at("hex").get<std::string>())throw std::runtime_error("observed stdin differs from original experiment input");
  xair_module *module{};need(xair_module_create(&module));std::unique_ptr<xair_module,decltype(&xair_module_destroy)> mg(module,xair_module_destroy);
  xair_block_id block{};need(xair_block_create(module,"observed_memcmp",&block));
  xair_value_id args[3]{};for(auto &a:args)need(xair_block_add_param(module,block,xair_type_i(64),"arg",&a));
  xair_op_attributes attr{};attr.kind=XAIR_ATTR_CALL;attr.call_kind=XAIR_CALL_DIRECT_EXTERNAL;attr.calling_convention=XAIR_CC_SYSV_X64;attr.effects=XAIR_EFFECT_READ_MEMORY;attr.import_name="memcmp";
  xair_type type=xair_type_i(32);const char *name="comparison_result";xair_value_id output{};
  need(xair_build_call(module,block,args,3,&type,&name,1,&attr,&output));need(xair_set_return(module,block,&output,1));
  xair_lift_result caller{};caller.branch_condition=XAIR_INVALID_ID;J caller_binding={{"status","unavailable"}};
  std::vector<std::pair<xair_value_id,uint64_t>> caller_seeds;
  std::vector<xair_value_id> caller_unknowns;
  if(c.contains("caller_code")) {
    auto code=input_bytes(c.at("caller_code").at("hex"));xair_image image{};const auto address=runtime_number(c.at("caller_code").at("address"));need(xair_image_init(&image,code.data(),code.size(),address));
    xair_lift_options lift{};xair_analysis_options_init(&lift.analysis);lift.analysis.max_wall_time=100;lift.arch=c.at("arch")=="x86"?XAIR_ARCH_X86_32:XAIR_ARCH_X86_64;lift.address=address;lift.max_instructions=16;lift.block_name="observed_comparison_caller";
    xair_analysis_result analysis{};xair_diagnostic diagnostic{};
    const auto lifted=xair_lift_basic_block_ex(module,&image,&lift,&caller,&analysis,&diagnostic);
    bool supported=lifted==XAIR_OK&&caller.branch_condition!=XAIR_INVALID_ID&&!caller.opaque_instruction_count&&!caller.input_flag_count&&!caller.input_vector_count&&(caller.memory_in==XAIR_INVALID_ID||!c.value("memory",J::array()).empty());
    for(size_t i=0;i<caller.input_reg_count&&supported;++i)if(caller.input_regs[i].reg!=XAIR_X86_RAX){std::string reg=xair_x86_reg_name(caller.input_regs[i].reg);if(lift.arch==XAIR_ARCH_X86_32&&reg.size()==3&&reg[0]=='r')reg[0]='e';supported=c.at("registers").contains(reg);}
    if(supported) {
      need(xair_block_reopen(module,block));std::map<xair_value_id,xair_value_id> bindings;
      for(size_t i=0;i<caller.input_reg_count;++i){auto reg=caller.input_regs[i];const auto type=xair_value_type(module,reg.value);xair_value_id value{};
        if(reg.reg==XAIR_X86_RAX){if(type.bits==32)value=output;else {
          xair_value_id low{},high{},mask{},masked{};
          need(xair_build_unary(module,block,XAIR_OP_ZEXT,type,output,"api_int_return",&low));
          need(xair_block_add_param(module,block,type,"unspecified_return_high",&high));caller_unknowns.push_back(high);
          need(xair_build_const_u64(module,block,type,UINT64_C(0xffffffff00000000),"high_mask",&mask));
          need(xair_build_binary(module,block,XAIR_OP_AND,type,high,mask,"return_high",&masked));
          need(xair_build_binary(module,block,XAIR_OP_OR,type,low,masked,"return_register",&value));
        }}
        else {auto label=std::string(xair_x86_reg_name(reg.reg));if(lift.arch==XAIR_ARCH_X86_32&&label.size()==3&&label[0]=='r')label[0]='e';need(xair_block_add_param(module,block,type,label.c_str(),&value));caller_seeds.emplace_back(value,runtime_number(c.at("registers").at(label)));}bindings[reg.value]=value;}
      if(caller.memory_in!=XAIR_INVALID_ID){xair_value_id memory{};need(xair_block_add_param(module,block,xair_value_type(module,caller.memory_in),"captured_memory",&memory));bindings[caller.memory_in]=memory;}
      std::vector<xair_value_id> edge;for(size_t i=0;i<xair_block_param_count(module,caller.block);++i){xair_value_id parameter{};need(xair_block_param_value(module,caller.block,i,&parameter));if(!bindings.contains(parameter))throw std::runtime_error("unbound caller parameter");edge.push_back(bindings.at(parameter));}
      need(xair_set_jump(module,block,caller.block,edge.data(),edge.size()));
      caller_binding={{"status","completed"},{"address",hex_address(address)},{"engine","XAIR native caller block"},{"assumption","int return lower 32 bits modeled; other caller registers concrete-seeded"}};
    }else {caller.branch_condition=XAIR_INVALID_ID;caller_binding={{"status","partial"},{"diagnostic","caller needs memory/flags/vector/call reconstruction or has no bounded conditional branch"}};}
  }
  need(xair_module_freeze(module));
  xair_sym_context *context{};need(xair_sym_context_create(&context));std::unique_ptr<xair_sym_context,decltype(&xair_sym_context_destroy)> cg(context,xair_sym_context_destroy);
  xair_analysis_options options{};xair_analysis_options_init(&options);options.max_wall_time=1000;options.max_memory=64*1024*1024;xair_sym_context_set_analysis_options(context,&options);
  xair_sym_state *state{};need(xair_sym_state_create(context,module,block,&state));std::unique_ptr<xair_sym_state,decltype(&xair_sym_state_destroy)> sg(state,xair_sym_state_destroy);
  xair_sym_environment *environment{};need(xair_sym_environment_create_builtin(context,XAIR_ARCH_X86_64,XAIR_CC_SYSV_X64,&environment));
  std::unique_ptr<xair_sym_environment,decltype(&xair_sym_environment_destroy)> eg(environment,xair_sym_environment_destroy);need(xair_sym_state_attach_environment(state,environment));
  xair_sym_object_id object{};need(xair_sym_object_add(state,0x1000,input.size(),3,&object));need(xair_sym_object_add(state,0x2000,input.size(),3,&object));
  const auto regions=c.value("memory",J::array());if(!regions.is_array()||regions.size()>2)throw std::runtime_error("caller memory bound exceeded");
  for(const auto &region:regions){auto data=input_bytes(region.at("hex"),4096);const auto address=runtime_number(region.at("address"));if(address>UINT64_MAX-data.size())throw std::runtime_error("caller memory extent wraps");
    need(xair_sym_object_add(state,address,data.size(),3,&object));for(size_t i=0;i<data.size();++i){xair_sym_expr_id byte{};need(xair_sym_const(context,8,data[i],&byte));need(xair_sym_memory_store8(state,address+i,byte));}}
  InputSolve solve;solve.context=context;solve.output=output;solve.mapping={{"source","stdin"},{"offset",offset},{"size",input.size()},{"address",c.at("address")}};
  solve.branch_condition=caller.branch_condition;solve.branch_target=caller.target;solve.branch_fallthrough=caller.fallthrough;
  for(auto [value,seed]:caller_seeds){xair_sym_expr_id expr{};need(xair_sym_const(context,xair_value_type(module,value).bits,seed,&expr));need(xair_sym_state_set_value(state,value,expr));}
  for(const auto value:caller_unknowns){xair_sym_expr_id expr{};need(xair_sym_symbol(context,xair_value_type(module,value).bits,"unspecified_return_high",&expr));need(xair_sym_state_set_value(state,value,expr));}
  for(size_t i=0;i<input.size();++i){xair_sym_expr_id symbol{},constant{};auto label="input_"+std::to_string(offset+i);need(xair_sym_symbol(context,8,label.c_str(),&symbol));solve.symbols.push_back(symbol);
    need(xair_sym_memory_store8(state,0x1000+i,symbol));need(xair_sym_const(context,8,expected[i],&constant));need(xair_sym_memory_store8(state,0x2000+i,constant));}
  for(size_t i=0;i<3;++i){xair_sym_expr_id value{};const bool right=c.at("input_side")=="right";need(xair_sym_const(context,64,i==0?(right?0x2000:0x1000):i==1?(right?0x1000:0x2000):input.size(),&value));need(xair_sym_state_set_value(state,args[i],value));}
  xair_sym_explore_options explore{};xair_sym_explore_options_init(&explore);explore.analysis=options;explore.max_states=4;explore.max_block_steps=4;
  xair_sym_explore_result result{};xair_diagnostic diag{};auto status=xair_sym_explore_detailed(state,&explore,InputSolve::terminal,&solve,&result,&diag);
  return {{"schema","indago.runtime-symbolic.v1"},{"producer","XAIR_SYM builtin memcmp"},{"status",status==XAIR_SYM_OK&&!result.unresolved_operations&&!solve.results.empty()?"completed":"partial"},
    {"native_status",xair_sym_status_name(status)},{"results",solve.results},{"diagnostic",solve.error},{"comparison_observation",comparison.at("id")},
    {"delivery_observation",delivery.at("id")},{"provenance",c.at("input")},{"caller_binding",caller_binding},{"model_library_version",xair_sym_environment_model_version(environment)},
    {"scope","observed input-to-comparison, not success-branch or whole-program reachability proof"},{"verified_solve",false}};
#endif
}
}
