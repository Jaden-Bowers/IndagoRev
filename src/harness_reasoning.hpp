#pragma once
#include "harness_validation.hpp"
#include "indago/runtime.hpp"
#include "harness_verification.hpp"
#if INDAGO_HAS_XAIR
#include <xair/xair_frontend.h>
#include <xair/xair_binary.h>
#endif
#include <cctype>
#include <deque>
#include <regex>

namespace indago {
// Durable investigation-local assertions. Only the native checker can set a
// checked state; no model-authored label is accepted as validation or a solve.
inline wb::J reasoning_initial(const wb::J &inv) {
  wb::J obligations=wb::J::array(),questions=inv.value("questions",wb::J::array());
  if(questions.empty())for(std::size_t i=0;i<inv.at("required_facts").size();++i)
    questions.push_back({{"id","q"+std::to_string(i)},{"fact_index",i},{"text",inv.at("required_facts")[i]},
      {"proof_obligation",required_proof_kind(inv,i).empty()?"evidence_backed_claim":required_proof_kind(inv,i)}});
  for(std::size_t i=0;i<inv.at("required_facts").size();++i)
    for(const auto *role:{"input","acceptance","rejection","constraints","output","candidate_validation","challenge_solve"})
      obligations.push_back({{"id","o"+std::to_string(i)+"_"+role},{"question","q"+std::to_string(i)},
        {"fact_index",i},{"role",role},{"state","unresolved"}});
  return {{"schema","indago.reasoning.v2"},{"revision",0},{"questions",questions},{"obligations",obligations},
    {"hypotheses",wb::J::array()},{"candidates",wb::J::array()},{"experiments",wb::J::array()},
    {"recoveries",wb::J::array()},{"proofs",wb::J::array()},{"solutions",wb::J::array()},
    {"requirements_verified",false},{"verified_solve",false}};
}

inline std::string reasoning_hex(const std::vector<unsigned char> &bytes) {
  static constexpr char digits[]="0123456789abcdef";
  std::string out;out.reserve(bytes.size()*2);
  for(auto byte:bytes){out.push_back(digits[byte>>4]);out.push_back(digits[byte&15]);}
  return out;
}

struct RecoveryFlow {
  bool engine_available=false;
  bool complete=true;
  std::set<std::size_t> reachable;
};

#if INDAGO_HAS_XAIR
inline bool recovery_decode(const std::vector<unsigned char> &bytes,std::size_t at,xair_x86_decoded_inst &instruction) {
  if(at>=bytes.size())return false;
  return xair_x86_decode_instruction(XAIR_ARCH_X86_32,bytes.data()+at,bytes.size()-at,at,&instruction)==XAIR_OK&&
    instruction.error==XAIR_X86_DECODE_OK&&instruction.length>0&&instruction.fallthrough==at+instruction.length;
}

// Narrow proof recognizer, not an x86 interpreter. XAIR supplies every decoded
// operand; anything outside this straight-line initializer grammar is unsupported.
inline wb::J recovery_native_initializer(const std::vector<unsigned char> &bytes,const wb::J &recovery) {
  auto reg=[](const xair_x86_operand &o,xair_x86_reg r,unsigned width) {
    return o.kind==XAIR_X86_OPERAND_REGISTER&&o.value.reg.reg_class==XAIR_X86_REG_CLASS_GPR&&
      o.value.reg.parent==r&&o.value.reg.width==width&&o.value.reg.bit_offset==0;
  };
  if(bytes.size()<9||bytes[0]!=0x55||!((bytes[1]==0x89&&bytes[2]==0xe5)||(bytes[1]==0x8b&&bytes[2]==0xec)))
    throw std::runtime_error("Initializer requires an unambiguous EBP frame");
  xair_x86_decoded_inst alloc{};
  if(!recovery_decode(bytes,3,alloc)||alloc.mnemonic!=XAIR_X86_MNEMONIC_SUB||
     !reg(alloc.operands[0],XAIR_X86_RSP,32)||alloc.operands[1].kind!=XAIR_X86_OPERAND_IMMEDIATE)
    throw std::runtime_error("Initializer stack allocation is unsupported");
  const auto frame=alloc.operands[1].value.imm;
  if(frame<16||frame>65536)throw std::runtime_error("Initializer frame bound exceeded");
  std::map<int,unsigned char> stores;
  std::map<unsigned,std::uint32_t> constants;
  std::map<unsigned,int> pointers;
  for(std::size_t at=alloc.fallthrough;at<bytes.size()&&at<16384;) {
    xair_x86_decoded_inst i{};
    if(!recovery_decode(bytes,at,i))throw std::runtime_error("Initializer decode failed");
    if(i.attributes&(XAIR_X86_ATTR_ADDRESS_SIZE|XAIR_X86_ATTR_OPERAND_SIZE|XAIR_X86_ATTR_SEGMENT|
                     XAIR_X86_ATTR_LOCK|XAIR_X86_ATTR_REP|XAIR_X86_ATTR_REPNE))
      throw std::runtime_error("Prefixed initializer instruction is outside the flat 32-bit proof grammar");
    const auto &dst=i.operands[0],&src=i.operands[1];
    if(i.mnemonic==XAIR_X86_MNEMONIC_NOP&&i.flow==XAIR_X86_FLOW_NORMAL) {}
    else if(i.mnemonic==XAIR_X86_MNEMONIC_MOV&&i.flow==XAIR_X86_FLOW_NORMAL&&
            dst.kind==XAIR_X86_OPERAND_REGISTER&&dst.value.reg.parent!=XAIR_X86_RBP&&dst.value.reg.parent!=XAIR_X86_RSP&&
            reg(dst,dst.value.reg.parent,32)&&src.kind==XAIR_X86_OPERAND_IMMEDIATE) {
      constants[dst.value.reg.parent]=static_cast<std::uint32_t>(src.value.imm);pointers.erase(dst.value.reg.parent);
    } else if(i.mnemonic==XAIR_X86_MNEMONIC_MOV&&i.flow==XAIR_X86_FLOW_NORMAL&&dst.kind==XAIR_X86_OPERAND_MEMORY&&
              dst.size_bits==8&&dst.value.mem.has_base&&!dst.value.mem.has_index&&
              dst.value.mem.base.parent==XAIR_X86_RBP&&!(i.attributes&XAIR_X86_ATTR_SEGMENT)) {
      const auto offset=dst.value.mem.displacement;
      if(offset>=0||offset<-static_cast<std::int64_t>(frame)||stores.contains(static_cast<int>(offset)))
        throw std::runtime_error("Initializer store is outside its frame or overwrites an earlier byte");
      unsigned value;
      if(src.kind==XAIR_X86_OPERAND_IMMEDIATE)value=static_cast<unsigned>(src.value.imm)&255;
      else if(src.kind==XAIR_X86_OPERAND_REGISTER&&reg(src,src.value.reg.parent,8)&&constants.contains(src.value.reg.parent))
        value=constants.at(src.value.reg.parent)&255;
      else throw std::runtime_error("Initializer byte has no exact constant definition");
      stores[static_cast<int>(offset)]=static_cast<unsigned char>(value);
    } else if(i.mnemonic==XAIR_X86_MNEMONIC_LEA&&dst.kind==XAIR_X86_OPERAND_REGISTER&&
              dst.value.reg.parent!=XAIR_X86_RBP&&dst.value.reg.parent!=XAIR_X86_RSP&&reg(dst,dst.value.reg.parent,32)&&
              src.kind==XAIR_X86_OPERAND_MEMORY&&src.value.mem.has_base&&!src.value.mem.has_index&&
              src.value.mem.base.parent==XAIR_X86_RBP&&src.value.mem.displacement<0&&
              src.value.mem.displacement>=-static_cast<std::int64_t>(frame)) {
      pointers[dst.value.reg.parent]=static_cast<int>(src.value.mem.displacement);constants.erase(dst.value.reg.parent);
    } else if(i.flow==XAIR_X86_FLOW_INDIRECT_CALL&&dst.kind==XAIR_X86_OPERAND_REGISTER&&
              reg(dst,dst.value.reg.parent,32)&&pointers.contains(dst.value.reg.parent)) {
      if(stores.size()!=recovery.at("input_size").get<std::size_t>()||stores.empty()||
         pointers.at(dst.value.reg.parent)!=stores.begin()->first||
         4-stores.begin()->first!=recovery.at("local_base").get<int>())
        throw std::runtime_error("Invoked native buffer differs from the Ghidra initializer range");
      std::string initialized;int offset=stores.begin()->first;
      for(const auto &[address,value]:stores) {
        if(address!=offset++)throw std::runtime_error("Native initializer has a hole");
        initialized.push_back(static_cast<char>(value));
      }
      if(sha256_text(initialized)!=recovery.at("input_sha256").get<std::string>())throw std::runtime_error("Native stores differ from reconstructed bytes");
      return {{"engine","XAIR"},{"straight_line",true},{"store_count",stores.size()},
        {"buffer_ebp_displacement",stores.begin()->first},{"call_offset",at},{"input_sha256",recovery.at("input_sha256")}};
    } else throw std::runtime_error("Unsupported initializer instruction, branch, call, or aliasing write");
    at=i.fallthrough;
  }
  throw std::runtime_error("No proven native transfer to the initialized buffer");
}
inline wb::J recovery_artifact_initializer(ProjectStore &store,const wb::J &inv,const std::string &entry,const wb::J &recovery) {
  const auto target=store.target(inv.at("project").get<std::string>(),inv.at("target_id").get<std::string>(),true);
  if(target.size>64*1024*1024)throw std::runtime_error("Initializer artifact exceeds 64 MiB");
  struct Image {xair_binary_view view{};~Image(){xair_binary_view_destroy(&view);}} image;
  xair_binary_load_options options{};xair_binary_load_options_init(&options);
  options.analysis.max_bytes=64*1024*1024;options.analysis.max_memory=128*1024*1024;options.analysis.max_wall_time=5000;
  xair_analysis_result result{};xair_diagnostic diagnostic{};
  const auto raw=wb::read(target.object_path,64*1024*1024);
  if(sha256_text(raw)!=inv.at("artifact_sha256").get<std::string>()||
     xair_binary_view_load_bytes_ex(raw.data(),raw.size(),&options,&image.view,&result,&diagnostic)!=XAIR_OK||image.view.arch!=XAIR_ARCH_X86_32)
    throw std::runtime_error("Native initializer requires an intact x86-32 artifact");
  const auto address=runtime_number(entry);
  const auto *segment=xair_binary_view_find_segment(&image.view,address,XAIR_BINARY_PERM_EXEC);
  if(!segment||address<segment->va||address-segment->va>=segment->file_size)throw std::runtime_error("Initializer has no file-backed executable mapping");
  const auto length=std::min<std::uint64_t>(16384,segment->file_size-(address-segment->va));
  std::vector<unsigned char> bytes(length);
  if(xair_binary_view_read(&image.view,address,bytes.data(),bytes.size())!=XAIR_OK)throw std::runtime_error("Initializer read failed");
  auto proof=recovery_native_initializer(bytes,recovery);proof["function_entry"]=entry;
  return proof;
}
inline RecoveryFlow recovery_control_flow(const std::vector<unsigned char> &bytes,std::size_t entry=0,std::size_t stop=std::size_t(-1)) {
  RecoveryFlow result;result.engine_available=true;std::deque<std::size_t> pending({entry});
  auto enqueue=[&](std::uint64_t address) {if(address>=bytes.size()){result.complete=false;return;}if(!result.reachable.contains(static_cast<std::size_t>(address)))pending.push_back(static_cast<std::size_t>(address));};
  while(!pending.empty()&&result.reachable.size()<4096) {
    const auto at=pending.front();pending.pop_front();
    if(result.reachable.contains(at))continue;
    xair_x86_decoded_inst instruction{};
    if(!recovery_decode(bytes,at,instruction)){result.complete=false;continue;}
    result.reachable.insert(at);
    if(at==stop)continue;
    switch(instruction.flow) {
      case XAIR_X86_FLOW_NORMAL:enqueue(instruction.fallthrough);break;
      case XAIR_X86_FLOW_CONDITIONAL_JUMP:enqueue(instruction.branch_target);enqueue(instruction.fallthrough);break;
      case XAIR_X86_FLOW_DIRECT_JUMP:enqueue(instruction.branch_target);break;
      case XAIR_X86_FLOW_DIRECT_CALL:case XAIR_X86_FLOW_INDIRECT_CALL:enqueue(instruction.fallthrough);break;
      default:break;
    }
  }
  if(!pending.empty())result.complete=false;
  return result;
}

inline wb::J recovery_stage_validation(const std::vector<unsigned char> &bytes,std::size_t call,std::size_t loop,const std::string &kind) {
  using namespace wb;
  auto exact=[&](std::size_t at,std::initializer_list<unsigned char> expected) {
    if(at>bytes.size()||expected.size()>bytes.size()-at||!std::equal(expected.begin(),expected.end(),bytes.begin()+at))
      throw std::runtime_error("Unsupported decoder operands or state transition");
  };
  auto decode=[&](std::size_t at,xair_x86_mnemonic mnemonic) {
    xair_x86_decoded_inst instruction{};
    if(!recovery_decode(bytes,at,instruction)||instruction.mnemonic!=mnemonic)
      throw std::runtime_error("Decoder instruction boundary or mnemonic rejected by XAIR");
    return instruction;
  };
  const auto call_instruction=decode(call,XAIR_X86_MNEMONIC_CALL);
  if(call_instruction.flow!=XAIR_X86_FLOW_DIRECT_CALL||call_instruction.branch_target!=call_instruction.fallthrough)
    throw std::runtime_error("Decoder get-PC call has altered control flow");
  decode(call+5,XAIR_X86_MNEMONIC_MOV);decode(call+8,XAIR_X86_MNEMONIC_ADD);
  exact(call+5,{0x8b,0x34,0x24,0x83,0xc6});
  std::size_t compare=0,condition=0,back=0,exit=0;
  if(kind=="xor_byte") {
    if(loop!=call+21)throw std::runtime_error("Non-contiguous byte decoder");
    exact(call+11,{0xb9});exact(loop-5,{0x83,0xf9,0});
    exact(loop,{0x80,0x36});exact(loop+3,{0x46,0x49});
    compare=loop-5;condition=loop-2;back=loop+5;exit=loop+7;
    decode(loop,XAIR_X86_MNEMONIC_XOR);decode(loop+3,XAIR_X86_MNEMONIC_INC);decode(loop+4,XAIR_X86_MNEMONIC_DEC);
  } else if(kind=="xor_dword") {
    if(loop!=call+21)throw std::runtime_error("Non-contiguous DWORD decoder");
    exact(call+11,{0xb9});exact(loop-5,{0x83,0xf9,0});
    exact(loop,{0x81,0x36});exact(loop+6,{0x83,0xc6,4,0x83,0xe9,4});
    compare=loop-5;condition=loop-2;back=loop+12;exit=loop+14;
    decode(loop,XAIR_X86_MNEMONIC_XOR);decode(loop+6,XAIR_X86_MNEMONIC_ADD);decode(loop+9,XAIR_X86_MNEMONIC_SUB);
  } else {
    if(loop!=call+37||call<7)throw std::runtime_error("Non-contiguous repeating-key decoder");
    exact(call-2,{0x89,0xe3});
    exact(call+11,{0x89,0xf1,0x81,0xc1});
    exact(call+19,{0x89,0xd8,0x83,0xc0});
    exact(call+24,{0x39,0xd8,0x75,5,0x89,0xe3,0x83,0xc3,4,0x39,0xce});
    exact(loop,{0x8a,0x13,0x30,0x16,0x43,0x46});
    const auto key_size=bytes[call+23];
    std::size_t pushed=0,at=call-2;
    while(at>=5&&bytes[at-5]==0x68){pushed+=4;at-=5;}
    if(!key_size||key_size>127||pushed<key_size||pushed-key_size>3)
      throw std::runtime_error("Repeating key is not the adjacent initialized stack range");
    compare=loop-4;condition=loop-2;back=loop+6;exit=loop+8;
    decode(loop,XAIR_X86_MNEMONIC_MOV);decode(loop+2,XAIR_X86_MNEMONIC_XOR);
    decode(loop+4,XAIR_X86_MNEMONIC_INC);decode(loop+5,XAIR_X86_MNEMONIC_INC);
  }
  decode(compare,XAIR_X86_MNEMONIC_CMP);
  const auto branch=decode(condition,XAIR_X86_MNEMONIC_JCC),jump=decode(back,XAIR_X86_MNEMONIC_JMP);
  const auto expected_condition=kind=="xor_dword"?XAIR_X86_COND_LE:XAIR_X86_COND_E;
  if(branch.flow!=XAIR_X86_FLOW_CONDITIONAL_JUMP||branch.condition!=expected_condition||branch.branch_target!=exit||
     jump.flow!=XAIR_X86_FLOW_DIRECT_JUMP||jump.branch_target!=(kind=="xor_repeating_key"?call+24:compare))
    throw std::runtime_error("Decoder loop branch condition or edge rejected by XAIR: branch="+
      std::to_string(branch.flow)+"/"+std::to_string(branch.condition)+"/"+std::to_string(branch.branch_target)+
      " expected="+std::to_string(expected_condition)+"/"+std::to_string(exit)+" jump="+
      std::to_string(jump.flow)+"/"+std::to_string(jump.branch_target)+" compare="+std::to_string(compare));
  return {{"engine","XAIR/xair_x86_decode_instruction"},{"architecture","x86-32"},
    {"instruction_boundaries_verified",true},{"loop_condition_verified",true},{"operands_verified",true},{"loop_exit",exit},
    {"loop_back_edge",jump.branch_target},{"decoder_reachable",true}};
}
#else
inline wb::J recovery_artifact_initializer(ProjectStore &,const wb::J &,const std::string &,const wb::J &) {
  throw std::runtime_error("XAIR required for native initializer proof");
}
inline RecoveryFlow recovery_control_flow(const std::vector<unsigned char> &,std::size_t=0,std::size_t=std::size_t(-1)) {return {};}
inline wb::J recovery_stage_validation(const std::vector<unsigned char> &,std::size_t,std::size_t,const std::string &) {
  throw std::runtime_error("XAIR instruction decoder is required for decoder validation");
}
#endif

inline wb::J recover_initialized_x86_blob(const std::string &source) {
  using namespace wb;
  if(source.size()>1024*1024)throw std::runtime_error("Decompiler source exceeds recovery bound");
  std::regex assignment(R"(local_([0-9a-fA-F]+)\s*=\s*(?:\(code\))?(0x[0-9a-fA-F]+|[0-9]+)\s*;)");
  std::map<unsigned,unsigned char,std::greater<unsigned>> locals;
  for(std::sregex_iterator it(source.begin(),source.end(),assignment),end;it!=end;++it) {
    auto offset=static_cast<unsigned>(std::stoul((*it)[1].str(),nullptr,16));
    auto value=std::stoul((*it)[2].str(),nullptr,0);
    if(value>255)continue;
    if(locals.contains(offset))throw std::runtime_error("Repeated local initializer; overwrite/control-flow semantics require native analysis");
    locals[offset]=static_cast<unsigned char>(value);
  }
  if(locals.size()<16||locals.size()>4096)throw std::runtime_error("No bounded initialized local-byte blob found");
  std::vector<unsigned char> bytes;bytes.reserve(locals.size());
  unsigned previous=locals.begin()->first;
  for(const auto &[offset,value]:locals) {
    if(!bytes.empty()&&offset+1!=previous)throw std::runtime_error("Non-contiguous local initializers require native layout analysis");
    bytes.push_back(value);previous=offset;
  }
  if(bytes.size()<16)throw std::runtime_error("Initialized local bytes are not contiguous");
  const auto original_sha=sha256_text(std::string(reinterpret_cast<const char*>(bytes.data()),bytes.size()));
  J stages=J::array();std::set<std::size_t> decoded;std::size_t continuation=0;
  auto u32=[&](std::size_t at)->std::uint32_t {
    if(at+4>bytes.size())throw std::runtime_error("Decoder immediate outside blob");
    return std::uint32_t(bytes[at])|(std::uint32_t(bytes[at+1])<<8)|(std::uint32_t(bytes[at+2])<<16)|(std::uint32_t(bytes[at+3])<<24);
  };
  auto header=[&](std::size_t loop,std::size_t &call_site,std::size_t &start,std::size_t &size)->bool {
    const auto begin=loop>64?loop-64:0;
    for(std::size_t call=begin;call+19<=loop;++call)
      if(bytes[call]==0xe8&&u32(call+1)==0&&bytes[call+5]==0x8b&&bytes[call+6]==0x34&&bytes[call+7]==0x24&&
         bytes[call+8]==0x83&&bytes[call+9]==0xc6) {
        if(bytes[call+11]==0xb9)size=u32(call+12);
        else if(bytes[call+11]==0x89&&bytes[call+12]==0xf1&&bytes[call+13]==0x81&&bytes[call+14]==0xc1)size=u32(call+15);
        else continue;
        if(bytes[call+10]>127)return false; // ADD imm8 is sign-extended.
        call_site=call;start=call+5+bytes[call+10];return size>0&&start<=bytes.size()&&size<=bytes.size()-start;
      }
    return false;
  };
  auto pushed_key=[&](std::size_t loop,std::size_t key_size)->std::vector<unsigned char> {
    if(key_size<1||key_size>128)return {};
    for(std::size_t cursor=loop;cursor>=2;--cursor) {
      if(bytes[cursor-2]!=0x89||bytes[cursor-1]!=0xe3)continue;
      std::vector<std::array<unsigned char,4>> pushes;
      std::size_t at=cursor-2;
      while(at>=5&&bytes[at-5]==0x68) {
        pushes.push_back({bytes[at-4],bytes[at-3],bytes[at-2],bytes[at-1]});at-=5;
      }
      std::vector<unsigned char> key;
      for(auto it=pushes.begin();it!=pushes.end();++it)key.insert(key.end(),it->begin(),it->end());
      if(key.size()>=key_size){key.resize(key_size);return key;}
    }
    return {};
  };
  for(unsigned pass=0;pass<8;++pass) {
    bool changed=false;const auto flow=recovery_control_flow(bytes);
    if(!flow.engine_available)throw std::runtime_error("XAIR instruction decoder is required for decoder recovery");
    for(std::size_t at=0;at+12<bytes.size();++at) {
      if(decoded.contains(at))continue;
      std::size_t call_site=0,start=0,size=0;std::vector<unsigned char> key;std::string kind;
      if(at+6<bytes.size()&&bytes[at]==0x80&&bytes[at+1]==0x36&&bytes[at+3]==0x46&&bytes[at+4]==0x49) {
        if(bytes[at+5]!=0xeb||bytes[at+6]<128)continue;
        if(!header(at,call_site,start,size))continue;
        key={bytes[at+2]};kind="xor_byte";
      } else if(at+15<bytes.size()&&bytes[at]==0x81&&bytes[at+1]==0x36&&bytes[at+6]==0x83&&bytes[at+7]==0xc6&&bytes[at+8]==4) {
        if(!header(at,call_site,start,size))continue;
        if(size%4)continue;
        key={bytes[at+2],bytes[at+3],bytes[at+4],bytes[at+5]};kind="xor_dword";
      } else if(at+6<bytes.size()&&bytes[at]==0x8a&&bytes[at+1]==0x13&&bytes[at+2]==0x30&&bytes[at+3]==0x16&&bytes[at+4]==0x43&&bytes[at+5]==0x46) {
        if(!header(at,call_site,start,size))continue;
        std::size_t key_size=0;
        for(std::size_t p=at>32?at-32:0;p+3<at;++p)if(bytes[p]==0x83&&bytes[p+1]==0xc0)key_size=bytes[p+2];
        key=pushed_key(at,key_size);if(key.empty())continue;kind="xor_repeating_key";
      } else continue;
      if(!flow.reachable.contains(call_site)||!flow.reachable.contains(at))continue;
      const auto validation=recovery_stage_validation(bytes,call_site,at,kind);
      if(start<validation.at("loop_exit").get<std::size_t>()||size>0x7fffffff)
        throw std::runtime_error("Decoder writes overlap its own instructions or overflow its signed counter");
#if INDAGO_HAS_XAIR
      // All paths between decoder macros must be this single, bounded path.
      // Unknown calls/conditional paths cannot silently preserve decoder state.
      auto cursor=continuation;unsigned steps=0;
      while(cursor!=call_site&&steps++<4096) {
        xair_x86_decoded_inst i{};
        if(cursor>call_site||!recovery_decode(bytes,cursor,i))throw std::runtime_error("Decoder continuation is not an instruction path");
        if(i.flow==XAIR_X86_FLOW_DIRECT_JUMP&&i.branch_target>cursor&&i.branch_target<=call_site) {cursor=i.branch_target;continue;}
        const bool push=i.mnemonic==XAIR_X86_MNEMONIC_PUSH&&i.operands[0].kind==XAIR_X86_OPERAND_IMMEDIATE;
        const bool key_base=i.length==2&&bytes[cursor]==0x89&&bytes[cursor+1]==0xe3;
        const bool padding=i.length==6&&bytes[cursor]==0x8d&&bytes[cursor+1]==0x80&&
          bytes[cursor+2]==0&&bytes[cursor+3]==0&&bytes[cursor+4]==0&&bytes[cursor+5]==0;
        if(i.flow!=XAIR_X86_FLOW_NORMAL||!(push||key_base||padding||i.mnemonic==XAIR_X86_MNEMONIC_NOP))
          throw std::runtime_error("Unmodeled state change between decoder stages");
        cursor=i.fallthrough;
      }
      if(cursor!=call_site)throw std::runtime_error("Decoder continuation bound exceeded");
#endif
      for(std::size_t i=0;i<size;++i)bytes[start+i]^=key[i%key.size()];
      continuation=validation.at("loop_exit").get<std::size_t>();
      decoded.insert(at);stages.push_back({{"kind",kind},{"entry_offset",call_site},{"decoder_offset",at},
        {"output_offset",start},{"size",size},{"key_hex",reasoning_hex(key)},{"validation",validation}});
      changed=true;break;
    }
    if(!changed)break;
  }
  const auto final_flow=recovery_control_flow(bytes,continuation);J strings=J::array();
  for(std::size_t mov=0;mov+1<bytes.size();++mov)if(bytes[mov]==0x89&&bytes[mov+1]==0xe1&&final_flow.reachable.contains(mov)) {
    std::vector<std::array<unsigned char,4>> pushes;std::size_t at=mov;
    while(at>=5&&bytes[at-5]==0x68&&final_flow.reachable.contains(at-5)){pushes.push_back({bytes[at-4],bytes[at-3],bytes[at-2],bytes[at-1]});at-=5;}
    if(pushes.empty())continue;
    const auto construction=at;
    std::string raw;for(auto &part:pushes)raw.append(reinterpret_cast<const char*>(part.data()),4);
    std::size_t cursor=mov+2;J mutation=nullptr;
    if(cursor+3<=bytes.size()&&bytes[cursor]==0xfe&&bytes[cursor+1]==0x49) {
      const auto offset=bytes[cursor+2];
      if(offset>=raw.size()||static_cast<unsigned char>(raw[offset])!=1||!final_flow.reachable.contains(cursor))continue;
      raw[offset]=0;mutation={{"kind","decrement_sentinel_to_nul"},{"offset",offset}};cursor+=3;
    }
    if(cursor+6>bytes.size()||bytes[cursor]!=0x31||bytes[cursor+1]!=0xc0||
       bytes[cursor+2]!=0x51||bytes[cursor+3]!=0x50||bytes[cursor+4]!=0xff||bytes[cursor+5]!=0xd7||
       !final_flow.reachable.contains(cursor)||!final_flow.reachable.contains(cursor+2)||
       !final_flow.reachable.contains(cursor+3)||!final_flow.reachable.contains(cursor+4))continue;
#if INDAGO_HAS_XAIR
    xair_x86_decoded_inst call_instruction{};
    if(!recovery_decode(bytes,cursor+4,call_instruction)||call_instruction.mnemonic!=XAIR_X86_MNEMONIC_CALL||
       call_instruction.flow!=XAIR_X86_FLOW_INDIRECT_CALL)continue;
    const auto sink_flow=recovery_control_flow(bytes,continuation,cursor+4);
    if(!sink_flow.complete)throw std::runtime_error("Incomplete decoded value-to-sink control flow");
    for(const auto pc:sink_flow.reachable) {
      xair_x86_decoded_inst instruction{};
      if(!recovery_decode(bytes,pc,instruction))throw std::runtime_error("Sink path decode failed");
      if(instruction.flow==XAIR_X86_FLOW_DIRECT_CALL||instruction.flow==XAIR_X86_FLOW_INDIRECT_JUMP||
         (instruction.flow==XAIR_X86_FLOW_INDIRECT_CALL&&pc!=cursor+4))
        throw std::runtime_error("Unmodeled call or indirect flow before the value sink");
      if((instruction.flow==XAIR_X86_FLOW_DIRECT_JUMP||instruction.flow==XAIR_X86_FLOW_CONDITIONAL_JUMP)&&
         instruction.branch_target>construction&&instruction.branch_target<=cursor+4)
        throw std::runtime_error("Control flow bypasses part of the value construction");
      for(unsigned operand=0;operand<instruction.visible_operand_count;++operand) {
        const auto &o=instruction.operands[operand];
        if(o.kind==XAIR_X86_OPERAND_MEMORY&&(o.actions&(XAIR_X86_ACTION_WRITE|XAIR_X86_ACTION_COND_WRITE))&&
           !(pc==mov+2&&!mutation.is_null()))
          throw std::runtime_error("Unmodeled memory write on the decoded sink path");
      }
    }
#endif
    auto value=raw;auto zero=value.find('\0');if(zero!=std::string::npos)value.resize(zero);
    while(!value.empty()&&static_cast<unsigned char>(value.back())<=32)value.pop_back();
    auto first=value.find_first_not_of(" \t\r\n");if(first!=std::string::npos)value.erase(0,first);
    if(value.size()>=3&&std::all_of(value.begin(),value.end(),[](unsigned char c){return c>=32&&c<127;}))
      strings.push_back({{"offset",mov},{"text",value},{"raw_hex",reasoning_hex(std::vector<unsigned char>(raw.begin(),raw.end()))},
        {"normalization","truncate at NUL, trim surrounding ASCII whitespace"},{"mutation",mutation},
        {"sink",{{"kind","indirect_call_argument"},{"argument_register","ecx"},{"call_offset",cursor+4},
          {"instruction_validated",true},{"control_flow_reachable",true},{"writes_between_value_and_sink",0}}}});
  }
  if(stages.empty()||strings.empty())throw std::runtime_error("No supported static decoder chain and output string found");
  std::set<std::string> alternatives;for(const auto &s:strings)alternatives.insert(s.at("text"));
  if(alternatives.size()!=1)throw std::runtime_error("Multiple printable candidates; native output-use analysis required");
  const auto answer=*alternatives.begin();
  return {{"schema","indago.static-recovery.v1"},{"local_base",locals.begin()->first},{"input_size",locals.size()},{"contiguous_size",bytes.size()},
    {"input_sha256",original_sha},{"decoded_sha256",sha256_text(std::string(reinterpret_cast<const char*>(bytes.data()),bytes.size()))},
    {"stages",stages},{"strings",strings},{"answer",answer},{"state","candidate_output_recovered"},
    {"verification_kind","recovered_candidate"},{"instruction_engine","XAIR/xair_x86_decode_instruction"},
    {"native_control_flow_verified",true},{"value_to_sink_verified",true},{"target_output_observed",false},
    {"accepted_input_verified",false},{"independently_graded",false},{"verified_solve",false},
    {"proof_scope","Question-bound static candidate. XAIR validates decoder instruction boundaries, loop edges, reachability, and value flow to an indirect call argument; the call target and runtime output are not established here"}};
}
inline wb::J reasoning_update(ProjectStore &store,const wb::J &inv,const wb::J &request) {
  using namespace wb;
  keys(request,{"operation","expected_revision","record"});
  auto state=inv.value("reasoning",reasoning_initial(inv));
  if(!state.contains("proofs"))state["proofs"]=J::array();
  if(!state.contains("questions"))state["questions"]=reasoning_initial(inv).at("questions");
  if(request.at("expected_revision")!=state.at("revision"))throw std::runtime_error("revision_conflict: reasoning changed");
  const auto op=request.at("operation").get<std::string>();
  const auto &r=request.at("record");
  auto string=[&](const J &obj,const char *key,std::size_t max=1024) {
    auto value=obj.at(key).get<std::string>();
    if(value.empty()||value.size()>max)throw std::runtime_error(std::string("Invalid reasoning field: ")+key);
    return value;
  };
  auto lookup=[&](const char *collection,const J &id)->J& {
    for(auto &item:state.at(collection))if(item.at("id")==id)return item;
    throw std::runtime_error("Unknown reasoning record");
  };
  auto sources=[&](const J &refs) {
    if(!refs.is_array()||refs.empty()||refs.size()>8)throw std::runtime_error("Require 1..8 native source references");
    J pins=J::array();
    for(const auto &ref:refs) {
      keys(ref,{"evidence_id","pointer"});
      auto page=harness_evidence_page(store,inv,{{"id",ref.at("evidence_id")},{"pointer",ref.at("pointer")},{"max_bytes",128},{"limit",1}});
      if(!page.value("source_verified",false))throw std::runtime_error("Unverified reasoning source");
      pins.push_back({{"evidence_id",page.at("id")},{"pointer",page.at("pointer")},{"raw_sha256",page.at("raw_sha256")},
        {"revision",page.at("revision")},{"native_status",page.at("native_status")}});
    }
    return pins;
  };
  auto full_source_value=[&](const J &pin) {
    Db db(store.root()/"indago-native.sqlite3");
    Q row(db,"SELECT record,sha FROM evidence WHERE project=? AND id=?");
    if(!row.s(1,inv.at("project").get<std::string>()).s(2,pin.at("evidence_id").get<std::string>()).row())
      throw std::runtime_error("Recovery evidence unavailable");
    const auto metadata=J::parse(row.text(0));const auto raw_sha=row.text(1);
    if(raw_sha!=pin.at("raw_sha256").get<std::string>()||metadata.at("raw_sha256").get<std::string>()!=raw_sha||metadata.at("revision")!=pin.at("revision")||
       !harness_contains_artifact(inv,metadata.at("artifact_sha256")))
      throw std::runtime_error("Recovery evidence pin or scope changed");
    const auto raw_path=object(store,raw_sha);
    if(fs::file_size(raw_path)>16*1024*1024)throw std::runtime_error("Recovery evidence exceeds 16 MiB bound");
    const auto bytes=read(raw_path,16*1024*1024);
    if(sha256_text(bytes)!=raw_sha)throw std::runtime_error("Recovery evidence integrity failure");
    return J::parse(bytes);
  };
  auto pinned_value=[&](const J &pin) {
    const auto native=full_source_value(pin);
    return native.at(J::json_pointer(pin.at("pointer").get<std::string>()));
  };
  auto full_source_text=[&](const J &pin) {
    const auto value=pinned_value(pin);
    if(!value.is_string())throw std::runtime_error("Recovery source must be native text");
    return value.get<std::string>();
  };
  auto append=[&](const char *collection,J item)->J& {
    if(state.at(collection).size()>=16)throw std::runtime_error("Reasoning collection limit is 16");
    item["id"]=std::string(collection)+"_"+std::to_string(state.at("revision").get<unsigned>()+1);
    state[collection].push_back(item);
    return state[collection].back();
  };
  auto signed_proof=[&](J proof)->J& {
    proof["schema"]="indago.solution-proof.v1";proof["project"]=inv.at("project");
    proof["investigation"]=inv.at("id");proof["artifact_sha256"]=inv.at("artifact_sha256");
    auto &saved=append("proofs",std::move(proof));auto unsigned_record=saved;
    unsigned_record.erase("record_sha256");saved["record_sha256"]=sha256_text(unsigned_record.dump());return saved;
  };
  if(op=="bind") {
    keys(r,{"id","description","sources"});
    auto &item=lookup("obligations",r.at("id"));
    item["description"]=string(r,"description");item["sources"]=sources(r.at("sources"));
    item["state"]="located_unproven";
  } else if(op=="hypothesize") {
    keys(r,{"obligation","statement","prediction","falsifier","sources"});
    lookup("obligations",r.at("obligation"));
    append("hypotheses",{{"obligation",r.at("obligation")},{"statement",string(r,"statement")},
      {"prediction",string(r,"prediction")},{"falsifier",string(r,"falsifier")},
      {"sources",sources(r.at("sources"))},{"state","untested"}});
  } else if(op=="revise_hypothesis") {
    keys(r,{"id","statement","prediction","falsifier","sources"});auto &item=lookup("hypotheses",r.at("id"));
    item={{"id",item.at("id")},{"obligation",item.at("obligation")},{"statement",string(r,"statement")},
      {"prediction",string(r,"prediction")},{"falsifier",string(r,"falsifier")},{"sources",sources(r.at("sources"))},{"state","untested"}};
  } else if(op=="check_hypothesis") {
    keys(r,{"id","checks"});auto &item=lookup("hypotheses",r.at("id"));
    const auto receipt=harness_validate(store,inv,r.at("checks"));
    item["check"]=receipt;item["state"]=receipt.at("status")=="passed"?"finite_check_passed":"finite_check_contradicted";
    item["semantic_entailment_checked"]=false;
  } else if(op=="candidate") {
    keys(r,{"obligation","hex","encoding","assumptions","sources"});
    lookup("obligations",r.at("obligation"));
    auto bytes=string(r,"hex",1024);
    if(bytes.size()%2||bytes.find_first_not_of("0123456789abcdefABCDEF")!=bytes.npos)throw std::runtime_error("Candidate requires exact hex bytes");
    std::transform(bytes.begin(),bytes.end(),bytes.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
    append("candidates",{{"obligation",r.at("obligation")},{"hex",bytes},{"encoding",string(r,"encoding",64)},
      {"assumptions",string(r,"assumptions")},{"sources",sources(r.at("sources"))},{"state","unvalidated"}});
  } else if(op=="derive") {
    keys(r,{"obligation","source","representation","spec","encoding","assumptions"});
    lookup("obligations",r.at("obligation"));
    const auto pinned=sources(J::array({r.at("source")}));
    auto page=harness_evidence_page(store,inv,{{"id",pinned[0].at("evidence_id")},{"pointer",pinned[0].at("pointer")},
      {"raw_sha256",pinned[0].at("raw_sha256")},{"max_bytes",512}});
    if(page.value("partial",true)||!page.contains("text"))throw std::runtime_error("Derivation requires complete bounded native text or hex");
    const auto derived=candidate_transform(page.at("text"),string(r,"representation",16),r.at("spec"));
    append("candidates",{{"obligation",r.at("obligation")},{"hex",derived.at("hex")},{"encoding",string(r,"encoding",64)},
      {"assumptions",string(r,"assumptions")},{"sources",pinned},{"derivation",derived},{"state","derived_unvalidated"}});
  } else if(op=="validate_transform_candidate") {
    keys(r,{"id","expected","representation","spec"});auto &item=lookup("candidates",r.at("id"));
    const auto pinned=sources(J::array({r.at("expected")}));
    auto page=harness_evidence_page(store,inv,{{"id",pinned[0].at("evidence_id")},{"pointer",pinned[0].at("pointer")},
      {"raw_sha256",pinned[0].at("raw_sha256")},{"max_bytes",512}});
    if(page.value("partial",true)||!page.contains("text"))throw std::runtime_error("Validation requires complete native expected bytes");
    const auto expected=candidate_transform(page.at("text"),string(r,"representation",16),{{"method","slice"}});
    const auto actual=candidate_transform(item.at("hex"),"hex",r.at("spec"));
    const bool matched=expected.at("hex")==actual.at("hex");
    item["check"]={{"actual",actual},{"expected",expected},{"sources",pinned},{"matched",matched},
      {"scope","finite byte transform under declared spec only; target implements this spec is unproven"}};
    item["state"]=matched?"finite_transform_matched":"finite_transform_contradicted";
    item["acceptance_proven"]=false;
  } else if(op=="validate_candidate") {
    keys(r,{"id","actual"});auto &item=lookup("candidates",r.at("id"));
    const auto pinned=sources(J::array({r.at("actual")}));
    const auto receipt=harness_validate(store,inv,J::array({{{"operation","equal"},{"operands",J::array({
      {{"evidence_id",pinned[0].at("evidence_id")},{"pointer",pinned[0].at("pointer")},{"raw_sha256",pinned[0].at("raw_sha256")}}})},{"expected",item.at("hex")}}}));
    item["check"]=receipt;item["state"]=receipt.at("status")=="passed"?"exact_representation_matched":"representation_contradicted";
    item["acceptance_proven"]=false;
  } else if(op=="experiment") {
    keys(r,{"hypothesis","candidate","prediction","observe","sources","pointer","expected","fact_index","proof_kind"});
    const auto &hypothesis=lookup("hypotheses",r.at("hypothesis"));
    const auto &candidate=lookup("candidates",r.at("candidate"));
    const auto observe=string(r,"observe",64);
    if(!std::set<std::string>{"capture_reanalyze","branch_witness","io_result"}.contains(observe))throw std::runtime_error("Unsupported experiment recipe");
    if(!r.at("expected").is_primitive()||r.at("expected").dump().size()>512)throw std::runtime_error("Experiment expected must be a bounded scalar");
    J experiment{{"hypothesis",r.at("hypothesis")},{"candidate",r.at("candidate")},
      {"hypothesis_sha256",sha256_text(lookup("hypotheses",r.at("hypothesis")).dump())},
      {"candidate_sha256",sha256_text(lookup("candidates",r.at("candidate")).dump())},
      {"pointer",string(r,"pointer",1024)},{"expected",r.at("expected")},
      {"prediction",string(r,"prediction")},{"observe",observe},{"sources",sources(r.at("sources"))},
      {"state","awaiting_operator_execution"},{"execution_authorized",false}};
    if(r.contains("fact_index")!=r.contains("proof_kind"))throw std::runtime_error("Runtime proof plan requires both fact_index and proof_kind");
    if(r.contains("proof_kind")) {
      const auto index=r.at("fact_index").get<std::size_t>();
      const auto kind=string(r,"proof_kind",64);
      if(index>=inv.at("required_facts").size()||!std::set<std::string>{"observed_output","accepted_input"}.contains(kind)||observe!="io_result")
        throw std::runtime_error("Runtime proof plan must bind an io_result to an output or accepted-input question");
      if(lookup("obligations",hypothesis.at("obligation")).at("fact_index")!=index||
         lookup("obligations",candidate.at("obligation")).at("fact_index")!=index)
        throw std::runtime_error("Runtime proof hypothesis and candidate must belong to the same question");
      if((kind=="observed_output"&&(r.at("pointer")!="/data/output"||!r.at("expected").is_string()))||
         (kind=="accepted_input"&&(r.at("pointer")!="/data/accepted"||r.at("expected")!=true)))
        throw std::runtime_error("Runtime output uses /data/output text; accepted input uses /data/accepted=true");
      experiment["fact_index"]=index;experiment["question"]=inv.at("required_facts")[index];experiment["proof_kind"]=kind;
    }
    append("experiments",std::move(experiment));
  } else if(op=="feedback") {
    keys(r,{"id","session","observation","sha256"});
    auto &item=lookup("experiments",r.at("id"));
    if(item.contains("receipt"))throw std::runtime_error("Experiment already has feedback; create a new experiment for another observation");
    if(item.at("hypothesis_sha256")!=sha256_text(lookup("hypotheses",item.at("hypothesis")).dump())||
       item.at("candidate_sha256")!=sha256_text(lookup("candidates",item.at("candidate")).dump()))
      throw std::runtime_error("Experiment hypothesis or candidate changed; preserve old experiment and plan a new one");
    const auto sessions=inv.value("runtime_observation_sessions",J::array());
    if(std::find(sessions.begin(),sessions.end(),r.at("session"))==sessions.end())
      throw std::runtime_error("capability_blocked: runtime session read grant required at investigation creation");
    if(!fs::exists(store.root()/"runtime.sqlite3"))throw std::runtime_error("Runtime evidence unavailable");
    auto session=runtime_command(store,{},{{"operation","status"},{"project",inv.at("project")},{"session",r.at("session")}});
    if(!harness_contains_artifact(inv,session.at("artifact_sha256")))throw std::runtime_error("Runtime session outside artifact scope");
    auto rows=runtime_command(store,{},{{"operation","observations"},{"project",inv.at("project")},{"session",r.at("session")},{"id",r.at("observation")},{"limit",1}}).at("observations");
    if(rows.empty()||rows[0].at("sha256")!=r.at("sha256"))throw std::runtime_error("Missing or changed runtime observation pin");
    const auto &observation=rows[0];
    const auto expected_kind=item.at("observe")=="branch_witness"?"witness_validation":item.at("observe")=="capture_reanalyze"?"runtime_feedback":"io_result";
    if(observation.at("kind")!=expected_kind)throw std::runtime_error("Observation kind does not match planned experiment");
    if(item.contains("proof_kind")&&(session.at("artifact_sha256")!=inv.at("artifact_sha256")||
       observation.at("data").value("producer",std::string())!="indago/bounded-stdio-v1"||
       observation.at("data").value("artifact_sha256",std::string())!=inv.at("artifact_sha256").get<std::string>()||
       !observation.at("data").value("complete",false)))
      throw std::runtime_error("Runtime proof requires a complete same-primary-artifact native I/O receipt");
    const auto value=observation.at(J::json_pointer(item.at("pointer").get<std::string>()));
    if(!value.is_primitive()||value.dump().size()>512)throw std::runtime_error("Feedback requires a complete bounded scalar");
    const bool matches=value==item.at("expected");
    item["receipt"]={{"session",r.at("session")},{"observation",r.at("observation")},{"sha256",r.at("sha256")},
      {"actual",value},{"expected",item.at("expected")},{"matches",matches},{"scope","this recorded execution only; candidate causality and entry-point acceptance not proven"}};
    if(item.value("proof_kind",std::string())=="accepted_input") {
      if(observation.at("data").value("acceptance_fact",std::string())!=item.at("question").get<std::string>()||
         !observation.at("data").contains("negative_control"))
        throw std::runtime_error("Acceptance oracle is not bound to this question and negative control");
      const auto &input_hex=observation.at(J::json_pointer("/data/input_hex"));
      const auto &candidate=lookup("candidates",item.at("candidate"));
      if(!input_hex.is_string()||input_hex.get<std::string>()!=candidate.at("hex").get<std::string>())
        throw std::runtime_error("Accepted-input observation does not contain the exact candidate bytes");
      item["receipt"]["input_hex"]=input_hex;
      item["receipt"]["candidate_sha256"]=item.at("candidate_sha256");
      item["receipt"]["scope"]="exact candidate bytes and acceptance result in this recorded execution only";
    }
    item["state"]=matches?"observation_matches_prediction":"observation_contradicts_prediction";
    lookup("hypotheses",item.at("hypothesis"))["state"]=item.at("state");
  } else if(op=="prove_observation") {
    keys(r,{"experiment","answer"});auto &experiment=lookup("experiments",r.at("experiment"));
    if(!experiment.contains("proof_kind")||experiment.value("state",std::string())!="observation_matches_prediction"||!experiment.contains("receipt"))
      throw std::runtime_error("A matching question-bound runtime observation is required");
    const auto kind=experiment.at("proof_kind").get<std::string>(),answer=string(r,"answer",512);
    if(kind=="observed_output") {
      const auto &actual=experiment.at("receipt").at("actual");
      if(!actual.is_string()||actual.get<std::string>()!=answer)throw std::runtime_error("Observed-output answer differs from the pinned runtime value");
    } else {
      const auto &candidate=lookup("candidates",experiment.at("candidate"));
      const std::vector<unsigned char> bytes(answer.begin(),answer.end());
      if(candidate.at("hex").get<std::string>()!=reasoning_hex(bytes)||
         experiment.at("receipt").value("input_hex",std::string())!=candidate.at("hex").get<std::string>()||
         experiment.at("receipt").at("actual")!=true)
        throw std::runtime_error("Accepted-input answer differs from the exact experimented candidate bytes");
    }
    signed_proof({{"kind",kind},{"fact_index",experiment.at("fact_index")},{"question",experiment.at("question")},
      {"obligation","o"+std::to_string(experiment.at("fact_index").get<std::size_t>())+(kind=="accepted_input"?"_acceptance":"_output")},
      {"answer",answer},{"experiment",experiment.at("id")},{"sources",experiment.at("sources")},
      {"runtime_observation",experiment.at("receipt")},{"state","verified"},
      {"limitations",J::array({kind=="accepted_input"?"Acceptance is established only for the exact recorded input, artifact, and execution session.":"Output is established only for the exact recorded execution session; acceptance and independent grading are separate."})}});
  } else if(op=="recover_initialized_x86") {
    keys(r,{"source","fact_index"});
    const auto index=r.at("fact_index").get<std::size_t>();
    if(index>=inv.at("required_facts").size())throw std::runtime_error("Recovery fact_index outside investigation");
    const auto pinned=sources(J::array({r.at("source")}));
    auto recovery=recover_initialized_x86_blob(full_source_text(pinned[0]));
    recovery["sources"]=pinned;recovery["fact_index"]=index;recovery["question"]=inv.at("required_facts")[index];
    recovery["obligation"]="o"+std::to_string(index)+"_candidate_validation";
    auto &saved=append("recoveries",std::move(recovery));
    signed_proof({{"kind","recovered_candidate"},{"fact_index",index},{"question",inv.at("required_facts")[index]},
      {"obligation",saved.at("obligation")},{"answer",saved.at("answer")},{"recovery",saved.at("id")},
      {"sources",saved.at("sources")},{"state","verified"},
      {"limitations",J::array({"Candidate reconstruction only; transformation semantics, runtime output, input acceptance, and independent grading require their own proof types."})}});
  } else if(op=="verify_transformation") {
    keys(r,{"recovery","control_flow","entry_flow"});auto &recovery=lookup("recoveries",r.at("recovery"));
    const auto control=sources(J::array({r.at("control_flow")})),entry=sources(J::array({r.at("entry_flow")}));
    for(const auto &pin:J::array({recovery.at("sources").at(0),entry.at(0),control.at(0)})) {
      const auto page=harness_evidence_page(store,inv,{{"id",pin.at("evidence_id")},{"pointer",pin.at("pointer")},{"max_bytes",64}});
      if(page.at("artifact_sha256")!=inv.at("artifact_sha256"))throw std::runtime_error("Transformation views must belong to the primary artifact");
    }
    const auto source_native=full_source_value(recovery.at("sources").at(0)),control_native=full_source_value(control.at(0));
    if(source_native.value("backend",std::string())!="ghidra"||source_native.value("operation",std::string())!="decompile"||
       !source_native.contains("function")||!source_native.at("function").contains("entry"))
      throw std::runtime_error("Transformation proof requires Ghidra function decompilation evidence");
    const auto function_entry=source_native.at("function").at("entry").get<std::string>();
    const auto entry_native=full_source_value(entry.at(0));
    const auto entry_pointer=entry.at(0).at("pointer").get<std::string>();
    const bool call_reference=entry_native.value("backend",std::string())=="ghidra"&&entry_native.value("operation",std::string())=="calls"&&
      std::regex_match(entry_pointer,std::regex(R"(/calls/[0-9]+/to)"));
    const bool entry_reference=entry_pointer=="/program/entry"&&entry_native.value("operation",std::string())=="inventory";
    if(!call_reference&&!entry_reference)throw std::runtime_error("Entry provenance is not a native call or entry-point reference");
    if(!pinned_value(entry.at(0)).is_string()||pinned_value(entry.at(0)).get<std::string>()!=function_entry)
      throw std::runtime_error("Entry/call reference does not select the recovered function");
    if(control_native.value("producer",std::string())!="XAIR/XAIR_CFG"||control_native.value("operation",std::string())!="cfg"||
       control_native.value("artifact_sha256",std::string())!=inv.at("artifact_sha256").get<std::string>())
      throw std::runtime_error("Transformation proof requires same-artifact XAIR CFG evidence");
    J selected_function;const auto &functions=control_native.at("functions");
    auto select_function=[&](const J &function) {
      if(function.at("location").at("address")==function_entry)selected_function=function;
    };
    if(functions.is_array())for(const auto &function:functions)select_function(function);else select_function(functions);
    if(selected_function.is_null()||selected_function.value("semantic_completeness",std::string())!="exact")
      throw std::runtime_error("XAIR CFG does not contain an exact selected function");
    std::set<unsigned> block_ids,reachable_ids,exact_ids;
    for(const auto &id:selected_function.at("blocks"))block_ids.insert(id.get<unsigned>());
    for(const auto &analysis:control_native.at("function_analysis"))
      if(analysis.value("function",unsigned(-1))==selected_function.at("id").get<unsigned>()&&analysis.value("reachable",false))reachable_ids.insert(analysis.at("node").get<unsigned>());
    for(const auto &block:control_native.at("blocks"))
      if(block.value("semantic_completeness",std::string())=="exact")exact_ids.insert(block.at("id").get<unsigned>());
    if(block_ids.empty()||!std::includes(reachable_ids.begin(),reachable_ids.end(),block_ids.begin(),block_ids.end())||
       !std::includes(exact_ids.begin(),exact_ids.end(),block_ids.begin(),block_ids.end())||
       control_native.value("indirect_flow_candidates",J::array()).empty())
      throw std::runtime_error("XAIR CFG does not prove reachable exact initializer flow to an indirect transfer");
    const auto source=full_source_text(recovery.at("sources").at(0));
    if(!std::regex_search(source,std::regex("\\(\\*\\(code \\*\\)&local_"+hex_address(recovery.at("local_base").get<unsigned>()).substr(2)+"\\)\\(\\);")))
      throw std::runtime_error("Ghidra decompilation does not transfer control to the initialized local blob");
    const auto checked=recover_initialized_x86_blob(source);
    const auto initializer=recovery_artifact_initializer(store,inv,function_entry,checked);
    if(checked.at("input_sha256")!=recovery.at("input_sha256")||checked.at("decoded_sha256")!=recovery.at("decoded_sha256")||
       checked.at("answer")!=recovery.at("answer")||!checked.value("native_control_flow_verified",false)||!checked.value("value_to_sink_verified",false))
      throw std::runtime_error("Transformation no longer reproduces with instruction, control-flow, and sink validation");
    J proof_sources=recovery.at("sources");proof_sources.push_back(control.at(0));proof_sources.push_back(entry.at(0));
    signed_proof({{"kind","verified_transformation"},{"checker_version",2},{"fact_index",recovery.at("fact_index")},{"question",recovery.at("question")},
      {"obligation","o"+std::to_string(recovery.at("fact_index").get<std::size_t>())+"_output"},
      {"answer",recovery.at("answer")},{"recovery",recovery.at("id")},{"sources",proof_sources},
      {"validation",{{"decoder_engine","XAIR/xair_x86_decode_instruction"},{"function_cfg_engine","XAIR/XAIR_CFG"},
        {"initializer",initializer},{"decoder_stages",checked.at("stages").size()},{"value_sink",checked.at("strings").at(0).at("sink")}}},
      {"state","verified"},{"limitations",J::array({"Conditional on reaching the initializer and final sink: native stores, decoder transformations and call-argument bytes are checked. Environment-dependent resolver termination and the indirect callee behavior are not established. No observed output, accepted input, or independent challenge grading is claimed."})}});
  } else if(op=="solution") {
    keys(r,{"proof","answer"});
    auto &proof=lookup("proofs",r.at("proof"));
    const auto answer=string(r,"answer",512);
    if(!verification_record_intact(proof)||proof.value("state",std::string())!="verified"||answer!=proof.at("answer").get<std::string>())
      throw std::runtime_error("Selected answer does not match the intact native proof");
    const auto index=proof.at("fact_index").get<std::size_t>();
    for(const auto &old:state.at("solutions"))if(old.at("fact_index")==index&&old.at("answer")!=answer)
      throw std::runtime_error("Contradictory answer already selected for this question");
    append("solutions",{{"proof",proof.at("id")},{"answer",answer},{"sources",proof.value("sources",J::array())},
      {"fact_index",index},{"question",proof.at("question")},{"obligation",proof.at("obligation")},
      {"state","question_answer_selected"},{"proof_kind",proof.at("kind")}});
    const auto kind=proof.at("kind").get<std::string>();
    for(auto &obligation:state.at("obligations"))if(obligation.at("fact_index")==index) {
      const auto role=obligation.at("role").get<std::string>();bool resolves=false;
      if(kind=="recovered_candidate")resolves=role=="candidate_validation";
      else if(kind=="verified_transformation")resolves=role=="candidate_validation"||role=="output";
      else if(kind=="observed_output")resolves=role=="output";
      else if(kind=="accepted_input")resolves=role=="input"||role=="acceptance"||role=="candidate_validation";
      if(resolves)obligation["state"]="resolved_by_"+kind;
    }
  } else throw std::runtime_error("Unknown reasoning operation");
  state["revision"]=state.at("revision").get<unsigned>()+1;
  auto projected=inv;projected["reasoning"]=state;
  const auto matched=verified_requirements(projected);
  state["requirements_verified"]=projected.contains("proof_requirements")&&!inv.at("required_facts").empty()&&
    matched.size()==inv.at("required_facts").size();
  state["verified_solve"]=state.at("requirements_verified").get<bool>()&&
    std::any_of(matched.begin(),matched.end(),[](const J &proof){
      return proof.at("kind")=="independently_graded_challenge_solve";
    });
  if(state.dump().size()>49152)throw std::runtime_error("Reasoning ledger exceeds 48 KiB");
  return state;
}
}
