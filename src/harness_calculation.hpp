#pragma once
#include "harness_artifact_read.hpp"
#include <cstdint>
#include <map>

namespace indago {
// A finite integer calculator, not a CPU emulator or a target execution tool.
// Expressions have no host calls, memory writes, jumps, or unbounded loops.
class InvestigationCalculation {
  using J=wb::J;
  std::vector<std::uint8_t> input;
  std::map<std::string,std::uint32_t> vars;
  std::size_t remaining=100000;
  static bool name(const std::string &s) {
    if(s.empty()||s.size()>32)return false;
    for(std::size_t i=0;i<s.size();++i) {
      const auto c=s[i];
      if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(i&&c>='0'&&c<='9')||(i&&c=='_')))return false;
    }
    return s!="i"&&s!="n";
  }
  static std::uint32_t integer(const J &value) {
    if(!value.is_number_integer()||value.get<std::int64_t>()<0||value.get<std::uint64_t>()>UINT32_MAX)
      throw std::runtime_error("Calculation constants must be unsigned 32-bit integers");
    return value.get<std::uint32_t>();
  }
  std::uint32_t eval(const J &e,unsigned depth=0) {
    if(depth>16||remaining==0)throw std::runtime_error("Calculation expression budget exhausted");
    --remaining;
    if(e.is_number_integer())return integer(e);
    if(e.is_string()) {
      const auto key=e.get<std::string>();const auto found=vars.find(key);
      if(found==vars.end())throw std::runtime_error("Unknown calculation variable: "+key);
      return found->second;
    }
    if(!e.is_array()||e.empty()||!e[0].is_string())throw std::runtime_error("Expected a calculation expression array");
    const auto op=e[0].get<std::string>();
    if(op=="select") {
      if(e.size()!=4)throw std::runtime_error("select requires condition, true expression, false expression");
      return eval(e[eval(e[1],depth+1)?2:3],depth+1);
    }
    if(op=="byte"||op=="not") {
      if(e.size()!=2)throw std::runtime_error("Unary calculation expression requires one operand");
      const auto a=eval(e[1],depth+1);
      if(op=="not")return ~a;
      if(a>=input.size())throw std::runtime_error("Calculation byte index outside the source slice");
      return input[a];
    }
    if(e.size()!=3)throw std::runtime_error("Binary calculation expression requires two operands");
    const auto a=eval(e[1],depth+1),b=eval(e[2],depth+1);
    if(op=="add")return a+b;
    if(op=="sub")return a-b;
    if(op=="mul")return static_cast<std::uint32_t>(static_cast<std::uint64_t>(a)*b);
    if(op=="xor")return a^b;
    if(op=="and")return a&b;
    if(op=="or")return a|b;
    if(op=="eq")return a==b;
    if(op=="lt")return a<b;
    if(op=="div"||op=="mod") {
      if(!b)throw std::runtime_error("Calculation division by zero");
      return op=="div"?a/b:a%b;
    }
    if(op=="shl"||op=="shr") {
      if(b>=32)throw std::runtime_error("Calculation shift must be below 32");
      return op=="shl"?a<<b:a>>b;
    }
    if(op=="rol8"||op=="ror8") {
      const auto v=a&255u,n=b%8u;
      if(!n)return v;
      return op=="rol8"?((v<<n)|(v>>(8-n)))&255u:((v>>n)|(v<<(8-n)))&255u;
    }
    throw std::runtime_error("Unsupported calculation operator: "+op);
  }
public:
  wb::J run(const wb::J &r,const std::string &hex) {
    using namespace wb;
    if(r.dump().size()>16384)throw std::runtime_error("Calculation program exceeds 16 KiB");
    if(hex.empty()||hex.size()>2048||hex.size()%2||hex.find_first_not_of("0123456789abcdef")!=hex.npos)
      throw std::runtime_error("Calculation requires bounded native hex bytes");
    for(std::size_t i=0;i<hex.size();i+=2)input.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i,2),nullptr,16)));
    const auto iterations=bound(r,"iterations",input.size(),256);
    if(!iterations)throw std::runtime_error("Calculation requires at least one iteration");
    const auto initial=r.value("variables",J::object());
    const auto body=r.value("body",J::array());
    if(!initial.is_object()||initial.size()>16||!body.is_array()||body.size()>32)
      throw std::runtime_error("Calculation permits 16 variables and 32 assignments");
    std::set<std::string> names;
    for(auto it=initial.begin();it!=initial.end();++it) {
      if(!name(it.key()))throw std::runtime_error("Invalid or reserved calculation variable");
      names.insert(it.key());vars[it.key()]=integer(it.value());
    }
    for(const auto &statement:body) {
      keys(statement,{"set","value"});const auto key=statement.at("set").get<std::string>();
      if(!name(key))throw std::runtime_error("Invalid or reserved calculation variable");
      statement.at("value");names.insert(key);
    }
    if(names.size()>16)throw std::runtime_error("Calculation variable budget exhausted");
    vars["n"]=static_cast<std::uint32_t>(input.size());
    std::string output,ascii;const char *digits="0123456789abcdef";bool printable=true;
    for(std::size_t i=0;i<iterations;++i) {
      vars["i"]=static_cast<std::uint32_t>(i);
      for(const auto &statement:body)vars[statement.at("set").get<std::string>()]=eval(statement.at("value"));
      const auto byte=eval(r.at("emit"));
      if(byte>255)throw std::runtime_error("Calculation output must be a byte; explicitly mask wider results");
      output+=digits[byte>>4];output+=digits[byte&15];ascii+=static_cast<char>(byte);
      printable=printable&&byte>=32&&byte<=126;
    }
    vars.erase("i");vars.erase("n");
    J result{{"hex",output},{"iterations",iterations},{"variables",vars},{"expression_steps",100000-remaining}};
    if(printable)result["ascii"]=ascii;
    return result;
  }
};
inline wb::J harness_calculation(const ProjectStore &store,const wb::J &component,const wb::J &request) {
  using namespace wb;
  keys(request,{"project","source","iterations","variables","body","emit"});
  auto source_request=request.at("source");
  // Component selection is performed once by the scoped reader. Nested sources
  // cannot change that component or add a host path.
  keys(source_request,{"offset","address","max_bytes","raw_sha256"});
  source_request["project"]=request.at("project");
  const auto source=harness_artifact_page(store,component,source_request);
  InvestigationCalculation calculator;auto result=calculator.run(request,source.at("hex").get<std::string>());
  auto descriptor=source;descriptor.erase("hex");descriptor.erase("trust");
  result["schema"]="indago.calculation.v1";result["status"]="evaluated";
  result["source"]=descriptor;result["artifact_sha256"]=source.at("artifact_sha256");
  result["program_sha256"]=sha256_text(request.dump());
  result["trust"]="Exact finite calculation under model-declared expressions, not proof of target semantics, accepted input, or runtime behavior";
  result["source_verified"]=true;result["pointer"]="/calculation";
  result["raw_sha256"]=sha256_text(result.dump());
  return result;
}
} // namespace indago
