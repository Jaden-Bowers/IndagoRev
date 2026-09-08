#include "indago/runtime.hpp"
#include <iostream>
int main() {
  using J=indago::RuntimeJson;
  J code{{"address","0x1000"},{"hex","83ff0774058d4703eb05b82a00000083f82a75029090c3"},{"size",23}};
  J capture{{"id","fixture_capture"},{"sha256","fixture"},{"data",{{"location",{{"runtime_address","0x1000"}}},{"instruction_bytes",code},{"code_bytes",code},{"registers",{{"arch","x64"},{"values",{{"rdi","0x7"},{"rax","0x0"},{"eflags","0x0"}}}}},{"memory",J::array()}}}};
  try {
    auto result=indago::runtime_symbolic(capture,{{"path",{"0x1000","0x100a"}},{"symbolic_registers",{"rdi"}},{"timeout_ms",5000}});
    if(result.at("results").empty()||result["results"][0]["selected_path_conditions"].size()!=1)throw std::runtime_error(result.dump());
    auto branches=result["results"][0]["branches"];
    if(branches[0]["native_verdict"]!="unsat"||branches[1]["native_verdict"]!="sat")throw std::runtime_error(result.dump());
    capture["data"]["capture_group_id"]="same_stop";
    capture["data"]["code_bytes"]={{"address","0x1000"},{"hex","83ff077405"},{"size",5}};
    capture["data"]["code_regions"]=J::array({{{"capture_group_id","same_stop"},{"code_bytes",{{"address","0x100a"},{"hex","b82a00000083f82a75029090c3"},{"size",13}}}}});
    auto regions=indago::runtime_symbolic(capture,{{"path",{"0x1000","0x100a"}},{"symbolic_registers",{"rdi"}},{"timeout_ms",5000}});
    if(regions["results"][0]["branches"][0]["native_verdict"]!="unsat"||regions["results"][0]["branches"][1]["native_verdict"]!="sat")throw std::runtime_error(regions.dump());
    std::cout<<"native selected path passed\n";
    return 0;
  }catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 1;}
}
