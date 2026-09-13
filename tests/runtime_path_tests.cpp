#include "indago/runtime.hpp"
#include <iostream>
int main() {
  using J = indago::RuntimeJson;
  J code{{"address", "0x1000"},
         {"hex", "83ff0774058d4703eb05b82a00000083f82a75029090c3"},
         {"size", 23}};
  J capture{
      {"id", "fixture_capture"},
      {"sha256", "fixture"},
      {"data",
       {{"location", {{"runtime_address", "0x1000"}}},
        {"instruction_bytes", code},
        {"code_bytes", code},
        {"registers",
         {{"arch", "x64"},
          {"values", {{"rdi", "0x7"}, {"rax", "0x0"}, {"eflags", "0x0"}}}}},
        {"memory", J::array()}}}};
  try {
    auto result =
        indago::runtime_symbolic(capture, {{"path", {"0x1000", "0x100a"}},
                                           {"symbolic_registers", {"rdi"}},
                                           {"timeout_ms", 5000}});
    if (result.at("results").empty() ||
        result["results"][0]["selected_path_conditions"].size() != 1)
      throw std::runtime_error(result.dump());
    auto branches = result["results"][0]["branches"];
    if (branches[0]["native_verdict"] != "unsat" ||
        branches[1]["native_verdict"] != "sat")
      throw std::runtime_error(result.dump());
    capture["data"]["capture_group_id"] = "same_stop";
    capture["data"]["code_bytes"] = {
        {"address", "0x1000"}, {"hex", "83ff077405"}, {"size", 5}};
    capture["data"]["code_regions"] =
        J::array({{{"capture_group_id", "same_stop"},
                   {"code_bytes",
                    {{"address", "0x100a"},
                     {"hex", "b82a00000083f82a75029090c3"},
                     {"size", 13}}}}});
    auto regions =
        indago::runtime_symbolic(capture, {{"path", {"0x1000", "0x100a"}},
                                           {"symbolic_registers", {"rdi"}},
                                           {"timeout_ms", 5000}});
    if (regions["results"][0]["branches"][0]["native_verdict"] != "unsat" ||
        regions["results"][0]["branches"][1]["native_verdict"] != "sat")
      throw std::runtime_error(regions.dump());
    J input_code{{"address", "0x1000"},
                 {"hex", "803f417505807f0142750290c3"},
                 {"size", 12}};
    J input_capture{
        {"id", "input_capture"},
        {"sha256", "fixture"},
        {"data",
         {{"location", {{"runtime_address", "0x1000"}}},
          {"instruction_bytes", input_code},
          {"code_bytes", input_code},
          {"registers",
           {{"arch", "x64"},
            {"values", {{"rdi", "0x2000"}, {"eflags", "0x0"}}}}},
          {"memory", J::array({{{"address", "0x2000"}, {"hex", "6162"}}})}}}};
    J solve{
        {"path", {"0x1000", "0x1005"}},
        {"timeout_ms", 5000},
        {"input_ranges",
         J::array({{{"source", "stdin"}, {"address", "0x2000"}, {"size", 2}}})},
        {"byte_constraints",
         J::array({{{"address", "0x2000"}, {"allowed_hex", "41"}},
                   {{"address", "0x2001"}, {"allowed_hex", "4243"}}})}};
    const auto inputs = indago::runtime_symbolic(input_capture, solve);
    if (inputs.at("status") != "completed" || inputs.at("results").empty())
      throw std::runtime_error(inputs.dump());
    const auto alternatives = inputs["results"][0]["branches"];
    if (alternatives[0]["input_candidates"][0]["hex"] != "4143" ||
        alternatives[1]["input_candidates"][0]["hex"] != "4142")
      throw std::runtime_error(inputs.dump());
    input_capture["data"]["registers"]["arch"] = "x86";
    input_capture["data"]["registers"]["values"] = {{"edi", "0x2000"},
                                                    {"eflags", "0x0"}};
    const auto x86inputs = indago::runtime_symbolic(input_capture, solve);
    if (x86inputs["results"][0]["branches"][1]["input_candidates"][0]["hex"] !=
        "4142")
      throw std::runtime_error(x86inputs.dump());
    solve["byte_constraints"][0]["allowed_hex"] = "44";
    const auto impossible = indago::runtime_symbolic(input_capture, solve);
    if (!impossible.at("results").empty())
      throw std::runtime_error("predecessor constraint was ignored");
    J checksum_code{{"address","0x1000"},{"hex","31c031c902040f48ffc14883f90272f43c837501c3c3"}};
    input_capture["data"]["registers"]={{"arch","x64"},{"values",{{"rdi","0x2000"},{"rax","0x0"},{"rcx","0x0"},{"eflags","0x0"}}}};
    input_capture["data"]["instruction_bytes"]=checksum_code;input_capture["data"]["code_bytes"]=checksum_code;
    solve["path"]={"0x1000","0x1004","0x1010"};solve["byte_constraints"][0]["allowed_hex"]="41";
    const auto checksum=indago::runtime_symbolic(input_capture,solve);
    if(checksum.at("status")!="completed"||checksum["results"][0]["branches"][1]["input_candidates"][0]["hex"]!="4142")throw std::runtime_error(checksum.dump());
    J payload{{"api","memcmp"},{"input_side","right"},{"input_hex","30"},{"expected_hex","42"},{"return_value",1},{"address","0x3000"},{"input",{{"input_id","read0"},{"offset",0}}}};
    J compared{{"id","compare0"},{"data",{{"native",{{"payload",payload}}}}}};
    J delivered{{"id","delivery0"},{"data",{{"native",{{"payload",{{"source","stdin"},{"input_id","read0"},{"complete",true},{"offset",0},{"hex","30"}}}}}}}};
    J session{{"request",{{"input_hex","30"}}}};
    auto observed=indago::runtime_solve_input(compared,delivered,session);
    if(observed.at("status")!="completed"||observed["results"][0]["branches"][0]["input_candidates"][0]["hex"]!="42")throw std::runtime_error(observed.dump());
    for(int fault=0;fault<3;++fault){auto bad=compared;auto wrong=session;
      if(fault==0)bad["data"]["native"]["payload"]["return_value"]=-1;
      if(fault==1)bad["data"]["native"]["payload"]["input"]["input_id"]="foreign";
      if(fault==2)wrong["request"]["input_hex"]="31";
      bool rejected=false;try{indago::runtime_solve_input(bad,delivered,wrong);}catch(const std::exception&){rejected=true;}
      if(!rejected)throw std::runtime_error("invalid observed input provenance accepted");
    }
    std::cout << "native selected path, loop checksum and bounded input candidates passed\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
