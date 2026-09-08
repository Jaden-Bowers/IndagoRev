#include "indago/xair.hpp"
#include "indago/sym.hpp"
#include <nlohmann/json.hpp>
#include <iostream>
#include <sstream>
#include <stdexcept>

#ifdef INDAGO_STANDALONE_TEST
namespace indago { std::string hex_address(std::uint64_t value) { std::ostringstream out; out << "0x" << std::hex << value; return out.str(); } }
#endif
static void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
int main(int argc, char** argv) {
    using namespace indago; using Json = nlohmann::json;
    try {
        TargetRecord target; target.object_path = argc > 1 ? argv[1] : "xair/XAIR/tests/corpus/phase3/control-flow.pe64";
        target.size = fs::file_size(target.object_path); target.sha256 = "test-artifact";
        XairQuery query; query.function = 0x140001000;
        auto result = query_xair(target, query); auto cfg = Json::parse(result.json);
        require(result.exit_code == 0 || result.exit_code == 3, "CFG failed");
        require(!cfg["edges"].empty() && !cfg["function_analysis"].empty(), "CFG graph algorithms absent");
        require(cfg["function_analysis"][0].contains("immediate_postdominator"), "postdominators missing");
        query.operation = "semantic"; result = query_xair(target, query); auto sem = Json::parse(result.json);
        require(!sem["instructions"].empty() && !sem["ssa_values"].empty(), "semantic IR absent");
        require(sem["instructions"][0].contains("source_locations"), "source mappings missing");
        query.max_items = 2; result = query_xair(target, query); auto limited = Json::parse(result.json);
        require(result.exit_code == 3 && limited["truncated"] == true, "item bound ignored");
        query.max_items = 10000; query.max_output_bytes = 2048; result = query_xair(target, query);
        require(result.json.size() <= 2048 && result.exit_code == 3, "byte bound ignored");
        std::atomic_bool cancel{true}; query.cancellation = &cancel; result = query_xair(target, query);
        require(result.status == "cancelled", "cancellation ignored");
        if (find_airece()) {
            for (const auto* operation : {"solve_branch", "source_to_sink", "path_condition", "taint", "symbolic_slice"}) {
                SymOptions options; options.operation = operation; options.address = "0x140001000";
                options.function = "0x140001000"; options.source = "value(v0)"; options.sink = "reach@0x140001013";
                std::cout << "testing " << operation << std::endl;
                result = query_sym(target, options); auto sym = Json::parse(result.json);
                require(result.exit_code == 0 || result.exit_code == 3, "symbolic operation failed");
                std::cout << operation << " " << result.status;
                if (sym.contains("branch_findings")) { require(!sym["branch_findings"].empty(), "branch native verdict missing"); std::cout << " " << sym["branch_findings"].dump(); }
                if (sym.contains("symbolic_findings")) { require(!sym["symbolic_findings"].empty(), "slice findings join missing"); std::cout << " " << sym["symbolic_findings"].dump(); }
                if (sym["native"].contains("native") && sym["native"]["native"].contains("verdict")) std::cout << " " << sym["native"]["native"]["verdict"];
                std::cout << '\n';
            }
        }
        std::cout << "native XAIR queries verified\n";
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
