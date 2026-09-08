#include "indago/airece.hpp"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>
#include <thread>
#include <atomic>

// A deterministic ELF64 image with the same code as control-flow.pe64.
indago::fs::path make_elf() {
    std::vector<unsigned char> bytes(0x1000, 0);
    auto put = [&](std::size_t at, std::uint64_t value, unsigned count) {
        for (unsigned i = 0; i < count; ++i) bytes[at + i] = static_cast<unsigned char>(value >> (8 * i));
    };
    bytes[0]=0x7f; bytes[1]='E'; bytes[2]='L'; bytes[3]='F'; bytes[4]=2; bytes[5]=1; bytes[6]=1;
    put(16,2,2); put(18,62,2); put(20,1,4); put(24,0x401000,8); put(32,64,8);
    put(52,64,2); put(54,56,2); put(56,1,2);
    const std::vector<unsigned char> code{0x48,0x39,0xd8,0x74,0x02,0x75,0x00,0x0f,0x94,0xc0,0x48,0x0f,0x45,0xc3,0xe8,0,0,0,0,0xff,0xd0,0xeb,0,0xc3};
    put(64,1,4); put(68,5,4); put(72,0x1000,8); put(80,0x401000,8); put(88,0x401000,8);
    put(96,code.size(),8); put(104,code.size(),8); put(112,0x1000,8);
    bytes.insert(bytes.end(),code.begin(),code.end());
    auto path = indago::fs::temp_directory_path() / ("indago-fixture-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".elf");
    std::ofstream file(path, std::ios::binary); file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return path;
}

int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--version") { std::cout << "fixture-worker 1.0\n"; return 0; }
    if (argc > 1 && std::string(argv[1]) == "fn") { std::cout << "invalid JSON"; return 0; }
    if (argc > 1 && std::string(argv[1]) == "--child") {
        if (argc > 2 && std::string(argv[2]) == "sleep") {
            std::this_thread::sleep_for(std::chrono::seconds(10)); return 0;
        }
        if (argc > 2 && std::string(argv[2]) == "flood") {
            std::cout << std::string(100000, 'x'); return 3;
        }
        for (int i = 2; i < argc; ++i) std::cout << argv[i] << '\n';
        return 0;
    }
    auto require = [](bool ok, const char* message) { if (!ok) throw std::runtime_error(message); };
    try {
        const auto self = indago::fs::absolute(argv[0]);
        indago::NativeProcessOptions options;
        options.wall_time_ms = 5000;
        auto result = indago::run_native_process(self, {"--child", "space argument", "quote\"slash\\", "$(literal)&"}, options);
        require(result.exit_code == 0 && result.output == "space argument\r\nquote\"slash\\\r\n$(literal)&\r\n"
            || result.exit_code == 0 && result.output == "space argument\nquote\"slash\\\n$(literal)&\n", "Literal argument roundtrip failed");
        options.max_output_bytes = 1024;
        result = indago::run_native_process(self, {"--child", "flood"}, options);
        require(result.exit_code == 3 && result.truncated && result.output.size() == 1024, "Output bounds or exit preservation failed");
        options.wall_time_ms = 25;
        result = indago::run_native_process(self, {"--child", "sleep"}, options);
        require(result.timed_out, "Timeout failed");
        options.wall_time_ms = 5000;
        options.cancel_file = indago::fs::temp_directory_path() / ("indago-cancel-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::thread canceller([path = options.cancel_file] { std::this_thread::sleep_for(std::chrono::milliseconds(30)); std::ofstream(path) << "cancel"; });
        result = indago::run_native_process(self, {"--child", "sleep"}, options);
        canceller.join(); indago::fs::remove(options.cancel_file);
        require(result.cancelled, "Cancellation failed");
        options.cancel_file.clear();
        std::atomic<bool> cancel_callback{false};
        options.should_cancel = [&] { return cancel_callback.load(); };
        std::jthread callback_canceller([&] { std::this_thread::sleep_for(std::chrono::milliseconds(30)); cancel_callback = true; });
        result = indago::run_native_process(self, {"--child", "sleep"}, options);
        callback_canceller.join();
        require(result.cancelled, "Callback cancellation failed");
        options.should_cancel = {};
        indago::TargetRecord fake_target;
        indago::AireceOptions fake; fake.executable=self; fake.operation="function"; fake.view="json";
        auto malformed = indago::run_airece(fake_target,fake);
        require(malformed.status == "failed" && nlohmann::json::parse(malformed.json).contains("protocol_error"), "Invalid native JSON accepted");
        for (const auto& [key,value] : std::vector<std::pair<std::string,std::string>>{{"max-wall-time-ms","120001"},{"max-functions","4097"},{"max-memory-bytes","0"},{"made-up","1"},{"view","json"}}) {
            fake.arguments={{key,value}}; bool rejected=false;
            try { (void)indago::run_airece(fake_target,fake); } catch (const std::runtime_error&) { rejected=true; }
            require(rejected,"Unbounded or unknown argument accepted");
        }
        if (argc > 1) {
            indago::TargetRecord target; target.id = "fixture"; target.object_path = indago::fs::absolute(argv[1]);
            indago::AireceOptions request; request.operation = "inspect";
            request.arguments["max-memory-bytes"]="2147483648";
            auto answer = indago::run_airece(target, request);
            auto doc = nlohmann::json::parse(answer.json);
            require(answer.exit_code == 0 || answer.exit_code == 3, "Real AIRECE inspect failed");
            require(!doc.at("native_output").get<std::string>().empty(), "Missing native output");
            require(doc["native"]["format"] == "pe" && doc["provenance"]["executable_sha256"].get<std::string>().size() == 64,"Missing structured inventory or provenance");
            request.max_output_bytes=1024;
            auto bounded=indago::run_airece(target,request);
            require(bounded.json.size() <= 1024 && nlohmann::json::parse(bounded.json)["truncated"] == true,"Final JSON envelope exceeded byte budget");
            request.max_output_bytes=1024*1024;
            request.operation = "function"; request.address = "0x140001000"; request.view = "agent";
            answer = indago::run_airece(target, request); doc = nlohmann::json::parse(answer.json);
            require(doc.contains("native") && doc["native"]["schema"] == "airece.agent-function.v1", "Native JSON and source evidence missing");
            const auto elf = make_elf();
            for (const auto& [path, address, callee, statement] : std::vector<std::tuple<indago::fs::path,std::string,std::string,std::string>>{
                {target.object_path,"0x140001000","0x140001013","F140001000:S:N0:branch"},
                {elf,"0x401000","0x401013","F401000:S:N0:branch"}}) {
                target.object_path = path;
                for (const auto& operation : {"inspect","functions","calls","xrefs","slice","path","flow","taint","evidence"}) {
                    request = {}; request.operation = operation;
                    if (request.operation == "xrefs" || request.operation == "slice" || request.operation == "taint") request.address = address;
                    if (request.operation == "evidence") request.address = statement;
                    if (request.operation == "path") request.arguments = {{"from",address},{"to",callee}};
                    if (request.operation == "flow") request.arguments = {{"source","value(v0)"},{"target","reach@" + callee}};
                    answer = indago::run_airece(target,request);
                    if (answer.exit_code != 0 && answer.exit_code != 3) throw std::runtime_error(std::string(operation) + " failed: " + answer.json);
                    doc = nlohmann::json::parse(answer.json);
                    require(doc["native_exit_code"] == answer.exit_code, "Native partial verdict changed");
                    if (request.operation == "flow") require(doc["native"]["verdict"] == "may-flow", "Native flow verdict lost");
                }
                for (const auto& view : {"compact","agent","pseudocode","disassembly","json"}) {
                    request = {}; request.operation = "function"; request.address = address; request.view = view;
                    answer = indago::run_airece(target,request);
                    require(answer.exit_code == 0 || answer.exit_code == 3, "Function view failed");
                    doc = nlohmann::json::parse(answer.json);
                    require(!doc["native_output"].get<std::string>().empty(), "Function view empty");
                }
            }
            indago::fs::remove(elf);
        }
        std::cout << "AIRECE process bounds, arguments, timeout, cancellation and native payload tests passed\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
