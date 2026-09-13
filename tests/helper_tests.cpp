#include "../src/analysis_helper.hpp"
#include "../src/harness_workbench.hpp"
#include "indago/harness.hpp"
#include <cstdlib>
#include <iostream>
#include <thread>
using namespace indago;
using J = nlohmann::json;
void check(bool value, const char *message) {
  if (!value)
    throw std::runtime_error(message);
}
template <class F> void rejects(F f, const char *message) {
  bool rejected = false;
  try {
    f();
  } catch (...) {
    rejected = true;
  }
  check(rejected, message);
}
int main() {
  const auto root = fs::temp_directory_path() / make_id("helper_checks");
  try {
    StaticService service(root);
    auto &store = service.store();
    store.create_project("helpers");
    atomic_write(root / "fixture.bin", "ABCD");
    auto target = store.import_target("helpers", root / "fixture.bin");
    J create{
        {"project", "helpers"},
        {"objective", "Test isolated analysis helpers"},
        {"required_facts", {"helper isolation"}},
        {"owner", {{"mode", "external"}, {"name", "offline helper fixture"}}},
        {"workbench_mutations", true},
        {"analysis_helpers", true},
        {"budget",
         {{"max_actions", 32},
          {"wall_ms", 540000},
          {"output_bytes", 2097152}}}};
    auto inv = harness_action(service, "create", create);
    const auto id = inv.at("id"), token = inv.at("owner_token");
    auto show = [&] {
      return harness_action(service, "show",
                            {{"project", "helpers"}, {"id", id}});
    };
    auto owned = [&](const char *operation, J r) {
      r["project"] = "helpers";
      r["id"] = id;
      r["owner_token"] = token;
      r["expected_revision"] = show().at("revision");
      return harness_action(service, operation, r);
    };
    J args{{"language", "c17"},
           {"source_code", "#include <stdio.h>\nint main(void){int "
                           "c;while((c=getchar())!=EOF)putchar(c);return 0;}"},
           {"input", {{"offset", 0}, {"max_bytes", 4}}},
           {"validation",
            {{"kind", "artifact_bytes"},
             {"expected", {{"offset", 0}, {"max_bytes", 4}}}}}};
    auto request = [&](const J &a) {
      return J{{"backend", "workbench"},
               {"operation", "helper.run"},
               {"project", "helpers"},
               {"arguments", a}};
    };
    auto no_grant = show();
    no_grant["envelope"]["analysis_helpers"] = false;
    rejects(
        [&] { normalize_harness_workbench(store, no_grant, request(args)); },
        "missing helper grant accepted");
    auto bad = args;
    bad["input"]["file"] = "/etc/passwd";
    rejects([&] { normalize_harness_workbench(store, show(), request(bad)); },
            "host input path accepted");
    bad = args;
    bad["compiler_flags"] = {"-fplugin=/host.so"};
    rejects([&] { normalize_harness_workbench(store, show(), request(bad)); },
            "compiler flag injection accepted");
    bad = args;
    bad["source_code"] = std::string(16385, 'x');
    rejects([&] { normalize_harness_workbench(store, show(), request(bad)); },
            "oversized source accepted");
    auto normalized = normalize_harness_workbench(store, show(), request(args));
    normalized["arguments"]["sealed"]["input"]["hex"] = "00";
    rejects([&] { normalize_harness_workbench(store, show(), normalized); },
            "altered input seal accepted");
    unsigned count = 0;
    auto run = [&](const J &a) {
      auto action =
          owned("propose", {{"key", "helper_" + std::to_string(++count)},
                            {"proposal",
                             {{"gap", "helper fixture"},
                              {"expected_evidence", "bounded receipt"},
                              {"prediction", "explicit outcome"},
                              {"fallback", "retain failure"}}},
                            {"request", request(a)}});
      auto executed = owned("run", {{"action_id", action.at("id")}});
      check(executed.at("result").contains("knowledge_ids"),
            executed.dump().c_str());
      auto record =
          wb::knowledge(store, "show",
                        {{"project", "helpers"},
                         {"id", executed.at("result").at("knowledge_ids")[0]}});
      check(record.contains("harness_origin"),
            "helper publication has no action lineage");
      auto page = harness_action(service, "read",
                                 {{"project", "helpers"},
                                  {"id", id},
                                  {"family", "helper"},
                                  {"operation", "read"},
                                  {"request",
                                   {{"id", record.at("id")},
                                    {"revision", record.at("revision")},
                                    {"pointer", "/source_code"},
                                    {"max_bytes", 32}}}});
      check(page.at("value") ==
                a.at("source_code").get<std::string>().substr(0, 32),
            "helper source page mismatch");
      auto again = owned("run", {{"action_id", action.at("id")}});
      check(again.at("result").at("knowledge_ids") ==
                executed.at("result").at("knowledge_ids"),
            "helper replay was executed twice");
      check(!record.at("body").at("verified_solve").get<bool>(),
            "helper promoted to solved");
      return record.at("body");
    };
#ifdef __linux__
    setenv("OPENROUTER_API_KEY", "helper-test-secret-not-a-credential", 1);
    auto copy = run(args);
    check(copy.at("validation_passed").get<bool>(), copy.dump().c_str());
    check(copy.at("repeatable_observed").get<bool>() &&
              copy.at("output_hex") == "41424344",
          "copy output incorrect");
    check(copy.at("stages").size() == 2, "fresh root replay missing");
    auto python = args;
    python["language"] = "python3";
    python["source_code"] = "import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n";
    check(run(python).at("validation_passed").get<bool>(), "Python copy failed");
    python["source_code"] = "raise ValueError('bounded diagnostic')\n";
    auto python_error = run(python);
    check(python_error.at("status") == "execution_failed" &&
              !python_error.at("validation_passed").get<bool>(),
          "Python exception accepted");
    python["source_code"] = "import os, socket\nassert 'OPENROUTER_API_KEY' not in os.environ\nassert not os.path.exists('/etc/passwd')\ntry:\n socket.socket()\nexcept PermissionError:\n pass\nelse:\n raise AssertionError('network allowed')\nprint('isolated')\n";
    python["validation"] = {{"kind", "none"}};
    check(run(python).at("repeatable_observed").get<bool>(), "Python isolation failed");
    python["source_code"] = "while True: pass\n";
    check(!run(python).at("repeatable_observed").get<bool>(), "Python timeout accepted");
    python["source_code"] = "print('x' * 10000)\n";
    check(!run(python).at("repeatable_observed").get<bool>(), "Python output overflow accepted");
    python["source_code"] = "try:\n x = bytearray(1024 * 1024 * 1024)\nexcept MemoryError:\n print('bounded')\nelse:\n raise AssertionError('memory limit absent')\n";
    check(run(python).at("repeatable_observed").get<bool>(), "Python memory limit absent");
    auto files=args;files["language"]="python3";
    files["inputs"]=J::array({{{"name","second"},{"target_id",target.id},{"offset",0},{"max_bytes",4}}});
    files["output_files"]={"decoded"};
    files["validation"]["output_file"]="decoded";
    files["source_code"]="from pathlib import Path\nimport sys\nb=Path('/input/files/second').read_bytes()\nPath('/tmp/output/decoded').write_bytes(b)\nsys.stdout.buffer.write(b)\n";
    auto published=run(files);check(published.at("validation_passed").get<bool>()&&published.at("files")[0].at("hex")=="41424344","scoped file helper failed");
    files["source_code"]="import os\nos.symlink('/input/input.bin','/tmp/output/decoded')\n";
    check(!run(files).at("repeatable_observed").get<bool>(),"symlink output accepted");
    files["inputs"][0]["target_id"]="foreign-target";
    rejects([&]{normalize_harness_workbench(store,show(),request(files));},"foreign helper input accepted");
    bad = args;
    bad["validation"]["expected"]["offset"] = 1;
    bad["validation"]["expected"]["max_bytes"] = 3;
    check(!run(bad).at("validation_passed").get<bool>(),
          "wrong reference passed");
    auto transform = args;
    transform["source_code"] = "#include <stdio.h>\nint main(void){int "
                               "c;while((c=getchar())!=EOF)putchar(c^32);}";
    transform["validation"] = {
        {"kind", "calculation"},
        {"program",
         {{"iterations", 4},
          {"emit", J::array({"xor", J::array({"byte", "i"}), 32})}}}};
    check(run(transform).at("validation_passed").get<bool>(),
          "native transform cross-check failed");
    auto generate = args;
    generate["language"] = "c++20";
    generate["source_code"] = "#include <cstdio>\nint main(){for(int "
                              "i=0;i<4;++i)std::putchar(65+i);}";
    check(run(generate).at("validation_passed").get<bool>(),
          "C++ generator failed");
    auto isolated = args;
    isolated["validation"] = {{"kind", "none"}};
    isolated["source_code"] = R"(#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void){
 if(getenv("OPENROUTER_API_KEY"))return 11;
 if(access("/etc/passwd",F_OK)==0||access("/proc",F_OK)==0||access("/home",F_OK)==0||access("/mnt/c",F_OK)==0)return 12;
 if(open("/usr/bin/helper-write",O_CREAT|O_WRONLY,0600)>=0)return 13;
 if(open("/outside-scratch",O_CREAT|O_WRONLY,0600)>=0)return 20;
 if(socket(AF_INET,SOCK_STREAM,0)>=0)return 14;
 if(fork()>=0)return 15;
 if(setsid()>=0)return 16;
 for(int fd=3;fd<256;++fd)if(fcntl(fd,F_GETFD)>=0)return 19;
 FILE*f=fopen("/tmp/seen","r");if(f)return 17;
 f=fopen("/tmp/seen","w");if(!f)return 18;fclose(f);
 puts("isolated");return 0;
})";
    auto isolation = run(isolated);
    check(isolation.at("repeatable_observed").get<bool>(),
          isolation.dump().c_str());
    auto timeout = isolated;
    timeout["source_code"] = "int main(void){for(;;){}}";
    check(!run(timeout).at("repeatable_observed").get<bool>(),
          "infinite helper succeeded");
    auto flood = isolated;
    flood["source_code"] = "#include <stdio.h>\nint main(void){for(int "
                           "i=0;i<10000;++i)putchar('x');}";
    check(!run(flood).at("repeatable_observed").get<bool>(),
          "output truncation succeeded");
    auto memory = isolated;
    memory["source_code"] = "#include <stdlib.h>\nint main(void){return "
                            "malloc(1024UL*1024*1024)?1:0;}";
    check(run(memory).at("repeatable_observed").get<bool>(),
          "address-space limit missing");
    auto invalid = isolated;
    invalid["source_code"] = "this is not C";
    check(run(invalid).at("status") == "compile_failed",
          "compile failure not recorded");
    auto smt = isolated;
    smt["language"] = "smt2";
    smt["source_code"] = "(declare-const x (_ BitVec 8)) (assert (= (bvxor x "
                         "#x20) #x61)) (check-sat) (get-value (x))";
    auto solved = run(smt);
    check(solved.at("repeatable_observed").get<bool>(), solved.dump().c_str());
    check(solved.at("output_hex").get<std::string>().find("736174") !=
              std::string::npos,
          "solver did not return sat");
    auto pending = owned("propose", {{"key", "cancel_helper"},
                                     {"proposal",
                                      {{"gap", "cancel"},
                                       {"expected_evidence", "cancellation"},
                                       {"prediction", "bounded stop"},
                                       {"fallback", "retain unknown"}}},
                                     {"request", request(timeout)}});
    std::exception_ptr cancel_error;
    std::jthread cancel([&] {
      std::this_thread::sleep_for(std::chrono::milliseconds(150));
      try {
        harness_action(
            service, "cancel",
            {{"project", "helpers"}, {"id", id}, {"owner_token", token}});
      } catch (...) {
        cancel_error = std::current_exception();
      }
    });
    const auto cancelled = owned("run", {{"action_id", pending.at("id")}});
    cancel.join();
    if (cancel_error)
      std::rethrow_exception(cancel_error);
    check(show().at("status") == "cancelled" &&
              cancelled.at("elapsed_ms").get<std::uint64_t>() < 5000 &&
              (cancelled.at("status") == "cancelled" ||
               cancelled.at("result").at("worker").at("cancelled").get<bool>()),
          "helper cancellation did not settle");
#else
    check(run(args).at("status") == "capability_blocked",
          "unsupported host executed generated code");
#endif
    std::cout << "Helper scope, receipts, replay, validation and isolation "
                 "checks passed; actions="
              << count << " workspace=" << root << '\n';
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << "\nworkspace=" << root << '\n';
    return 1;
  }
}
