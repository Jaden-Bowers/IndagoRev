#include "indago/harness.hpp"
#include "indago/storage_lease.hpp"
#include "indago/workbench.hpp"
#include "network_cursor_checks.hpp"
#include "managed_index_checks.hpp"
#include "offline_contract_checks.hpp"
#include "packet_stream_checks.hpp"
#include "index_completeness_checks.hpp"
#include <fstream>
#include <iostream>
#include <sqlite3.h>

using namespace indago;
using J = nlohmann::json;
void check(bool b, const char *text) {
  if (!b)
    throw std::runtime_error(text);
}
template <class F> void rejects(F f, const char *text) {
  bool rejected = false;
  try {
    f();
  } catch (const std::exception &) {
    rejected = true;
  }
  check(rejected, text);
}
int main() {
  auto dir = fs::temp_directory_path() / make_id("indago_knowledge_test");
  try {
    packet_stream_checks();
    index_completeness_checks(dir / "index-completeness-fixture");
    network_cursor_checks(dir / "network-cursor-fixture");
    managed_index_checks(dir / "managed-index-fixture");
    offline_contract_checks(dir / "offline-contract-fixture");
    StaticService svc(dir);
    auto &store = svc.store();
    store.create_project("demo");
    auto call = [&](std::string_view family, std::string_view op, J r) {
      if (family != "retention" && !(family == "bundle" && op == "import"))
        r["project"] = "demo";
      return workbench_action(svc, family, op, r);
    };
    auto file = dir / "input.bin";
    atomic_write(file, "ABCGo build ID:example");
    auto t = store.import_target("demo", file);
    J req{{"project", "demo"},
          {"backend", "xair"},
          {"operation", "cfg"},
          {"budget",
           {{"max_items", 100},
            {"wall_ms", 1000},
            {"memory_bytes", 1048576},
            {"output_bytes", 65536}}}};
    auto job = svc.prepare(req);
    J native{
        {"status", "completed"},
        {"functions",
         J::array({{{"id", 0},
                    {"name", "entry"},
                    {"location",
                     {{"address", "0x1000"}, {"address_space", "program"}}},
                    {"blocks", {0}},
                    {"semantic_completeness", "partial"}}})},
        {"blocks",
         J::array({{{"id", 0},
                    {"location",
                     {{"address", "0x1000"}, {"address_space", "program"}}}}})},
        {"calls", J::array({{{"from", "0x1000"}, {"to", "0x2000"}}})}};
    auto result =
        store.publish_result(t, job, "xair", {0, "completed", native.dump()});
    auto evidence = result["evidence_ids"][0];
    J hypothesis{{"kind", "hypothesis"},
                 {"title", "Input decoding hypothesis"},
                 {"scope", {{"artifact_sha256", t.sha256}}},
                 {"body",
                  {{"prediction", "bytes map to output"},
                   {"alternatives", J::array({"decoy"})},
                   {"unknowns", J::array({"other inputs"})}}},
                 {"support", J::array({evidence})}};
    auto h = call("knowledge", "put", hypothesis);
    check(h["revision"] == 1 && h["freshness"] == "current",
          "knowledge publication");
    J summary{
        {"kind", "summary"},
        {"title", "Summary"},
        {"scope", {{"artifact_sha256", t.sha256}}},
        {"body", {{"text", "depends on hypothesis"}}},
        {"dependencies", J::array({{{"type", "record"}, {"id", h["id"]}}})}};
    auto s = call("knowledge", "put", summary);
    hypothesis["id"] = h["id"];
    hypothesis["expected_revision"] = 1;
    hypothesis["title"] = "Revised hypothesis";
    auto h2 = call("knowledge", "put", hypothesis);
    check(h2["revision"] == 2, "optimistic update");
    rejects([&] { call("knowledge", "put", hypothesis); },
            "stale update must fail");
    auto stale = call("knowledge", "show", {{"id", s["id"]}});
    check(stale["freshness"] == "stale" && stale["state"] == "inferred",
          "stale is not false");
    check(!call("knowledge", "impact", {{"id", h["id"]}})["records"].empty(),
          "dependency impact");
    hypothesis.erase("id");
    hypothesis.erase("expected_revision");
    hypothesis["state"] = "validated";
    rejects([&] { call("knowledge", "put", hypothesis); },
            "caller cannot promote validated");
    hypothesis.erase("state");
    hypothesis["support"] = J::array({"ev_missing"});
    rejects([&] { call("knowledge", "put", hypothesis); },
            "missing evidence rejected");
    auto packet = call("graph", "packet",
                       {{"address", "0x1000"},
                        {"depth", 2},
                        {"limit", 10},
                        {"output_bytes", 8192}});
    check(!packet["nodes"].empty() && packet.dump().size() <= 8192,
          "bounded graph packet");
    check(!call("coverage", "report", {{"artifact", t.sha256}})["gaps"].empty(),
          "coverage gaps");
    auto derived = call("transform", "run",
                        {{"artifact", t.sha256},
                         {"offset", 0},
                         {"size", 3},
                         {"spec", {{"method", "xor"}, {"key_hex", "01"}}}});
    auto output = derived["artifact_sha256"].get<std::string>();
    J v{{"scope",
         {{"artifact_sha256", output}, {"inputs", "one supplied fixture"}}},
        {"subject", derived["record"]["id"]},
        {"cases", J::array({{{"actual_artifact", output},
                             {"expected_hex", "404342"}}})}};
    auto validated = call("validate", "compare", v);
    check(validated["state"] == "validated", "exact bytes validator");
    auto pinned_validation = v;
    pinned_validation["subject"] = h["id"];
    pinned_validation["dependencies"] =
        J::array({{{"type", "record"}, {"id", h["id"]}, {"pin", "1"}}});
    rejects([&] { call("validate", "compare", pinned_validation); },
            "validator rejects stale subject pin at publication transaction");
    pinned_validation["dependencies"][0]["pin"] = "2";
    check(call("validate", "compare", pinned_validation)["state"] ==
              "validated",
          "validator accepts current pinned subject");
    v["cases"][0]["expected_hex"] = "00";
    auto failed = call("validate", "compare", v);
    check(failed["state"] == "contradicted" &&
              !failed["body"]["cases"][0]["passed"].get<bool>(),
          "counterexample retained");
    J signature{{"kind", "signature"},
                {"title", "Known three bytes"},
                {"scope", {{"artifact_sha256", t.sha256}}},
                {"body",
                 {{"sha256", sha256_text("ABC")},
                  {"offset", 0},
                  {"size", 3},
                  {"provenance", "fixture source"}}}};
    call("knowledge", "put", signature);
    auto rec =
        call("recognize", "scan", {{"artifact", t.sha256}, {"publish", true}});
    check(rec["findings"].size() >= 2, "marker and exact byte recognition");
    req["target_id"] = t.id;
    auto next = svc.prepare(req);
    native["functions"][0]["name"] = "changed";
    store.publish_result(t, next, "xair", {0, "completed", native.dump()});
    check(call("knowledge", "show", {{"id", h["id"]}})["freshness"] == "stale",
          "analysis revision invalidates dependent claims");
    J ghreq = req;
    ghreq["backend"] = "ghidra";
    ghreq["operation"] = "functions";
    auto gj = svc.prepare(ghreq);
    J gn = native;
    gn["program_revision"] = 1;
    gn["provenance"] = {{"session_key", "fixture-session"}};
    auto gr =
        store.publish_result(t, gj, "ghidra", {0, "completed", gn.dump()});
    J gs = summary;
    gs.erase("dependencies");
    gs["support"] = gr["evidence_ids"];
    auto dependent = call("knowledge", "put", gs);
    // Metadata fixture, not a live Ghidra-worker qualification run.
    auto gh_inv = harness_action(
        svc, "create",
        {{"project", "demo"},
         {"target_id", t.id},
         {"objective", "Audit persistent-program citation freshness"},
         {"required_facts", J::array({"function inventory"})},
         {"owner",
          {{"mode", "external"}, {"name", "offline metadata fixture"}}},
         {"budget",
          {{"max_actions", 1}, {"wall_ms", 10000}, {"output_bytes", 65536}}}});
    auto gh_report = harness_action(
        svc, "finish",
        {{"project", "demo"},
         {"id", gh_inv["id"]},
         {"owner_token", gh_inv["owner_token"]},
         {"expected_revision", gh_inv["revision"]},
         {"status", "answered"},
         {"answer", "Synthetic inventory metadata exists"},
         {"gaps", J::array()},
         {"claims", J::array({{{"fact", "function inventory"},
                               {"text", "Fixture inventory exists"},
                               {"evidence_ids", gr["evidence_ids"]},
                               {"limitations",
                                J::array({"Synthetic metadata only"})}}})}});
    harness_action(svc, "release",
                   {{"project", "demo"},
                    {"id", gh_inv["id"]},
                    {"owner_token", gh_inv["owner_token"]},
                    {"expected_revision", gh_report["revision"]}});
    ghreq["operation"] = "control_flow";
    ghreq["address"] = "0x1000";
    auto edited = svc.prepare(ghreq);
    gn["program_revision"] = 2;
    store.publish_result(t, edited, "ghidra", {0, "completed", gn.dump()});
    check(call("knowledge", "show", {{"id", dependent["id"]}})["freshness"] ==
              "stale",
          "Ghidra Program edits invalidate other operation scopes");
    auto gh_audit = harness_action(svc, "audit",
                                   {{"project", "demo"}, {"id", gh_inv["id"]}});
    check(gh_audit["status"] == "needs_review" &&
              gh_audit["issues"][0]["reasons"][0] ==
                  "Ghidra Program revision advanced; requery affected view" &&
              harness_action(
                  svc, "show",
                  {{"project", "demo"}, {"id", gh_inv["id"]}})["report"] ==
                  gh_report["report"],
          "saved report audit detects Ghidra edits across different operation "
          "scopes");
    auto base64file = dir / "base64.txt";
    atomic_write(base64file, "QUJD");
    auto encoded = store.import_target("demo", base64file);
    auto decoded = call("transform", "run",
                        {{"artifact", encoded.sha256},
                         {"spec", {{"method", "base64_decode"}}}});
    check(decoded["artifact_sha256"] == sha256_text("ABC"),
          "canonical base64 decode");
    atomic_write(dir / "bad64.txt", "QR==");
    auto bad = store.import_target("demo", dir / "bad64.txt");
    rejects(
        [&] {
          call("transform", "run",
               {{"artifact", bad.sha256},
                {"spec", {{"method", "base64_decode"}}}});
        },
        "noncanonical base64 padding rejected");
    auto batch =
        call("batch", "create",
             {{"budget",
               {{"wall_ms", 1000},
                {"output_bytes", 65536},
                {"memory_bytes", 1048576},
                {"max_jobs", 1}}},
              {"steps", J::array({{{"name", "reserved"}, {"request", req}}})}});
    auto reservedAction = batch["steps"][0]["request"];
    auto key =
        batch["id"].get<std::string>() + ":" + sha256_text("reserved") + ":1";
    reservedAction["idempotency_key"] = key;
    auto reservedJob = svc.prepare(reservedAction);
    store.publish_result(t, reservedJob, "xair",
                         {0, "completed", native.dump()});
    batch["reserved_wall_ms"] = 1000;
    batch["reserved_output_bytes"] = 65536;
    batch["jobs_started"] = 1;
    batch["steps"][0]["reserved"] = true;
    batch["steps"][0]["reserved_key"] = key;
    sqlite3 *testDb{};
    check(sqlite3_open((dir / "indago-native.sqlite3").string().c_str(),
                       &testDb) == SQLITE_OK,
          "batch recovery fixture DB");
    sqlite3_stmt *statement{};
    check(sqlite3_prepare_v2(
              testDb,
              "UPDATE wb_batches SET "
              "record=?,owner='expired-test-owner',deadline=0 WHERE id=?",
              -1, &statement, nullptr) == SQLITE_OK,
          "batch recovery fixture statement");
    auto reservedText = batch.dump(), batchId = batch["id"].get<std::string>();
    sqlite3_bind_text(statement, 1, reservedText.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(statement, 2, batchId.c_str(), -1, SQLITE_TRANSIENT);
    check(sqlite3_step(statement) == SQLITE_DONE, "reserved attempt fixture");
    sqlite3_finalize(statement);
    sqlite3_close(testDb);
    auto resumed = call("batch", "run", {{"id", batchId}});
    check(resumed["status"] == "completed" && resumed["jobs_started"] == 1 &&
              resumed["steps"][0]["job_id"] == reservedJob["id"],
          "reservation recovery reuses one completed job at exhausted ceiling");
    auto bundle = dir.parent_path() / (dir.filename().string() + "_bundle"),
         restored = dir.parent_path() / (dir.filename().string() + "_restored");
    J system_input{
        {"os", "windows"},
        {"architecture", "mixed"},
        {"components", J::array({{{"name", "server"},
                                  {"target_id", t.id},
                                  {"role", "service"},
                                  {"path", "bin/server.exe"}},
                                 {{"name", "client"},
                                  {"target_id", t.id},
                                  {"role", "program"},
                                  {"path", "bin/client.exe"}}})},
        {"launches", J::array({{{"name", "client"},
                                {"component", "client"},
                                {"depends_on", J::array({"server"})}},
                               {{"name", "server"},
                                {"component", "server"},
                                {"readiness", "service_ready"}}})},
        {"environment", {{"LAB_TOKEN", {{"secret_ref", "fixture_token"}}}}},
        {"requirements", J::array({{{"kind", "runtime"},
                                    {"name", "source-backed fixture runtime"},
                                    {"version", "1"}}})}};
    auto system = call("system", "create", {{"manifest", system_input}});
    check(system["kind"] == "system_manifest" &&
              system["body"]["launch_order"] ==
                  J::array({"server", "client"}) &&
              system["body"]["components"][0]["artifact_sha256"] == t.sha256,
          "system manifest pins component identity and orders launch "
          "dependencies");
    auto preflight = call("system", "preflight", {{"id", system["id"]}});
    check(preflight["status"] == "capability_blocked" &&
              preflight["ready_for_execution"] == false &&
              preflight["target_execution"] == false &&
              preflight["hashed_bytes"] == t.size &&
              preflight["artifacts"][1]["integrity"] == "verified",
          "manifest preflight deduplicates integrity work and does not claim a "
          "lab");
    auto bounded_preflight =
        call("system", "preflight", {{"id", system["id"]}, {"max_bytes", 1}});
    check(bounded_preflight["partial"] == true &&
              bounded_preflight["hashed_bytes"] == 0,
          "preflight byte budget cannot be bypassed by large components");
    auto bad_system = system_input;
    bad_system["launches"][1]["depends_on"] = J::array({"client"});
    rejects(
        [&] {
          call("system", "create", {{"manifest", bad_system}});
        },
        "cyclic system launch graph rejected");
    bad_system = system_input;
    bad_system["components"][0]["path"] = "../host.exe";
    rejects(
        [&] {
          call("system", "create", {{"manifest", bad_system}});
        },
        "manifest cannot stage outside guest-relative root");
    bad_system["components"][0]["path"] = "bin/CON.exe";
    rejects(
        [&] {
          call("system", "create", {{"manifest", bad_system}});
        },
        "Windows device path rejected");
    bad_system = system_input;
    bad_system["components"][1]["path"] = "BIN/SERVER.EXE";
    rejects(
        [&] {
          call("system", "create", {{"manifest", bad_system}});
        },
        "case-folded guest collision rejected");
    bad_system = system_input;
    bad_system["network"] = "external";
    rejects(
        [&] {
          call("system", "create", {{"manifest", bad_system}});
        },
        "manifest cannot grant external network");
    bad_system = system_input;
    bad_system["components"][1]["path"] = "bin";
    rejects(
        [&] {
          call("system", "create", {{"manifest", bad_system}});
        },
        "guest file/directory overlap rejected");
    bad_system = system_input;
    bad_system["environment"]["lab_token"] = {
        {"value", "not the declared secret"}};
    rejects(
        [&] {
          call("system", "create", {{"manifest", bad_system}});
        },
        "Windows environment aliases rejected");
    bad_system = system_input;
    bad_system["isolation"] = "wsl";
    rejects(
        [&] {
          call("system", "create", {{"manifest", bad_system}});
        },
        "WSL is not a hostile-code sandbox");
    auto forged = summary;
    forged["kind"] = "system_manifest";
    rejects([&] { call("knowledge", "put", forged); },
            "ordinary assertion cannot forge computed system manifest");
    call("bundle", "export", {{"destination", bundle.string()}});
    auto imported =
        call("bundle", "import",
             {{"source", bundle.string()}, {"destination", restored.string()}});
    check(imported["workspace"] == restored.string(),
          "portable import finalized");
    StaticService reopened(restored);
    check(workbench_action(reopened, "system", "show",
                           {{"project", "demo"},
                            {"id", system["id"]}})["body"] == system["body"],
          "portable bundle retains exact system manifest without execution "
          "authority");
    auto loaded = workbench_action(reopened, "knowledge", "show",
                                   {{"project", "demo"}, {"id", s["id"]}});
    check(loaded["freshness"] == "stale",
          "bundle preserves dependency graph and freshness");
    J manifest;
    {
      std::ifstream f(bundle / "manifest.json");
      f >> manifest;
    }
    const auto originalManifest = manifest;
    auto rejectManifest = [&](const J &changed, const char *message) {
      atomic_write(bundle / "manifest.json", changed.dump());
      atomic_write(bundle / "manifest.sha256", sha256_text(changed.dump()));
      auto destination = dir.parent_path() / make_id("rejected_bundle");
      rejects(
          [&] {
            call("bundle", "import",
                 {{"source", bundle.string()},
                  {"destination", destination.string()}});
          },
          message);
      check(!fs::exists(destination), "rejected snapshot not published");
    };
    manifest["project"] = "another";
    rejectManifest(manifest, "declared project mismatch rejected");
    manifest = originalManifest;
    manifest["core"]["jobs"][0]["status"] = "running";
    rejectManifest(manifest, "live job import rejected");
    manifest = originalManifest;
    manifest["runtime"]["runtime_sessions"] = J::array(
        {{{"id", "run_fixture"},
          {"project", "demo"},
          {"cancel", 0},
          {"record",
           J{{"id", "run_fixture"}, {"project", "demo"}, {"state", "running"}}
               .dump()}}});
    rejectManifest(manifest, "live session import rejected");
    manifest["runtime"]["runtime_sessions"][0]["record"] = J{
        {"id", "run_fixture"},
        {"project", "another"},
        {"state", "exited"}}.dump();
    rejectManifest(manifest, "cross-project runtime record rejected");
    atomic_write(bundle / "manifest.json", originalManifest.dump());
    atomic_write(bundle / "manifest.sha256",
                 sha256_text(originalManifest.dump()));
    rejects(
        [&] {
          call("bundle", "import",
               {{"source", bundle.string()},
                {"destination", restored.string()}});
        },
        "import never overwrites workspace");
    const auto orphan = sha256_text("orphan");
    auto orphanPath =
        dir / "objects" / "sha256" / orphan.substr(0, 2) / orphan.substr(2);
    atomic_write(orphanPath, "orphan");
    fs::last_write_time(orphanPath, fs::file_time_type::clock::now() -
                                        std::chrono::hours(25));
    auto plan = call("retention", "plan", J::object());
    check(plan["candidates"].size() == 1,
          "retention preserves all evidence references");
    {
      StorageLease active(dir);
      rejects(
          [&] {
            call("retention", "quarantine",
                 {{"plan_digest", plan["plan_digest"]}});
          },
          "retention cannot race publisher");
    }
    auto moved =
        call("retention", "quarantine", {{"plan_digest", plan["plan_digest"]}});
    check(!fs::exists(orphanPath) &&
              fs::exists(fs::path(moved["quarantine"].get<std::string>()) /
                         orphan),
          "recoverable retention");
    std::cout << J{{"status", "passed"},
                   {"workspace", dir.string()},
                   {"restored", restored.string()},
                   {"checks",
                    "records, revision conflicts, dependency freshness, graph "
                    "bounds, coverage, transformations, validators, "
                    "recognition, portable bundle, retention locking"}}
                     .dump()
              << '\n';
  } catch (const std::exception &e) {
    std::cerr << e.what() << " (retained " << dir << ")\n";
    return 1;
  }
}
