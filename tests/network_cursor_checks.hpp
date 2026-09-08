#pragma once
#include "../src/runtime_call_identity.hpp"
#include "../src/workbench_db.hpp"
#include "indago/runtime.hpp"

// Offline database fixtures only: no attachment, sockets, capture or execution.
inline void network_cursor_checks(const indago::fs::path &root) {
  using namespace indago;
  using J = nlohmann::json;
  J invocation{{"call_id", "call_fixture"},
               {"process_id", "process_fixture"},
               {"native",
                {{"payload",
                  {{"api", "recv"}, {"thread_instance", "thread_fixture"}}}}}};
  auto entered =
      advance_api_call_identity(nullptr, invocation, "api_enter", "entry");
  if (entered.at("pair_complete") != false ||
      !entered.at("return_observation").is_null())
    throw std::runtime_error("missing API return was invented");
  auto paired =
      advance_api_call_identity(entered, invocation, "api_leave", "return");
  if (paired.at("pair_complete") != true ||
      paired.at("network_delivery_proven") != false)
    throw std::runtime_error(
        "API pair either missing or falsely claims delivery");
  auto duplicate =
      advance_api_call_identity(paired, invocation, "api_enter", "duplicate");
  if (duplicate.at("pair_complete") != false ||
      duplicate.at("entry_observation") != "entry" ||
      duplicate.at("duplicate_observations") != 1)
    throw std::runtime_error(
        "duplicate API entry replaced source or remained complete");
  auto different = invocation;
  different["process_id"] = "other_process";
  auto conflict =
      advance_api_call_identity(entered, different, "api_leave", "conflict");
  if (conflict.at("pair_complete") != false ||
      conflict.at("conflicting_observations") != true)
    throw std::runtime_error("API identity conflict was silently paired");
  auto missing_entry = advance_api_call_identity(nullptr, invocation,
                                                 "api_leave", "return_only");
  if (missing_entry.at("pair_complete") != false ||
      !missing_entry.at("entry_observation").is_null())
    throw std::runtime_error("missing API entry was invented");
  ProjectStore store(root);
  store.initialize();
  store.create_project("network_test");
  auto read = [&](J r) {
    r["project"] = "network_test";
    return runtime_command(store, {}, r);
  };
  read({{"operation", "sessions"}});
  wb::Db db(root / "runtime.sqlite3");
  wb::Q session(
      db, "INSERT INTO runtime_sessions(id,project,record) VALUES(?,?,?)");
  session.s(1, "fixture")
      .s(2, "network_test")
      .s(3,
         J{{"id", "fixture"}, {"state", "exited"}, {"result_status", "partial"}}
             .dump())
      .row();
  auto insert = [&](std::uint64_t sequence, std::string kind, J data) {
    auto id = "obs_" + std::to_string(sequence);
    auto raw = J{{"id", id}, {"kind", kind}, {"data", data}}.dump();
    wb::Q q(db, "INSERT INTO "
                "runtime_observations(sequence,id,session,kind,anchor,sha,"
                "record) VALUES(?,?,?,?,?,?,?)");
    q.n(1, sequence)
        .s(2, id)
        .s(3, "fixture")
        .s(4, kind)
        .s(5, "")
        .s(6, sha256_text(raw))
        .s(7, raw)
        .row();
  };
  {
    wb::Tx tx(db);
    for (std::uint64_t i = 1; i <= 512; ++i)
      insert(i, "fixture_noise", J::object());
    insert(513, "fixture_large", {{"bytes", std::string(70000, 'x')}});
    tx.commit();
  }
  J native{{"backend", "frida"},
           {"socket", {{"id", "socket_fixture"}}},
           {"native", {{"payload", {{"api", "send"}, {"return_value", "1"}}}}}};
  insert(514, "api_leave", native);
  J request{{"operation", "network"},
            {"session", "fixture"},
            {"from", 0},
            {"limit", 1}};
  auto first = read(request);
  if (!first.at("events").empty() || first.at("next_from") != 256 ||
      first.at("scanned_observations") != 256 || first.at("snapshot_to") != 514)
    throw std::runtime_error(
        "sparse network cursor did not bound scan and advance");
  insert(515, "api_leave", native);
  request["from"] = first.at("next_from");
  request["to"] = first.at("snapshot_to");
  auto second = read(request);
  if (!second.at("events").empty() || second.at("next_from") != 512)
    throw std::runtime_error(
        "second sparse network cursor skipped scan progress");
  request["from"] = second.at("next_from");
  auto third = read(request);
  if (third.at("events").size() != 1 ||
      third.at("events")[0].at("sequence") != 514 ||
      !third.at("next_from").is_null() ||
      third.at("omitted_observations") != 1 ||
      third.at("page_complete") != false ||
      third.at("scan_omissions")[0].at("observation_id") != "obs_513")
    throw std::runtime_error("network cursor failed snapshot isolation or "
                             "explicit oversized-source omission");
  request.erase("to");
  request["from"] = 514;
  request["id"] = "unrelated_socket";
  if (!read(request).at("events").empty())
    throw std::runtime_error("network cursor crossed socket identity filter");
  request["id"] = "socket_fixture";
  auto appended = read(request);
  if (appended.at("events").size() != 1 ||
      appended.at("events")[0].at("sequence") != 515)
    throw std::runtime_error(
        "new network snapshot cannot see appended observation");
  db.exec("UPDATE runtime_observations SET sha='invalid' WHERE sequence=515");
  bool rejected = false;
  try {
    read(request);
  } catch (const std::exception &) {
    rejected = true;
  }
  if (!rejected)
    throw std::runtime_error("network cursor accepted altered source hash");
}
