#pragma once
#include "workbench_db.hpp"

namespace indago::wb {
// Internal dispatch context, never accepted from a workbench JSON request.
// The knowledge revision and its action publication pointer commit together.
struct PublicationContext {
  std::string project, investigation, action, runner, request_sha256;
};
inline thread_local const PublicationContext *publication_context = nullptr;
class PublicationScope {
  PublicationContext context_;

public:
  explicit PublicationScope(PublicationContext context)
      : context_(std::move(context)) {
    if (publication_context)
      throw std::runtime_error("nested workbench publication context");
    publication_context = &context_;
  }
  PublicationScope(const PublicationScope &) = delete;
  PublicationScope &operator=(const PublicationScope &) = delete;
  ~PublicationScope() { publication_context = nullptr; }
};
inline J publication_origin() {
  const auto &c = *publication_context;
  return {{"investigation", c.investigation},
          {"action", c.action},
          {"request_sha256", c.request_sha256}};
}
inline J publication_action(Db &db) {
  const auto &c = *publication_context;
  Q get(db, "SELECT record FROM wb_investigation_actions WHERE project=? AND "
            "investigation=? AND id=? AND runner=? AND deadline>? AND "
            "request_hash=?");
  if (!get.s(1, c.project)
           .s(2, c.investigation)
           .s(3, c.action)
           .s(4, c.runner)
           .n(5, now_ms())
           .s(6, c.request_sha256)
           .row())
    throw std::runtime_error("publication runner or request identity lost");
  auto action = J::parse(get.text(0));
  if (!action.value("dispatch_started", false) ||
      action.contains("publication") ||
      action.at("request").at("backend") != "workbench" ||
      sha256_text(action.at("request").dump()) != c.request_sha256)
    throw std::runtime_error("invalid or repeated action publication");
  return action;
}
// Called under the knowledge publisher's BEGIN IMMEDIATE transaction, before
// updating its head. Includes the predecessor pin for knowledge.revise, without
// introducing a forbidden self-dependency into the knowledge graph.
inline void check_publication_dependencies(Db &db, const std::string &project) {
  if (!publication_context)
    return;
  if (publication_context->project != project)
    throw std::runtime_error("cross-project publication context");
  auto action = publication_action(db);
  for (const auto &pin : action.at("request").at("dependency_pins")) {
    const auto type = pin.at("type").get<std::string>();
    const auto id = pin.at("id").get<std::string>();
    std::string sql;
    if (type == "artifact")
      sql = "SELECT sha FROM targets WHERE project=? AND sha=?";
    else if (type == "record")
      sql = "SELECT CAST(revision AS TEXT) FROM wb_heads WHERE project=? AND "
            "id=?";
    else if (type == "evidence")
      sql = "SELECT revision FROM evidence WHERE project=? AND id=?";
    else
      throw std::runtime_error("unsupported publication dependency type");
    Q current(db, sql);
    if (!current.s(1, project).s(2, id).row() ||
        pin.at("pin") != current.text(0))
      throw std::runtime_error("dependency pin changed before publication");
  }
}
inline void link_publication(Db &db, const J &record, const std::string &sha) {
  if (!publication_context)
    return;
  const auto &c = *publication_context;
  if (record.at("project") != c.project)
    throw std::runtime_error("cross-project publication context");
  auto action = publication_action(db);
  action["publication"] = {{"knowledge_id", record.at("id")},
                           {"revision", record.at("revision")},
                           {"sha256", sha},
                           {"origin", publication_origin()}};
  Q put(db, "UPDATE wb_investigation_actions SET record=? WHERE project=? AND "
            "id=? AND runner=?");
  put.s(1, action.dump()).s(2, c.project).s(3, c.action).s(4, c.runner).row();
  if (sqlite3_changes(db.p) != 1)
    throw std::runtime_error("publication runner changed");
}
} // namespace indago::wb
