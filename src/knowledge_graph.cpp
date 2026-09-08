#include "workbench_db.hpp"
#include <algorithm>
#include <deque>

namespace indago::wb {
namespace {
J brief(J r) {
  r.erase("native");
  r["native_payload_omitted"] = true;
  return r;
}
bool unresolved(const J &r) {
  if (!r.is_object())
    return false;
  for (const char *k : {"semantic_completeness", "native_verdict", "resolution",
                        "status", "coverage"})
    if (r.contains(k)) {
      auto v = r[k].dump();
      std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      for (const char *term : {"partial", "unknown", "unresolved",
                               "unsupported", "opaque", "timeout"})
        if (v.find(term) != std::string::npos)
          return true;
    }
  return false;
}
} // namespace
J coverage(const ProjectStore &store, const J &r) {
  keys(r, {"project", "artifact", "limit", "scan_limit"});
  auto p = project(store, r);
  auto artifact = r.value("artifact", std::string{});
  if (!artifact.empty())
    hash(artifact);
  auto limit = bound(r, "limit", 100, 1000),
       scan = bound(r, "scan_limit", 10000, 100000);
  if (!limit || !scan)
    throw std::runtime_error("positive coverage bounds required");
  Db db(store.root() / "indago-native.sqlite3");
  J counts = J::array(), gaps = J::array();
  Q groups(db,
           "SELECT e.backend,e.kind,count(*) FROM static_entities e JOIN "
           "analysis_heads h ON h.project=e.project AND h.revision=e.revision "
           "WHERE e.project=? AND (?='' OR e.artifact=?) GROUP BY "
           "e.backend,e.kind ORDER BY e.backend,e.kind");
  groups.s(1, p).s(2, artifact).s(3, artifact);
  while (groups.row())
    counts.push_back({{"producer", groups.text(0)},
                      {"kind", groups.text(1)},
                      {"discoveries", groups.num(2)}});
  auto add = [&](J gap) {
    if (gaps.size() < limit)
      gaps.push_back(std::move(gap));
  };
  std::size_t inspected = 0, detected = 0;
  bool truncated = false;
  Q q(db, "SELECT e.record FROM static_entities e JOIN analysis_heads h ON "
          "h.project=e.project AND h.revision=e.revision WHERE e.project=? AND "
          "(?='' OR e.artifact=?) ORDER BY e.id LIMIT ?");
  q.s(1, p).s(2, artifact).s(3, artifact).n(4, scan + 1);
  while (q.row()) {
    if (inspected++ == scan) {
      truncated = true;
      break;
    }
    auto e = J::parse(q.text(0));
    auto n = e.value("native", J::object());
    if (unresolved(n)) {
      ++detected;
      add({{"kind", "backend_semantic_gap"},
           {"entity", brief(e)},
           {"native_coverage", n},
           {"interpretation",
            "backend reports a coverage limitation; not unreachability"}});
    }
  }
  Q edges(db, "SELECT e.record FROM static_relations e JOIN analysis_heads h "
              "ON h.project=e.project AND h.revision=e.revision WHERE "
              "e.project=? AND (?='' OR e.artifact=?) AND (e.kind IN "
              "('call','cfg_edge','indirect_flow')) AND e.target='' AND "
              "e.target_anchor='' ORDER BY e.id LIMIT ?");
  edges.s(1, p).s(2, artifact).s(3, artifact).n(4, limit + 1);
  while (edges.row()) {
    ++detected;
    add({{"kind", "unresolved_relationship_endpoint"},
         {"relationship", brief(J::parse(edges.text(0)))}});
  }
  Q jobs(db,
         "SELECT id,status,revision FROM jobs WHERE project=? AND status NOT "
         "IN ('completed','complete') AND (?='' OR target IN (SELECT id FROM "
         "targets WHERE project=? AND sha=?)) ORDER BY rowid DESC LIMIT ?");
  jobs.s(1, p).s(2, artifact).s(3, p).s(4, artifact).n(5, limit + 1);
  while (jobs.row()) {
    ++detected;
    add({{"kind", "incomplete_or_failed_job"},
         {"job", jobs.text(0)},
         {"status", jobs.text(1)},
         {"revision", jobs.text(2)}});
  }
  Q functions(db,
              "SELECT e.record FROM static_entities e JOIN analysis_heads h ON "
              "h.project=e.project AND h.revision=e.revision WHERE e.project=? "
              "AND e.kind='function' AND (?='' OR e.artifact=?) AND NOT "
              "EXISTS(SELECT 1 FROM indexed_revisions r JOIN analysis_heads a "
              "ON a.revision=r.revision WHERE r.project=e.project AND "
              "r.artifact=e.artifact AND r.backend=e.backend AND "
              "json_extract(r.record,'$.request.address')=e.address AND "
              "json_extract(r.record,'$.request.operation') NOT IN "
              "('functions','inventory','inspect')) ORDER BY e.id LIMIT ?");
  functions.s(1, p).s(2, artifact).s(3, artifact).n(4, limit + 1);
  while (functions.row()) {
    ++detected;
    add({{"kind", "no_current_addressed_analysis"},
         {"entity", brief(J::parse(functions.text(0)))},
         {"interpretation",
          "No address-selected analysis indexed for this producer; whole-image "
          "analysis may contain more detail"}});
  }
  // Runtime records retain their producer coverage; absence of runtime data is
  // never a negative observation.
  auto runtime = store.root() / "runtime.sqlite3";
  if (fs::exists(runtime)) {
    Db rd(runtime);
    Q sessions(rd, "SELECT record FROM runtime_sessions WHERE project=? AND "
                   "(?='' OR json_extract(record,'$.artifact_sha256')=?) ORDER "
                   "BY rowid DESC LIMIT 20");
    sessions.s(1, p).s(2, artifact).s(3, artifact);
    while (sessions.row()) {
      auto s = J::parse(sessions.text(0));
      add({{"kind", "runtime_coverage_requires_review"},
           {"session", s.value("id", std::string{})},
           {"scope", "bounded observer windows, code scopes and collection "
                     "limits; inspect runtime observations"}});
    }
  }
  return {{"schema", "indago.coverage.v1"},
          {"project", p},
          {"artifact", artifact},
          {"inventory", counts},
          {"gaps", gaps},
          {"scanned_entities", std::min(inspected, scan)},
          {"partial", truncated || detected > gaps.size()},
          {"gap_count_is_lower_bound", true},
          {"negative_inference_allowed", false},
          {"unknown_dimensions",
           {"total reachable code", "unobserved paths",
            "external-call model adequacy", "uncaptured state",
            "cross-observer completeness"}},
          {"interpretation", "Discovery counts are per backend/revision, not "
                             "unique functions or a completeness percentage"}};
}

J graph(const ProjectStore &store, const std::string &op, const J &r) {
  if (op == "event") {
    keys(r, {"project", "observation", "depth", "limit", "output_bytes"});
    auto p = project(store, r);
    if (!fs::exists(store.root() / "runtime.sqlite3"))
      throw std::runtime_error("runtime evidence unavailable");
    Db db(store.root() / "runtime.sqlite3");
    Q q(db,
        "SELECT o.record,o.sha FROM runtime_observations o JOIN "
        "runtime_sessions s ON s.id=o.session WHERE s.project=? AND o.id=?");
    if (!q.s(1, p).s(2, r.at("observation").get<std::string>()).row())
      throw std::runtime_error("unknown runtime observation");
    auto text = q.text(0);
    if (sha256_text(text) != q.text(1))
      throw std::runtime_error("runtime evidence integrity mismatch");
    auto observation = J::parse(text);
    auto data = observation.value("data", J::object()),
         location =
             data.value("location", data.value("source_location", J::object()));
    J out{{"schema", "indago.event-packet.v1"},
          {"observation", observation},
          {"static_packet", nullptr},
          {"partial", false}};
    if (location.is_object() && location.contains("anchor_id")) {
      J input = r;
      input.erase("observation");
      input["anchor"] = location["anchor_id"];
      out["static_packet"] = graph(store, "packet", input);
    } else
      out["static_gap"] = "No mapped static anchor; retain runtime code-epoch "
                          "identity and use explicit capture/reanalysis";
    auto budget = bound(r, "output_bytes", 262144, 2 * 1024 * 1024);
    if (budget < 4096)
      throw std::runtime_error("packet budget must be >=4096");
    if (out.dump().size() > budget) {
      out["observation"].erase("data");
      out["observation"]["data_omitted"] = true;
      out["partial"] = true;
    }
    if (out.dump().size() > budget) {
      out["static_packet"] = nullptr;
      out["static_packet_omitted"] = true;
    }
    return out;
  }
  keys(r, {"project", "id", "anchor", "address", "artifact", "search", "depth",
           "limit", "output_bytes", "direction", "kinds"});
  auto p = project(store, r);
  auto limit = bound(r, "limit", 100, 1000), depth = bound(r, "depth", 2, 8),
       budget = bound(r, "output_bytes", 262144, 2 * 1024 * 1024);
  if (!limit || budget < 4096)
    throw std::runtime_error(
        "graph requires positive limit and >=4096 output_bytes");
  const auto direction = r.value("direction", std::string("both"));
  if (direction != "both" && direction != "in" && direction != "out")
    throw std::runtime_error("invalid graph direction");
  J filter{{"limit", limit}};
  for (const auto *key : {"id", "anchor", "address", "artifact", "search"})
    if (r.contains(key))
      filter[key] = r[key];
  if (op == "search") {
    auto result = store.index_query(p, filter);
    result["schema"] = "indago.graph-search.v1";
    return result;
  }
  if (op != "neighborhood" && op != "packet")
    throw std::runtime_error("unknown graph operation");
  if (!r.contains("id") && !r.contains("anchor") && !r.contains("address") &&
      !r.contains("search"))
    throw std::runtime_error("graph seed required");
  Db db(store.root() / "indago-native.sqlite3");
  std::set<std::string> nodeIds, edgeIds, anchors;
  std::deque<std::pair<J, std::size_t>> todo;
  J nodes = J::array(), edges = J::array();
  bool partial = false;
  std::size_t bytes = 2048;
  auto node = [&](J e, std::size_t d) {
    auto id = e.at("id").get<std::string>();
    if (nodeIds.contains(id))
      return;
    auto b = brief(e);
    auto size = b.dump().size();
    if (nodes.size() >= limit || bytes + size > budget) {
      partial = true;
      return;
    }
    bytes += size;
    nodeIds.insert(id);
    nodes.push_back(b);
    todo.emplace_back(e, d);
  };
  auto seeds = store.index_query(p, filter);
  partial = !seeds["next_offset"].is_null();
  for (auto e : seeds["records"])
    node(e, 0);
  std::set<std::string> kinds;
  if (r.contains("kinds")) {
    if (!r["kinds"].is_array() || r["kinds"].size() > 32)
      throw std::runtime_error("kinds must be an array <=32");
    for (const auto &k : r["kinds"])
      kinds.insert(k.get<std::string>());
  }
  while (!todo.empty()) {
    auto [e, d] = todo.front();
    todo.pop_front();
    if (d >= depth)
      continue;
    auto id = e["id"].get<std::string>();
    auto loc = e.value("location", J{});
    auto anchor = loc.is_object() ? loc.value("anchor_id", std::string{}) : "";
    std::string match = "";
    if (direction != "in")
      match = "(t.source=? OR (?<>'' AND t.source_anchor=?))";
    if (direction == "both")
      match += " OR ";
    if (direction != "out")
      match += "(t.target=? OR (?<>'' AND t.target_anchor=?))";
    Q q(db, "SELECT t.record FROM static_relations t JOIN analysis_heads h ON "
            "h.project=t.project AND h.revision=t.revision WHERE t.project=? "
            "AND (?='' OR t.artifact=?) "
            "AND (" +
                match + ") ORDER BY t.id LIMIT ?");
    int i = 1;
    q.s(i++, p);
    auto artifact = r.value("artifact", std::string{});
    q.s(i++, artifact);
    q.s(i++, artifact);
    if (direction != "in") {
      q.s(i++, id);
      q.s(i++, anchor);
      q.s(i++, anchor);
    }
    if (direction != "out") {
      q.s(i++, id);
      q.s(i++, anchor);
      q.s(i++, anchor);
    }
    q.n(i, limit + 1);
    std::size_t scanned = 0;
    while (q.row()) {
      if (++scanned > limit) {
        partial = true;
        break;
      }
      auto rel = J::parse(q.text(0));
      if (!kinds.empty() && !kinds.contains(rel.value("kind", std::string{})))
        continue;
      auto rid = rel["id"].get<std::string>();
      if (!edgeIds.insert(rid).second)
        continue;
      auto b = brief(rel);
      auto size = b.dump().size();
      if (edges.size() >= limit || bytes + size > budget) {
        partial = true;
        break;
      }
      bytes += size;
      edges.push_back(b);
      for (const auto *side : {"source", "target"}) {
        if (direction == "out" && std::string(side) == "source")
          continue;
        if (direction == "in" && std::string(side) == "target")
          continue;
        auto endpoint = rel.value(std::string(side) + "_entity", J{});
        auto endpointLoc = rel.value(std::string(side) + "_location", J{});
        J f{{"limit", std::min<std::size_t>(limit, 32)}};
        if (r.contains("artifact"))
          f["artifact"] = r["artifact"];
        if (endpointLoc.is_object() && endpointLoc.contains("anchor_id"))
          f["anchor"] = endpointLoc["anchor_id"];
        else if (endpoint.is_string())
          f["id"] = endpoint;
        else
          continue;
        auto linked = store.index_query(p, f);
        if (!linked["next_offset"].is_null())
          partial = true;
        for (auto v : linked["records"])
          node(v, d + 1);
      }
    }
  }
  J out{{"schema",
         op == "packet" ? "indago.evidence-packet.v1" : "indago.graph.v1"},
        {"nodes", nodes},
        {"relationships", edges},
        {"partial", partial},
        {"depth", depth},
        {"direction", direction},
        {"interpretation",
         "Normalized references connect native discoveries; traversal is not a "
         "feasibility, equivalence or causation proof"}};
  if (op == "packet") {
    J claims = J::array(), disagreements = J::array();
    for (const auto &n : nodes) {
      auto c = store.index_query(
          p, {{"category", "claims"}, {"subject", n["id"]}, {"limit", 20}});
      if (!c["next_offset"].is_null())
        partial = true;
      for (const auto &claim : c["records"]) {
        auto size = claim.dump().size();
        if (bytes + size > budget) {
          partial = true;
          break;
        }
        bytes += size;
        claims.push_back(claim);
      }
      auto loc = n.value("location", J{});
      if (loc.is_object()) {
        auto a = loc.value("anchor_id", std::string{});
        if (!a.empty() && anchors.insert(a).second) {
          auto c =
              store.index_query(p, {{"category", "compare"}, {"anchor", a}});
          for (const auto &pair : c["disagreements"]) {
            auto size = pair.dump().size();
            if (bytes + size > budget) {
              partial = true;
              break;
            }
            bytes += size;
            disagreements.push_back(pair);
          }
          partial = partial || c.value("truncated", false);
        }
      }
    }
    out["claims"] = claims;
    out["disagreements"] = disagreements;
    out["partial"] = partial;
    out["omissions"] = {"native payloads: use evidence IDs and JSON pointers",
                        "unknown control/dataflow endpoints remain unknown",
                        "nonselected neighborhoods and runtime windows",
                        "no model-generated summary"};
  }
  // Envelope overhead cannot defeat the caller's byte bound.
  while (out.dump().size() > budget) {
    out["partial"] = true;
    if (out.contains("disagreements") && !out["disagreements"].empty())
      out["disagreements"].erase(out["disagreements"].end() - 1);
    else if (out.contains("claims") && !out["claims"].empty())
      out["claims"].erase(out["claims"].end() - 1);
    else if (!out["relationships"].empty())
      out["relationships"].erase(out["relationships"].end() - 1);
    else if (!out["nodes"].empty())
      out["nodes"].erase(out["nodes"].end() - 1);
    else
      break;
  }
  return out;
}
} // namespace indago::wb
