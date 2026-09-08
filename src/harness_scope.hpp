#pragma once
#include "workbench_db.hpp"

namespace indago {
// Roots and derivation grants are operator-declared at creation. Only verified
// receipts can add derived components; discoveries cannot expand authority.
inline wb::J harness_components(const wb::J &inv) {
  auto components =
      inv.contains("scope")
          ? inv.at("scope").at("components")
          : wb::J::array({{{"target_id", inv.at("target_id")},
                           {"artifact_sha256", inv.at("artifact_sha256")}}});
  for (const auto &derived : inv.value("derived_components", wb::J::array()))
    components.push_back(derived);
  return components;
}
inline bool harness_contains_artifact(const wb::J &inv, const wb::J &sha) {
  for (const auto &c : harness_components(inv))
    if (c.at("artifact_sha256") == sha)
      return true;
  return false;
}
inline wb::J harness_select_component(const wb::J &inv, const wb::J &r) {
  if (r.contains("project") && r.at("project") != inv.at("project"))
    throw std::runtime_error("cross-project investigation request");
  const auto components = harness_components(inv);
  if (!r.contains("target_id") && !r.contains("artifact_sha256") &&
      !r.contains("artifact"))
    return {{"target_id", inv.at("target_id")},
            {"artifact_sha256", inv.at("artifact_sha256")}};
  for (const auto &c : components) {
    if ((!r.contains("target_id") || r.at("target_id") == c.at("target_id")) &&
        (!r.contains("artifact_sha256") ||
         r.at("artifact_sha256") == c.at("artifact_sha256")) &&
        (!r.contains("artifact") ||
         r.at("artifact") == c.at("artifact_sha256")))
      return c;
  }
  throw std::runtime_error("cross-scope or mismatched component request");
}
wb::J harness_read_packet(StaticService &, const wb::J &inv,
                          const wb::J &payload);
void harness_check_knowledge(wb::Db &, const wb::J &inv, const wb::J &record);
} // namespace indago
