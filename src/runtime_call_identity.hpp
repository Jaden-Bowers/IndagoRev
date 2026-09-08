#pragma once
#include "indago/runtime.hpp"

namespace indago {
// Observation-token pairing only. This is neither network reassembly nor an
// assertion about delivery, OS handle lifetime or target-clock ordering.
inline RuntimeJson advance_api_call_identity(const RuntimeJson &previous,
                                             const RuntimeJson &data,
                                             const std::string &kind,
                                             const RuntimeJson &observation) {
  using J = RuntimeJson;
  if (kind != "api_enter" && kind != "api_leave")
    throw std::runtime_error(
        "API identity requires entry or return observation");
  const auto &payload = data.at("native").at("payload");
  J call{{"id", data.at("call_id")},
         {"api", payload.at("api")},
         {"process_id", data.value("process_id", J(nullptr))},
         {"thread_instance", payload.value("thread_instance", J(nullptr))},
         {"entry_observation", nullptr},
         {"return_observation", nullptr},
         {"conflicting_observations", false},
         {"duplicate_observations", 0},
         {"identity_scope", "Frida collection-local API invocation token"},
         {"network_delivery_proven", false}};
  if (!previous.is_null()) {
    if (previous.at("id") != data.at("call_id"))
      throw std::runtime_error("API identity token differs from prior record");
    call = previous;
  }
  const auto field =
      kind == "api_enter" ? "entry_observation" : "return_observation";
  if (call.at("api") != payload.at("api") ||
      call.at("process_id") != data.value("process_id", J(nullptr)) ||
      call.at("thread_instance") !=
          payload.value("thread_instance", J(nullptr)))
    call["conflicting_observations"] = true;
  if (!call.at(field).is_null())
    call["duplicate_observations"] =
        call.at("duplicate_observations").get<std::uint64_t>() + 1;
  else
    call[field] = observation;
  call["pair_complete"] = !call.at("entry_observation").is_null() &&
                          !call.at("return_observation").is_null() &&
                          call.at("conflicting_observations") == false &&
                          call.at("duplicate_observations") == 0;
  return call;
}
} // namespace indago
