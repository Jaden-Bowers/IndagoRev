#pragma once
#include "indago/core.hpp"
#include <functional>

namespace indago {
class ModelContextError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};
class ModelTransportError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};
class ModelRateLimitError : public ModelTransportError {
public:
  std::uint64_t retry_after_ms;
  explicit ModelRateLimitError(std::uint64_t delay = 60000)
      : ModelTransportError("provider HTTP 429; inference rejected, checkpoint retained"),
        retry_after_ms(delay) {}
};
using ModelCancel = std::function<bool()>;
// Receives no credential. Tests inject deterministic protocol responses here.
using ModelTransport = std::function<std::string(const nlohmann::json &profile,
                                                 const nlohmann::json &body,
                                                 const ModelCancel &cancel)>;
nlohmann::json normalize_model_profile(const nlohmann::json &);
nlohmann::json model_tool_schema(bool finish_only = false, bool json_string = false);
nlohmann::json decode_model_response(std::string_view wire,
                                     const nlohmann::json &profile);
nlohmann::json model_complete(const nlohmann::json &profile,
                              const nlohmann::json &messages,
                              const ModelCancel &, ModelTransport = {},
                              bool finish_only = false);
std::string model_http_request(const nlohmann::json &profile,
                               const nlohmann::json &body, const ModelCancel &);
} // namespace indago
