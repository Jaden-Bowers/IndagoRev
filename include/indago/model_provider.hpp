#pragma once
#include "indago/core.hpp"
#include <functional>

namespace indago {
// Provider rejected the request because it exceeds the model context.
class ModelContextError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};
// Transport-level provider failure (network or HTTP).
class ModelTransportError : public std::runtime_error {
public:
  using std::runtime_error::runtime_error;
};
// Provider rate-limited inference (HTTP 429); carries the retry delay.
class ModelRateLimitError : public ModelTransportError {
public:
  std::uint64_t retry_after_ms;
  explicit ModelRateLimitError(std::uint64_t delay = 60000)
      : ModelTransportError("provider HTTP 429; inference rejected, checkpoint retained"),
        retry_after_ms(delay) {}
};
using ModelCancel = std::function<bool()>;
// Injects a model HTTP transport; receives the profile and body but no
// credential. Tests use it to return deterministic protocol responses.
using ModelTransport = std::function<std::string(const nlohmann::json &profile,
                                                 const nlohmann::json &body,
                                                 const ModelCancel &cancel)>;
// Validates and fills defaults in a model profile.
nlohmann::json normalize_model_profile(const nlohmann::json &);
// Returns the JSON schema for model tool calls (optionally finish-only).
nlohmann::json model_tool_schema(bool finish_only = false, bool json_string = false);
// Decodes a raw provider response into normalized content and tool calls.
nlohmann::json decode_model_response(std::string_view wire,
                                     const nlohmann::json &profile);
// Performs one completion round, optionally limited to the finish tool.
nlohmann::json model_complete(const nlohmann::json &profile,
                              const nlohmann::json &messages,
                              const ModelCancel &, ModelTransport = {},
                              bool finish_only = false);
// Sends a provider HTTP request, honoring cancellation.
std::string model_http_request(const nlohmann::json &profile,
                               const nlohmann::json &body, const ModelCancel &);
} // namespace indago
