#pragma once
#include "workbench_db.hpp"
#include "indago/runtime.hpp"
#if INDAGO_HAS_XAIR
#include <xair/xair_binary.h>
#endif
#include <sstream>

namespace indago {
inline wb::J harness_artifact_page(const ProjectStore &store, const wb::J &component,
                                   const wb::J &request) {
  using namespace wb;
  keys(request, {"project", "offset", "address", "max_bytes", "raw_sha256"});
  if (request.contains("address") && request.contains("offset"))
    throw std::runtime_error("Select a virtual address or a file offset, not both");
  const auto length = bound(request, "max_bytes", 256, 1024);
  if (!length) throw std::runtime_error("Artifact page must request at least one byte");
  const auto target = store.target(request.at("project").get<std::string>(),
                                   component.at("target_id").get<std::string>(), true);
  const auto sha = component.at("artifact_sha256").get<std::string>();
  if (request.contains("raw_sha256") && request.at("raw_sha256") != sha)
    throw std::runtime_error("Artifact source pin mismatch");
  const auto raw = read(target.object_path, 64 * 1024 * 1024);
  if (sha256_text(raw) != sha) throw std::runtime_error("Artifact source integrity failure");
  std::uint64_t offset = bound(request, "offset", 0, 64 * 1024 * 1024);
  std::uint64_t available = offset <= raw.size() ? raw.size() - offset : 0;
  J mapping = nullptr;
  if (request.contains("address")) {
#if INDAGO_HAS_XAIR
    struct Image {
      xair_binary_view view{};
      ~Image() { xair_binary_view_destroy(&view); }
    } image;
    xair_binary_load_options options{};
    xair_binary_load_options_init(&options);
    options.analysis.max_bytes = 64 * 1024 * 1024;
    options.analysis.max_memory = 128 * 1024 * 1024;
    options.analysis.max_wall_time = 5000;
    xair_analysis_result result{};
    xair_diagnostic diagnostic{};
    if (xair_binary_view_load_bytes_ex(raw.data(), raw.size(), &options, &image.view,
                                     &result, &diagnostic) != XAIR_OK)
      throw std::runtime_error("Native file mapping unavailable; use a file offset");
    const auto address = runtime_number(request.at("address").get<std::string>());
    const auto *segment = xair_binary_view_find_segment(&image.view, address, 0);
    if (!segment || address < segment->va || address - segment->va >= segment->file_size)
      throw std::runtime_error("Address has no file-backed mapping; runtime or zero-filled bytes are not artifact bytes");
    const auto delta = address - segment->va;
    if (segment->file_offset > raw.size() || delta > raw.size() - segment->file_offset)
      throw std::runtime_error("Native mapping exceeds artifact");
    offset = segment->file_offset + delta;
    available = std::min<std::uint64_t>(segment->file_size - delta, raw.size() - offset);
    mapping = {{"virtual_address", request.at("address")}, {"segment_va", segment->va},
               {"file_offset", offset}, {"source", "XAIR binary loader; static file-backed mapping"}};
#else
    throw std::runtime_error("Virtual-address artifact reads require XAIR");
#endif
  }
  if (!available) throw std::runtime_error("Artifact offset is outside readable bytes");
  const auto count = std::min<std::uint64_t>(length, available);
  const auto bytes = raw.substr(static_cast<std::size_t>(offset), static_cast<std::size_t>(count));
  static constexpr char hex[] = "0123456789abcdef";
  std::string encoded;
  for (const unsigned char value : bytes) {
    encoded.push_back(hex[value >> 4]); encoded.push_back(hex[value & 15]);
  }
  return {{"schema", "indago.artifact-page.v1"}, {"artifact_sha256", sha},
          {"raw_sha256", sha}, {"source_verified", true}, {"offset", offset},
          {"pointer", "/artifact_bytes"}, {"offset_unit", "file_bytes"}, {"length", count},
          {"hex", encoded}, {"slice_sha256", sha256_text(bytes)}, {"mapping", mapping},
          {"next_offset", count < available ? J(offset + count) : J(nullptr)},
          {"trust", "Exact artifact bytes; no runtime observation or semantic proof"}};
}
}
