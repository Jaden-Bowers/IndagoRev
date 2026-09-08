#include "indago/runtime.hpp"
#include "indago/service.hpp"
#include <algorithm>

namespace indago {
namespace {
using J = RuntimeJson;
std::string decode(const J &memory) {
  const auto hex = memory.at("hex").get<std::string>();
  if (hex.empty() || hex.size() > 131072 || hex.size() % 2 ||
      hex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
    throw std::runtime_error("capture has no valid bounded bytes");
  std::string bytes;
  for (size_t i = 0; i < hex.size(); i += 2)
    bytes += static_cast<char>(std::stoul(hex.substr(i, 2), nullptr, 16));
  if (memory.at("size").get<size_t>() != bytes.size())
    throw std::runtime_error("capture byte count mismatch");
  return bytes;
}
// A single-region ELF container for analysis ONLY. No reconstructed headers,
// guessed imports, unobserved padding within the region, or executable promise.
std::string analysis_image(std::string_view bytes, uint64_t address, bool x86) {
  if (address > UINT64_MAX - bytes.size() ||
      (x86 && address + bytes.size() > 0x100000000ULL))
    throw std::runtime_error("capture address overflow");
  std::string out(4096 + bytes.size(), '\0');
  auto put = [&](size_t at, uint64_t value, size_t width) {
    for (size_t i = 0; i < width; ++i)
      out.at(at + i) = static_cast<char>(value >> (i * 8));
  };
  out.replace(0, 4,
              "\x7f"
              "ELF",
              4);
  put(4, x86 ? 1 : 2, 1);
  put(5, 1, 1);
  put(6, 1, 1);
  put(16, 2, 2);
  put(18, x86 ? 3 : 62, 2);
  put(20, 1, 4);
  if (x86) {
    put(24, address, 4);
    put(28, 52, 4);
    put(40, 52, 2);
    put(42, 32, 2);
    put(44, 1, 2);
    put(52, 1, 4);
    put(56, 4096, 4);
    put(60, address, 4);
    put(64, address, 4);
    put(68, bytes.size(), 4);
    put(72, bytes.size(), 4);
    put(76, 5, 4);
    put(80, 1, 4);
  } else {
    put(24, address, 8);
    put(32, 64, 8);
    put(52, 64, 2);
    put(54, 56, 2);
    put(56, 1, 2);
    put(64, 1, 4);
    put(68, 5, 4);
    put(72, 4096, 8);
    put(80, address, 8);
    put(88, address, 8);
    put(96, bytes.size(), 8);
    put(104, bytes.size(), 8);
    put(112, 1, 8);
  }
  out.replace(4096, bytes.size(), bytes);
  return out;
}
} // namespace
RuntimeJson runtime_code_epoch(const J &session, J &location, const J &memory,
                               std::string_view method) {
  if (memory.value("size", size_t{}) == 0)
    return nullptr;
  auto bytes = decode(memory);
  J epoch{{"id", make_id("epoch")},
          {"session_id", session.at("id")},
          {"process_id", session.at("process_id")},
          {"address_space_id",
           session.value("address_space_id", session.at("process_id"))},
          {"module_id", location.value("module_id", J{})},
          {"address", memory.at("address")},
          {"size", bytes.size()},
          {"requested", memory.value("requested", J(bytes.size()))},
          {"bytes_sha256", sha256_text(bytes)},
          {"capture_method", method},
          {"observed_at", utc_timestamp()},
          {"coverage", "one contiguous read; no missing bytes synthesized"},
          {"continuity", "point observation only; equal hashes do not prove "
                         "unchanged intervening execution"}};
  if (memory.contains("timestamp_ms")) {
    epoch["producer_timestamp_ms"] = memory["timestamp_ms"];
    epoch["producer_clock_domain"] = memory.value("clock_domain", "unknown");
    epoch["producer_sequence"] = memory.value("sequence", J{});
  }
  if (memory.contains("read_interval_unix_ms")) epoch["read_interval_unix_ms"] = memory["read_interval_unix_ms"];
  location["code_epoch_id"] = epoch["id"];
  location["runtime_location_id"] =
      "rloc_" +
      sha256_text(J::array({session.at("id"), epoch["address_space_id"],
                            session.at("process_id"), epoch["module_id"],
                            memory.at("address"), epoch["id"]})
                      .dump());
  return epoch;
}
RuntimeJson runtime_reanalyze(ProjectStore &store, const J &session,
                              const J &observation, const J &request) {
  const auto &data = observation.at("data");
  auto selected = request.value("backend", std::string("xair"));
  if (selected != "xair" && selected != "ghidra" && selected != "both")
    throw std::runtime_error(
        "reanalysis backend must be xair, ghidra, or both");
  const auto &memory = data.at("code_bytes");
  const auto &epoch = data.at("code_epoch");
  auto bytes = decode(memory);
  if (sha256_text(bytes) != epoch.at("bytes_sha256").get<std::string>())
    throw std::runtime_error("code epoch integrity mismatch");
  auto project = session.at("project").get<std::string>();
  auto address = runtime_number(memory.at("address"));
  auto arch = data.at("arch").get<std::string>();
  if (arch != "x86" && arch != "x64")
    throw std::runtime_error("unsupported captured architecture");
  auto image = analysis_image(bytes, address, arch == "x86");
  J regions=J::array({{{"code_bytes",memory},{"code_epoch",epoch},{"location",data.at("location")}}});
  for(const auto &region:data.value("code_regions",J::array())) {
    if(data.value("capture_group_id","").empty()||region.value("capture_group_id","")!=data.value("capture_group_id",""))throw std::runtime_error("regions do not share a stopped capture group");
    if(region.at("code_epoch").is_null())throw std::runtime_error("unreadable code region has no epoch");
    regions.push_back(region);
  }
  if(regions.size()>17)throw std::runtime_error("region count exceeds budget");
  J mappings=J::array();
  size_t payload=4096;
  if(regions.size()>1) {
    image.resize(4096);
    auto put=[&](size_t at,uint64_t value,size_t width){for(size_t i=0;i<width;++i)image.at(at+i)=static_cast<char>(value>>(i*8));};
    const bool x86=arch=="x86";put(x86?44:56,regions.size(),2);
    size_t index=0;
    for(const auto &region:regions){const auto &m=region.at("code_bytes");auto region_bytes=decode(m);auto start=runtime_number(m.at("address"));
      if(region_bytes.empty()||sha256_text(region_bytes)!=region.at("code_epoch").at("bytes_sha256").get<std::string>())throw std::runtime_error("region byte identity mismatch");
      if(start>UINT64_MAX-region_bytes.size()||(x86&&start+region_bytes.size()>0x100000000ULL)||payload+region_bytes.size()>4096+65536)throw std::runtime_error("region image budget/extent exceeded");
      for(const auto &prior:mappings){auto begin=runtime_number(prior.at("runtime_address")),end=begin+prior.at("size").get<uint64_t>();if(start<end&&start+region_bytes.size()>begin)throw std::runtime_error("overlapping captured regions require explicit selection; not silently merged");}
      size_t header=x86?52+32*index:64+56*index;
      put(header,1,4);
      if(x86){put(header+4,payload,4);put(header+8,start,4);put(header+12,start,4);put(header+16,region_bytes.size(),4);put(header+20,region_bytes.size(),4);put(header+24,5,4);put(header+28,1,4);}
      else {put(header+4,5,4);put(header+8,payload,8);put(header+16,start,8);put(header+24,start,8);put(header+32,region_bytes.size(),8);put(header+40,region_bytes.size(),8);put(header+48,1,8);}
      mappings.push_back({{"runtime_address",hex_address(start)},{"analysis_address",hex_address(start)},{"file_offset",payload},{"size",region_bytes.size()},{"code_epoch",region.at("code_epoch")}});
      image+=region_bytes;payload+=region_bytes.size();++index;
    }
  }else mappings.push_back({{"runtime_address",hex_address(address)},{"analysis_address",hex_address(address)},{"file_offset",4096},{"size",bytes.size()},{"code_epoch",epoch}});
  auto directory = store.root() / "staging" / make_id("capture");
  fs::create_directories(directory);
  auto raw_path = directory / "observed.bin",
       image_path = directory / "analysis-only.elf";
  atomic_write(raw_path, bytes);
  atomic_write(image_path, image);
  auto raw = store.import_target(project, raw_path);
  std::vector<TargetRecord> extra_raw;
  for(size_t i=1;i<regions.size();++i){auto path=directory/("region-"+std::to_string(i)+".bin");atomic_write(path,decode(regions[i].at("code_bytes")));extra_raw.push_back(store.import_target(project,path));mappings[i]["raw_artifact_sha256"]=extra_raw.back().sha256;fs::remove(path);}
  mappings[0]["raw_artifact_sha256"]=raw.sha256;
  auto target = store.import_target(project, image_path);
  J lineage{
      {"schema", "indago.capture-derivation.v1"},
      {"kind", regions.size()==1?"synthetic_single_region_analysis_image":"synthetic_stopped_region_set_analysis_image"},
      {"regions",mappings},
      {"capture_group_id",data.value("capture_group_id","")},
      {"temporal_compatibility","only regions from the same stopped capture; not atomic against external shared-memory writers"},
      {"session_id", session.at("id")},
      {"source_observation_id", observation.at("id")},
      {"source_observation_sha256", observation.at("sha256")},
      {"code_epoch", epoch},
      {"source_location", data.at("location")},
      {"raw_artifact_sha256", raw.sha256},
      {"artifact_sha256", target.sha256},
      {"target_id", target.id},
      {"mapping",
       {{"runtime_address", hex_address(address)},
        {"analysis_address", hex_address(address)},
        {"file_offset", 4096},
        {"size", bytes.size()}}},
      {"synthesized",
       {"ELF header", "RX load segments for explicitly captured code ranges",
        "entry at requested capture start"}},
      {"limitations",
       {"not a reconstructed runnable image", "no imports or external memory",
        "entry may not be a real function start",
        "capture coherence limited to backend read guarantees"}},
      {"capture_status", memory.value("status", "partial")}};
  store.record_derivation(target, lineage);
  store.record_derivation(raw, lineage);
  for(const auto &record:extra_raw)store.record_derivation(record,lineage);
  fs::remove(raw_path);
  fs::remove(image_path);
  fs::remove(directory);
  StaticService service(store.root());
  J analyses = J::array();
  bool complete = memory.value("status", "partial") == "completed";
  for(const auto &region:regions)complete=complete&&region.at("code_bytes").value("status","partial")=="completed";
  for (auto backend : {"xair", "ghidra"}) {
    if (selected != "both" && selected != backend)
      continue;
    for (auto operation :
         (std::string(backend) == "xair"
              ? std::vector<std::string>{"inventory", "cfg", "semantic"}
              : std::vector<std::string>{"import", "decompile", "tokens",
                                         "cfg"})) {
      J action{{"project", project},
               {"target_id", target.id},
               {"backend", backend},
               {"operation", operation},
               {"budget",
                {{"wall_ms", request.value("timeout_ms", 60000)},
                 {"max_items", 256},
                 {"output_bytes", 1048576}}}};
      if (operation != "inventory" && operation != "import")
        action["address"] = hex_address(address);
      auto job = service.prepare(action);
      auto result = service.execute(job);
      complete = complete && result.value("status", "failed") == "completed";
      result.erase("data");
      analyses.push_back(result);
    }
  }
  return {{"status", complete ? "completed" : "partial"},
          {"derivation", lineage},
          {"analyses", analyses}};
}
} // namespace indago
