#include "indago/runtime.hpp"
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <unistd.h>
#endif
#include <fstream>
#include <mutex>
#include <set>
#include "engine_payload.hpp"
#include "payload_identity.hpp"
#include "payload_codec.hpp"

namespace indago {
namespace {
fs::path payload_cache_base(){
#ifdef _WIN32
  wchar_t local[32768];
  const auto n=GetEnvironmentVariableW(L"LOCALAPPDATA",local,32768);
  if(!n||n>=32768||!fs::path(local).is_absolute())throw std::runtime_error("Absolute LOCALAPPDATA unavailable");
  return fs::path(local)/"IndagoRev"/"engines"/"groups-v1";
#else
  const auto* directory=std::getenv("HOME");
  if(!directory||!fs::path(directory).is_absolute())throw std::runtime_error("Absolute HOME unavailable for engine cache");
  return fs::path(directory)/".cache"/"indago"/"engines"/"groups-v1";
#endif
}
}
RuntimeJson bundled_payload_inventory(){
  using J=RuntimeJson;
  J groups=J::array();std::uint64_t total=0,expanded=0;
  for(const auto* group:{"runtime","ghidra","ilspy","enrichment","network","replay"}){
    std::uint64_t bytes=0,raw=0,count=0,compressed=0;
    for(const auto& entry:engine_payload){if(!entry.name)break;if(payload::group_for(entry.name)==group){bytes+=entry.stored_size;raw+=entry.size;++count;if(entry.compressed)++compressed;}}
    J item{{"group",group},{"available",count!=0},{"files",count},{"embedded_bytes",bytes},{"expanded_bytes",raw},{"compressed_files",compressed}};
    if(count){const auto identity=payload::group_identity(engine_payload,group);item["manifest_sha256"]=identity;
      item["cache_directory"]=(payload_cache_base()/(std::string(group)+"-"+identity)).string();}
    groups.push_back(std::move(item));total+=bytes;expanded+=raw;
  }
  return {{"schema","indago.payload-inventory.v1"},{"bundle_sha256",engine_bundle_sha},{"groups",groups},
    {"embedded_payload_bytes",total},{"expanded_payload_bytes",expanded},{"cache_inspected",false},{"cache_extraction_performed",false},
    {"scope","embedded worker files only; excludes native code, build SDKs, legacy caches and filesystem overhead"}};
}
// Payload files are immutable by content. Never search CWD, PATH or an
// installed SDK.
fs::path bundled_engines(std::string_view group) {
  static std::mutex verification_mutex;
  static std::set<std::string> verified;
  std::lock_guard verification_lock(verification_mutex);
  const auto cache_name=std::string(group)+"-"+payload::group_identity(engine_payload,group);
  const auto root=payload_cache_base()/cache_name;
  auto verification_key=root.string()+":"+std::string(group);
  if(verified.contains(verification_key))return root;
  auto reject_linked_parents=[](const fs::path& path){
  for (auto parent = path; parent.has_relative_path();
       parent = parent.parent_path()) {
#ifdef _WIN32
    auto attrs = GetFileAttributesW(parent.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES &&
        (attrs & FILE_ATTRIBUTE_REPARSE_POINT))
      throw std::runtime_error("engine cache cannot use reparse points");
#else
    if (fs::is_symlink(parent))
      throw std::runtime_error("engine cache cannot use symlinks");
#endif
  }
  };
  reject_linked_parents(root);
  fs::create_directories(root);
  reject_linked_parents(root);
  for (auto &entry : engine_payload) {
    if (!entry.name)
      break;
    const auto payload_name=std::string_view(entry.name);
    const auto payload_group=payload::group_for(payload_name);
    if (payload_group != group) continue;
#ifdef _WIN32
    // Extraction paths can exceed MAX_PATH in a full Ghidra distribution.
    // Keep extended paths local to file I/O; return ordinary paths to Java.
    auto file = (fs::path(L"\\\\?\\" + root.wstring()) / entry.name).make_preferred();
#else
    auto file = root / entry.name;
#endif
    reject_linked_parents(file.parent_path());
    fs::create_directories(file.parent_path());
    reject_linked_parents(file.parent_path());
    if (fs::exists(file)) {
#ifdef _WIN32
      if (GetFileAttributesW(file.c_str()) & FILE_ATTRIBUTE_REPARSE_POINT)
        throw std::runtime_error("engine payload cannot be a reparse point");
#else
      if (fs::is_symlink(file))
        throw std::runtime_error("engine payload cannot be a symlink");
#endif
      if (sha256_file(file) == entry.sha)
        continue;
      throw std::runtime_error("engine payload hash mismatch: " +
                               file.string());
    }
#ifdef _WIN32
    auto resource = FindResourceW(nullptr, MAKEINTRESOURCEW(entry.id),
                                  MAKEINTRESOURCEW(10));
    auto loaded = resource ? LoadResource(nullptr, resource) : nullptr;
    auto data = loaded ? LockResource(loaded) : nullptr;
    auto size = resource ? SizeofResource(nullptr, resource) : 0;
#else
    auto data = entry.data;
    auto size = entry.stored_size;
#endif
    if(size!=entry.stored_size)throw std::runtime_error("Embedded payload storage size mismatch");
    if ((!data || !size) && std::string_view(entry.sha) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
      throw std::runtime_error("embedded runtime payload missing");
    auto temp = file.parent_path() /
                (file.filename().string() + "." + make_id("extract"));
    struct TemporaryExtraction {
      fs::path path;
      ~TemporaryExtraction() {
        std::error_code ignored;
        fs::remove(path, ignored);
      }
    } temporary_extraction{temp};
    {
      std::ofstream stream(temp, std::ios::binary);
      payload::decode(stream,{static_cast<const unsigned char*>(data),size},entry.size,entry.compressed);
      stream.close();
      if (!stream || sha256_file(temp) != entry.sha)
        throw std::runtime_error("engine extraction failed: " + std::string(entry.name) + " expected " + entry.sha + " size " + std::to_string(size));
    }
    // No replacement of an existing file: another worker may be extracting too.
#ifdef _WIN32
    bool published =
        MoveFileExW(temp.c_str(), file.c_str(), MOVEFILE_WRITE_THROUGH) != 0;
#else
    fs::permissions(temp, fs::perms::owner_all);
    bool published = ::link(temp.c_str(), file.c_str()) == 0;
    fs::remove(temp);
#endif
    if (!published) {
      fs::remove(temp);
      if (!fs::exists(file) || sha256_file(file) != entry.sha)
        throw std::runtime_error("engine payload publication failed");
    }
  }
  verified.insert(verification_key);
  return root;
}
fs::path bundled_dbgeng() {
  return bundled_engines() / "dbgeng" / "dbgeng.dll";
}
} // namespace indago
