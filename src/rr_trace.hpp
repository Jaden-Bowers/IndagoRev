#pragma once
#include "indago/core.hpp"
#include <map>
namespace indago::replay {
inline void unlinked_path(const fs::path& path) {
    if(!path.is_absolute())throw std::runtime_error("Replay path must be absolute");
    for(auto p=path;p.has_relative_path();p=p.parent_path())
        if(fs::is_symlink(fs::symlink_status(p)))throw std::runtime_error("Replay paths cannot traverse symbolic links");
}
// rr's packed trace is flat. No archive extraction, external mappings or
// caller-provided path entries are resolved by this projection.
inline nlohmann::json trace_manifest(const fs::path& directory,std::uint64_t budget,bool hashes) {
    unlinked_path(directory);
    std::map<std::string,nlohmann::json> files;
    std::uint64_t bytes=0;
    if(fs::exists(directory))for(const auto& entry:fs::directory_iterator(directory)) {
        const auto name=entry.path().filename().string();
        if(name.size()>255||files.size()>=1024||!fs::is_regular_file(entry.symlink_status()))
            throw std::runtime_error("Trace contains an unsupported entry or exceeds 1024 files");
        const auto size=entry.file_size();
        if(size>67108864||bytes>budget||size>budget-bytes)throw std::runtime_error("Trace byte budget exceeded");
        bytes+=size;
        nlohmann::json record{{"size",size}};
        if(hashes) {
            if(fs::hard_link_count(entry.path())!=1)throw std::runtime_error("Packed trace retains external hard links");
            record["sha256"]=sha256_file(entry.path());
            if(entry.file_size()!=size)throw std::runtime_error("Trace changed during hashing");
        }
        files.emplace(name,std::move(record));
    }
    if(hashes)for(const auto* required:{"version","events","data","mmaps","tasks"})
        if(!files.contains(required))throw std::runtime_error("Packed rr trace is missing a required native stream");
    nlohmann::json manifest{{"schema","indago.rr-trace-manifest.v1"},{"files",files},{"bytes",bytes},{"hashed",hashes}};
    if(hashes)manifest["sha256"]=sha256_text(manifest.dump());
    return manifest;
}
}
