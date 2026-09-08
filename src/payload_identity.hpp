#pragma once
#include "indago/core.hpp"
#include <map>
#include <stdexcept>
namespace indago::payload {
inline std::string_view group_for(std::string_view name) {
    if(name.starts_with("ghidra/"))return "ghidra";
    if(name.starts_with("ilspy/"))return "ilspy";
    if(name.starts_with("enrichment/"))return "enrichment";
    if(name.starts_with("network/"))return "network";
    if(name.starts_with("replay/"))return "replay";
    return "runtime";
}
// The full executable still embeds the entire manifest. Cache identity depends
// only on the requested group, so an unrelated tool update cannot duplicate it.
template<class Entries>
std::string group_identity(const Entries& entries,std::string_view group) {
    if(group!="runtime"&&group!="ghidra"&&group!="ilspy"&&group!="enrichment"&&group!="network"&&group!="replay")throw std::runtime_error("Unknown engine payload group");
    std::map<std::string,std::string> selected;
    for(const auto& entry:entries){
        if(!entry.name)break;
        if(group_for(entry.name)!=group)continue;
        if(!selected.emplace(entry.name,entry.sha).second)throw std::runtime_error("Duplicate engine payload name");
    }
    if(selected.empty())throw std::runtime_error("Requested engine payload group is unavailable");
    nlohmann::json manifest{{"schema","indago.engine-group.v1"},{"group",group},{"files",selected}};
    return sha256_text(manifest.dump());
}
}
