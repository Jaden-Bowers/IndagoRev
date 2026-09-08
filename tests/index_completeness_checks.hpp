#pragma once
#include "indago/service.hpp"
inline void index_completeness_checks(const indago::fs::path& root){
    using namespace indago;using J=nlohmann::json;
    StaticService service(root);auto& store=service.store();store.create_project("completeness");
    atomic_write(root/"input.bin","compile-free bounded result fixtures");
    const auto target=store.import_target("completeness",root/"input.bin");
    const J request{{"project","completeness"},{"backend","xair"},{"operation","inventory"}};
    // Native verdict and transport/publication status intentionally differ.
    const J native{{"status","native-fixture-verdict"},{"functions",J::array({{{"name","f"},{"address","0x1000"}}})}};
    auto publish=[&](const std::string& status){
        const auto job=service.prepare(request);auto payload=native;
        if(status!="partial")payload["program"]={{"image_base","0x1000"},{"segments",J::array({{{"va","0x1000"},{"file_offset",status=="failed"?"0x99":"0x10"},{"file_size",64}}})}};
        return store.publish_result(target,job,"xair",{result_exit_code(status),status,payload.dump()});
    };
    const auto complete=publish("completed");
    auto partial=publish("partial");
    if(complete["index"]["partial"]!=false||partial["index"]["partial"]!=true)throw std::runtime_error("Publication completeness lost in index");
    const auto failed=publish("failed");
    auto verify=[&]{
        const auto current=store.index_query("completeness",{{"category","entities"},{"kind","function"}});
        if(current["records"].size()!=1)throw std::runtime_error("Failed retry replaced usable index view");
        const auto& row=current["records"][0];
        if(row["revision"]!=partial["result_revision"]||row["source_status"]!="partial"||row["partial"]!=true||row["projection_partial"]!=false)
            throw std::runtime_error("Source incompleteness and projection incompleteness conflated");
        if(row["location"]["file_offset"]!="0x10"||row["location"]["mapping_evidence_id"]!=complete["evidence_ids"][0])
            throw std::runtime_error("Failed retry poisoned later layout evidence");
        const auto revision=store.index_query("completeness",{{"category","revisions"},{"revision",failed["result_revision"]}});
        if(revision["records"][0]["source_status"]!="failed"||revision["records"][0]["freshness"]!="superseded")
            throw std::runtime_error("Failed publication became current during indexing");
        const auto evidence=store.evidence("completeness",partial["evidence_ids"][0].get<std::string>());
        if(evidence["evidence"][0]["native_result"]!=native)throw std::runtime_error("Index metadata rewrote native verdict");
    };
    verify();partial=publish("partial");verify();store.reindex("completeness");verify();
}
