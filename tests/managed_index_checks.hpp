#pragma once
#include "indago/static_index.hpp"
#include "indago/service.hpp"

inline void managed_index_checks(const indago::fs::path& root) {
    using namespace indago;
    using J=nlohmann::json;
    StaticService service(root);
    service.store().create_project("managed");
    atomic_write(root/"fixture.bin","compile-free metadata identity fixture");
    auto target=service.store().import_target("managed",root/"fixture.bin");
    J request{{"project","managed"},{"backend","ilspy"},{"operation","methods"}};
    const auto job=service.prepare(request);
    J method{{"token","0x06000001"},{"name","M"},{"location",{{"address_space","managed_metadata"},{"address","0x06000001"}}}};
    auto index=normalize_static(target,job,"ilspy","ev_test",{{"methods",J::array({method})}},{{"image_base","0x400000"}});
    const auto& entity=index.at("entities").at(0);
    if(entity.at("kind")!="managed_method"||entity.at("native_id")!="0x06000001"||entity.at("location").contains("rva"))
        throw std::runtime_error("Managed token identity became a native VA");
    auto native=normalize_static(target,job,"xair","ev_native",{{"functions",J::array({{{"address","0x06000001"},{"name","native"}}})}},J::object());
    if(native.at("entities").at(0).at("location").at("anchor_id")==entity.at("location").at("anchor_id"))
        throw std::runtime_error("Managed and native address spaces alias");
    service.store().cancel_job("managed",job.at("id").get<std::string>());
    if(service.execute(job).at("status")!="cancelled")throw std::runtime_error("Managed prelaunch cancellation failed");
    request["arguments"]={{"offset",-1}};
    bool rejected=false;try{service.normalize(request);}catch(const std::exception&){rejected=true;}
    if(!rejected)throw std::runtime_error("Negative managed pagination accepted");
}
