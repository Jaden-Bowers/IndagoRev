#pragma once
#include "indago/service.hpp"
inline void offline_contract_checks(const indago::fs::path& root){
    using namespace indago;using J=nlohmann::json;
    StaticService service(root);service.store().create_project("offline");
    atomic_write(root/"fixture.bin","not a packet capture or executable");
    service.store().import_target("offline",root/"fixture.bin");
    for(const auto* backend:{"lief","wireshark"}){
        J request{{"project","offline"},{"backend",backend},{"operation",std::string_view(backend)=="lief"?"sections":"packets"}};
        const auto job=service.prepare(request);service.store().cancel_job("offline",job.at("id").get<std::string>());
        if(service.execute(job).at("status")!="cancelled")throw std::runtime_error("Offline adapter cancellation before dispatch failed");
        for(const auto& bad:J::array({J{{"offset",-1}},J{{"offset",65537}},J{{"offset","0"}},J{{"script","unexpected"}}})){
            auto invalid=request;invalid["arguments"]=bad;bool rejected=false;
            try{(void)service.normalize(invalid);}catch(const std::exception&){rejected=true;}
            if(!rejected)throw std::runtime_error("Offline adapter accepted invalid bounded arguments");
        }
        auto addressed=request;addressed["address"]="0x401000";bool rejected=false;
        try{(void)service.normalize(addressed);}catch(const std::exception&){rejected=true;}
        if(!rejected)throw std::runtime_error("Offline metadata adapter accepted a program address");
    }
}
