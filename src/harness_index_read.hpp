#pragma once
#include "harness_scope.hpp"
#include "workbench_db.hpp"

namespace indago {
inline wb::J harness_index_page(const ProjectStore& store,const wb::J& selected,
                                const std::string& operation,wb::J request) {
    using namespace wb;
    keys(request,{"project","artifact","id","kind","backend","revision","name","search","address","anchor","source","target","subject","predicate","offset","limit"});
    if(!std::set<std::string>{"entities","relations","claims","revisions"}.contains(operation))throw std::runtime_error("Unsupported read-only index operation");
    request["artifact"]=selected.at("artifact_sha256");
    request["category"]=operation;
    const auto limit=bound(request,"limit",4,16),offset=bound(request,"offset",0,1000000);
    if(!limit)throw std::runtime_error("Index page requires a positive limit");
    request["limit"]=limit;request["offset"]=offset;
    const auto native=store.index_query(request.at("project").get<std::string>(),request);
    J result{{"schema","indago.investigation-index-page.v1"},{"category",operation},
        {"artifact_sha256",selected.at("artifact_sha256")},{"offset",offset},
        {"records",J::array()},{"representation","indexed descriptors; use evidence/read for native payloads"},
        {"source_verified",false},{"next_offset",native.at("next_offset")}};
    for(const auto& row:native.at("records")){
        J item{{"details_omitted",true}};
        for(const auto* key:{"id","kind","revision","producer","evidence_id","freshness","partial","source_status","source_result_incomplete","projection_partial","subject","predicate","source_entity","target_entity"})
            if(row.contains(key))item[key]=row.at(key);
        for(const auto* key:{"name","native_id","json_pointer"})if(row.contains(key)&&row.at(key).is_string()){
            const auto& text=row.at(key).get_ref<const std::string&>();
            const auto ceiling=std::string_view(key)=="json_pointer"?1024U:256U;
            if(text.size()<=ceiling)item[key]=text;
            else{item[std::string(key)+"_omitted"]=true;item[std::string(key)+"_sha256"]=sha256_text(text);}
        }
        for(const auto* key:{"location","source_location","target_location"})if(row.contains(key)&&row.at(key).is_object()){
            J loc=J::object();for(const auto* field:{"anchor_id","artifact_sha256","address_space","address","rva","file_offset"})if(row.at(key).contains(field))loc[field]=row.at(key).at(field);
            item[key]=std::move(loc);
        }
        result["records"].push_back(item);
        if(result.dump().size()>3800){result["records"].erase(result["records"].end()-1);result["next_offset"]=offset+result["records"].size();break;}
    }
    if(result["records"].empty()&&!native["records"].empty())throw std::runtime_error("Indexed descriptor exceeds packet budget; use an evidence pointer directly");
    result["partial"]=true; // descriptor projection, regardless of collection exhaustion
    return result;
}
}
