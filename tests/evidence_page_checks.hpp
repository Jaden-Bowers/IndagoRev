#pragma once
#include "../src/harness_evidence_read.hpp"
#include "indago/service.hpp"

inline void evidence_page_checks(const indago::fs::path& root) {
    using namespace indago;using J=nlohmann::json;
    StaticService service(root);auto& store=service.store();store.create_project("pages");
    atomic_write(root/"fixture.bin","read-only evidence page fixture");auto target=store.import_target("pages",root/"fixture.bin");
    auto job=service.prepare({{"project","pages"},{"backend","xair"},{"operation","inventory"}});
    std::string unicode;for(unsigned i=0;i<300;++i)unicode+="line\n\"\t\xf0\x9f\x94\x8d";
    J native{{"text",unicode},{"objects",J::array()},{"functions",J::array()},{"a/~b",{{"value",42}}}};
    for(unsigned i=0;i<30;++i)native["objects"].push_back({{"index",i},{"huge",std::string(3000,'x')}});
    for(unsigned i=0;i<12;++i)native["functions"].push_back({{"address",hex_address(0x400000+i*16)},{"name",std::string(2000,'f')}});
    auto published=store.publish_result(target,job,"xair",{3,"partial",native.dump()});
    J inv{{"project","pages"},{"target_id",target.id},{"artifact_sha256",target.sha256}};
    J request{{"id",published["evidence_ids"][0]}};
    auto call=[&](J r){return harness_read_packet(service,inv,{{"family","evidence"},{"operation","read"},{"request",r}});};
    std::size_t index_offset=0,seen=0;
    for(unsigned attempt=0;attempt<20;++attempt){
        auto descriptors=harness_read_packet(service,inv,{{"family","index"},{"operation","entities"},{"request",{{"kind","function"},{"offset",index_offset},{"limit",16}}}});
        if(descriptors.dump().size()>4096||descriptors.at("source_verified")!=false)throw std::runtime_error("Index page budget/provenance failure");
        for(const auto& descriptor:descriptors.at("records")){if(descriptor.contains("native")||!descriptor.contains("evidence_id")||descriptor.at("name_omitted")!=true)throw std::runtime_error("Index page lost projection markers");++seen;}
        if(descriptors.at("next_offset").is_null())break;
        auto next=descriptors.at("next_offset").get<std::size_t>();if(next<=index_offset)throw std::runtime_error("Nonprogressing index cursor");index_offset=next;
    }
    if(seen!=12)throw std::runtime_error("Index descriptor paging lost rows");
    auto page=call(request);
    if(!page.at("source_verified").get<bool>()||page.at("native_status")!="partial"||page.at("representation")!="child_descriptors")throw std::runtime_error("Evidence page provenance missing");
    bool escaped=false;for(const auto& item:page.at("items"))if(item.at("pointer")=="/a~1~0b")escaped=true;
    if(!escaped)throw std::runtime_error("Evidence JSON pointer escaping failed");
    request["pointer"]="/a~1~0b/value";if(call(request).at("value")!=42)throw std::runtime_error("Escaped scalar selection failed");
    request["pointer"]="/text";request["max_bytes"]=19;std::string collected;std::size_t cursor=0;
    for(unsigned attempts=0;attempts<1000;++attempts){request["offset"]=cursor;page=call(request);if(page.dump().size()>4096)throw std::runtime_error("Evidence packet overflow");collected+=page.at("text").get<std::string>();if(page.at("next_offset").is_null())break;auto next=page.at("next_offset").get<std::size_t>();if(next<=cursor)throw std::runtime_error("Nonprogressing evidence text cursor");cursor=next;request["raw_sha256"]=page.at("raw_sha256");}
    if(collected!=unicode)throw std::runtime_error("UTF-8 evidence text paging lost bytes");
    request["pointer"]="/objects";request["offset"]=0;request["limit"]=3;page=call(request);
    if(page.at("items").size()!=3||page.at("next_offset")!=3||page.at("items")[0].contains("value"))throw std::runtime_error("Large array child was inlined or paging failed");
    auto reject=[&](J r){bool failed=false;try{call(r);}catch(const std::exception&){failed=true;}if(!failed)throw std::runtime_error("Invalid evidence page request accepted");};
    request["raw_sha256"]=std::string(64,'0');reject(request);request.erase("raw_sha256");
    request["pointer"]="/text";request["offset"]=8;reject(request); // continuation byte of first emoji
    request["pointer"]="/missing";request["offset"]=0;reject(request);
    request["pointer"]="";inv["artifact_sha256"]=std::string(64,'0');reject(request);inv["artifact_sha256"]=target.sha256;
    atomic_write(wb::object(store,published.at("raw_sha256").get<std::string>()),"{}");reject(request);
}
