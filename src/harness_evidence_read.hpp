#pragma once
#include "harness_scope.hpp"
#include "workbench_db.hpp"
#include <algorithm>
#include <iterator>

namespace indago {
// A bounded projection of native record fields. Nested data stays addressable
// through the original source pointer; omitted fields are never inferred.
inline wb::J evidence_scalar_projection(const wb::J &record) {
    wb::J fields=wb::J::object();
    if(!record.is_object())return fields;
    for(auto it=record.begin();it!=record.end();++it) {
        if(!it.value().is_primitive()||it.value().dump().size()>512)continue;
        fields[it.key()]=it.value();
        if(fields.dump().size()>1024)fields.erase(it.key());
    }
    return fields;
}
// Read one verified immutable native JSON snapshot. JSON pointers are relative
// to that native document, never filesystem paths or authority instructions.
inline wb::J harness_evidence_page(const ProjectStore& store, const wb::J& inv,
                                   const wb::J& request) {
    using namespace wb;
    keys(request,{"project","id","pointer","offset","limit","max_bytes","raw_sha256","projection"});
    const auto projection=request.value("projection",std::string("descriptors"));
    if(projection!="descriptors"&&projection!="scalars")throw std::runtime_error("Evidence projection must be descriptors or scalars");
    const auto evidence_id=request.at("id").get<std::string>();identifier(evidence_id);
    const auto pointer=request.value("pointer",std::string{});
    if(pointer.size()>1024)throw std::runtime_error("Evidence JSON pointer exceeds 1024 bytes");
    const auto offset=bound(request,"offset",0,16*1024*1024);
    const auto limit=bound(request,"limit",8,16);
    const auto text_budget=bound(request,"max_bytes",1024,2048);
    if(!limit||text_budget<4)throw std::runtime_error("Evidence page requires positive limit and at least four text bytes");
    Db db(store.root()/"indago-native.sqlite3");
    Q row(db,"SELECT record,sha FROM evidence WHERE project=? AND id=?");
    if(!row.s(1,inv.at("project").get<std::string>()).s(2,evidence_id).row())throw std::runtime_error("Unknown evidence");
    const auto metadata=J::parse(row.text(0));const auto raw_sha=row.text(1);
    if(!harness_contains_artifact(inv,metadata.at("artifact_sha256")))throw std::runtime_error("Evidence outside investigation scope");
    if(metadata.at("raw_sha256")!=raw_sha)throw std::runtime_error("Evidence metadata hash mismatch");
    if(request.contains("raw_sha256")&&request.at("raw_sha256")!=raw_sha)throw std::runtime_error("Stale evidence snapshot pin");
    J result{{"schema","indago.evidence-page.v1"},{"id",evidence_id},{"artifact_sha256",metadata.at("artifact_sha256")},
        {"raw_sha256",raw_sha},{"revision",metadata.at("revision")},{"producer",metadata.at("producer")},
        {"native_status",metadata.at("status")},{"pointer",pointer},{"offset",offset},{"source_verified",false}};
    const auto raw_path=object(store,raw_sha);
    if(fs::file_size(raw_path)>16*1024*1024){result["partial"]=true;result["omitted"]=true;result["diagnostic"]="Native snapshot exceeds 16 MiB read bound; submit a narrower backend query";return result;}
    const auto bytes=read(raw_path,16*1024*1024);
    if(sha256_text(bytes)!=raw_sha)throw std::runtime_error("Evidence integrity failure");
    const auto native=J::parse(bytes);
    const auto& value=native.at(J::json_pointer(pointer));
    result["source_verified"]=true;result["type"]=value.type_name();
    if(value.is_string()) {
        const auto& text=value.get_ref<const std::string&>();
        if(offset>text.size()||(offset<text.size()&&(static_cast<unsigned char>(text[offset])&0xc0)==0x80))throw std::runtime_error("Text offset must be a UTF-8 byte boundary within the string");
        auto end=std::min(text.size(),offset+text_budget);
        auto boundary=[&]{while(end>offset&&end<text.size()&&(static_cast<unsigned char>(text[end])&0xc0)==0x80)--end;};
        boundary();
        result["offset_unit"]="utf8_bytes";result["total_bytes"]=text.size();
        for(;;){result["text"]=text.substr(offset,end-offset);result["next_offset"]=end<text.size()?J(end):J(nullptr);result["partial"]=offset!=0||end!=text.size();if(result.dump().size()<=4096)break;if(end==offset)throw std::runtime_error("Evidence pointer metadata exceeds packet budget");--end;boundary();}
        if(end==offset&&offset<text.size())throw std::runtime_error("Evidence packet has no room for text; use a shorter pointer");
    } else if(value.is_array()||value.is_object()) {
        if(offset>value.size())throw std::runtime_error("Collection offset outside evidence value");
        result["offset_unit"]="items";result["representation"]="child_descriptors";result["total_items"]=value.size();result["items"]=J::array();
        auto it=value.begin();std::advance(it,offset);auto cursor=offset;
        auto escape=[](const std::string& key){std::string text;for(char c:key)text+=c=='~'?"~0":c=='/'?"~1":std::string(1,c);return text;};
        for(;it!=value.end()&&result["items"].size()<limit;++it,++cursor){
            const auto key=value.is_array()?std::to_string(cursor):it.key();
            J item{{"index",cursor},{"type",it->type_name()}};
            const auto child_pointer=pointer+"/"+escape(key);
            if(child_pointer.size()<=1024){item["pointer"]=child_pointer;if(value.is_object())item["key"]=key;}
            else{item["pointer_omitted"]=true;item["key_sha256"]=sha256_text(key);}
            if(it->is_array()||it->is_object())item["total_items"]=it->size();
            else if(it->is_string())item["total_bytes"]=it->get_ref<const std::string&>().size();
            if(it->is_primitive()&&(!it->is_string()||it->get_ref<const std::string&>().size()<=512)&&it->dump().size()<=512)item["value"]=*it;
            else item["value_omitted"]=true;
            if(projection=="scalars"&&it->is_object()) {
                const auto fields=evidence_scalar_projection(*it);
                if(!fields.empty()) {
                    item["value"]=fields;item["value_projection"]="scalars";
                    item["value_omitted"]=fields!=*it;
                }
            }
            result["items"].push_back(item);
            if(result.dump().size()>3700){result["items"].back().erase("value");result["items"].back()["value_omitted"]=true;if(result.dump().size()>3700){result["items"].erase(result["items"].end()-1);break;}}
        }
        if(cursor==offset&&cursor<value.size())throw std::runtime_error("Evidence pointer metadata exceeds packet budget");
        result["next_offset"]=cursor<value.size()?J(cursor):J(nullptr);result["partial"]=offset!=0||cursor!=value.size();
    } else {
        if(offset)throw std::runtime_error("Scalar evidence has no offset");
        result["value"]=value;result["partial"]=false;result["next_offset"]=nullptr;
    }
    if(result.dump().size()>4096)throw std::runtime_error("Evidence page exceeds packet budget");
    return result;
}
}
