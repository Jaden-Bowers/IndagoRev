#include "indago/static_index.hpp"
#include <charconv>
#include <map>
#include <set>
#include <functional>
namespace indago {
using Json=nlohmann::json;
namespace {
std::string id(std::string_view prefix,const Json& key){return std::string(prefix)+"_"+sha256_text(key.dump());}
std::optional<std::uint64_t> address(const Json& v){
    if(v.is_number_unsigned())return v.get<std::uint64_t>();
    if(!v.is_string())return {};
    auto s=v.get<std::string>();if(s.starts_with("0x"))s.erase(0,2);else return {};
    std::uint64_t n{};auto r=std::from_chars(s.data(),s.data()+s.size(),n,16);if(r.ec!=std::errc{}||r.ptr!=s.data()+s.size())return {};return n;
}
std::string scalar(const Json& v){return v.is_string()?v.get<std::string>():v.is_primitive()&&!v.is_null()?v.dump():"";}
std::string pointer_key(std::string s){std::string out;for(char c:s)out+=c=='~'?"~0":c=='/'?"~1":std::string(1,c);return out;}
}
Json normalize_static(const TargetRecord& target,const Json& job,std::string_view backend,std::string_view evidence,const Json& native,const Json& layout){
    Json out{{"entities",Json::array()},{"relations",Json::array()},{"claims",Json::array()},{"partial",false}};
    const auto revision=job.at("revision").get<std::string>();
    Json program=layout;
    if(native.contains("program"))program=native["program"];
    if(program.is_object()&&!program.contains("segments")&&layout.contains("segments")&&program.value("image_base",Json{})==layout.value("image_base",Json{})){program["segments"]=layout["segments"];program["mapping_evidence_id"]=layout.value("mapping_evidence_id",Json{});}
    const auto base=program.is_object()?address(program.value("image_base",Json{})):std::nullopt;
    auto location=[&](Json loc){
        if(backend=="runtime"&&loc.is_object()&&loc.contains("artifact_sha256")&&loc.contains("anchor_id"))return loc;
        if(!loc.is_object())loc=Json{{"address",loc}};
        const auto parsed=address(loc.value("address",Json{}));if(!parsed)return Json(nullptr);
        auto space=loc.value("address_space",std::string("program"));
        const auto native_space=space;if(space=="ram"||space=="virtual")space="program";
        Json r{{"artifact_sha256",target.sha256},{"address_space",space},{"address",hex_address(*parsed)},{"native_address_space",native_space}};
        if(program.contains("mapping_evidence_id"))r["mapping_evidence_id"]=program["mapping_evidence_id"];
        r["anchor_id"]=id("loc",Json::array({target.sha256,space,hex_address(*parsed)}));
        if(space=="program"&&base&&*parsed>=*base){r["image_base"]=hex_address(*base);r["rva"]=hex_address(*parsed-*base);}
        if(space=="program"&&program.contains("segments")){
            Json offsets=Json::array();
            for(const auto& s:program["segments"]){auto va=address(s.value("va",Json{}));auto off=address(s.value("file_offset",Json{}));auto size=s.value("file_size",std::uint64_t{});if(va&&off&&*parsed>=*va&&*parsed-*va<size&&*off<=UINT64_MAX-(*parsed-*va))offsets.push_back(hex_address(*off+*parsed-*va));}
            if(offsets.size()==1)r["file_offset"]=offsets[0];else if(offsets.size()>1){r["mapping_ambiguous"]=true;r["file_offset_candidates"]=offsets;}
        }
        return r;
    };
    auto item_location=[&](const Json& item){
        if(item.contains("location")&&item["location"].is_object())return location(item["location"]);
        if(item.contains("source_locations")&&item["source_locations"].is_array()&&!item["source_locations"].empty())return location(item["source_locations"][0]);
        for(const auto* key:{"address","entry","begin","min_address","va"})if(item.contains(key)){auto l=location(item[key]);if(!l.is_null())return l;}
        return Json(nullptr);
    };
    const std::map<std::string,std::string> kinds{{"functions","function"},{"function","function"},{"blocks","block"},{"instructions","instruction"},{"operations","operation"},{"ssa_values","ssa_value"},{"constants","constant"},{"types","type"},{"variables","variable"},{"database_variables","variable"},{"parameters","variable"},{"strings","string"},{"imports","import"},{"exports","export"},{"symbols","symbol"},{"metadata","metadata"},{"statements","statement"},{"tokens","token"},{"calls","call"},{"xrefs","xref"},{"edges","cfg_edge"},{"transfers","cfg_edge"},{"indirect_flow_candidates","indirect_flow"},{"function_analysis","graph_analysis"},{"evidence","native_evidence"},{"exception_relations","exception_relation"},{"initialization_callbacks","initializer"},{"virtual_table_slots","virtual_slot"},{"virtual_dispatch","indirect_flow"}};
    std::map<std::string,std::string> native_ids,block_addresses;
    std::map<std::string,Json> locations;
    std::function<void(const Json&,const std::string&,unsigned)> walk;
    auto add=[&](const std::string& kind,const Json& item,const std::string& pointer,const Json& inherited=Json(nullptr)){
        if(out["entities"].size()>=100000){out["partial"]=true;return;}
        auto loc=item_location(item);if(loc.is_null())loc=inherited;const auto entity=id("ent",Json::array({revision,backend,pointer}));
        auto native_id=scalar(item.value("id",item.value("ir_op",backend=="ilspy"?item.value("token",Json{}):Json{})));
        auto name=scalar(item.value("name",item.value("mnemonic",item.value("text",item.value("path",item.value("value",item.value("low",Json{})))))));
        auto ns=pointer.substr(0,pointer.rfind('/'));if(pointer.substr(pointer.rfind('/')+1).find_first_not_of("0123456789")==std::string::npos)ns=ns.substr(0,ns.rfind('/'));
        Json record{{"id",entity},{"kind",kind},{"revision",revision},{"producer",backend},{"evidence_id",evidence},{"artifact_sha256",target.sha256},{"location",loc},{"native_id",native_id},{"native_namespace",ns},{"name",name},{"json_pointer",pointer},{"native",item}};
        if(!native_id.empty())native_ids[ns+"|"+kind+":"+native_id]=entity;
        if(!loc.is_null()){locations[entity]=loc;if(kind=="block")block_addresses[ns+"|"+loc["address"].get<std::string>()]=entity;}
        out["entities"].push_back(std::move(record));
    };
    walk=[&](const Json& value,const std::string& path,unsigned depth){
        if(depth>24){out["partial"]=true;return;}
        if(!value.is_object())return;
        if(backend=="wireshark"&&path.empty()){
            if(value.contains("packets")&&value["packets"].is_array())for(std::size_t i=0;i<value["packets"].size();++i)
                if(value["packets"][i].is_object()){
                    const auto& packet=value["packets"][i];
                    if(packet.value("stream_projection_partial",false)||packet.value("frame_reference_projection_partial",false))out["partial"]=true;
                    add("packet",packet,"/packets/"+std::to_string(i));
                }
            if(value.contains("streams")&&value["streams"].is_array())for(std::size_t i=0;i<value["streams"].size();++i)
                if(value["streams"][i].is_object())add("packet_stream",value["streams"][i],"/streams/"+std::to_string(i));
            return;
        }
        if(backend=="lief"&&path.empty()){
            for(const auto& [collection,kind]:std::map<std::string,std::string>{{"sections","section"},{"resources","resource"},{"notes","format_note"},{"libraries","library"}}){
                if(value.contains(collection)&&value[collection].is_array())for(std::size_t i=0;i<value[collection].size();++i)
                    if(value[collection][i].is_object())add(kind,value[collection][i],"/"+collection+"/"+std::to_string(i));
            }
            return;
        }
        for(auto it=value.begin();it!=value.end();++it){
            if((backend=="capa"||backend=="floss")&&it.key()=="native_document")continue;
            const auto ptr=path+"/"+pointer_key(it.key());auto k=kinds.find(it.key());
            if(it.value().is_array())for(std::size_t i=0;i<it.value().size();++i){const auto& item=it.value()[i];if(!item.is_object())continue;const auto ip=ptr+"/"+std::to_string(i);if(backend=="capa"&&it.key()=="capabilities")add("capability",item,ip);else if(backend=="ilspy"&&it.key()=="methods")add("managed_method",item,ip);else if(k!=kinds.end())add(k->second,item,ip);else if(backend=="ghidra"&&it.key()=="varnodes")add("ssa_value",item,ip);else if(backend=="ghidra"&&it.key()=="indirect_flows")add("indirect_flow",item,ip);walk(item,ip,depth+1);}
            else if(it.value().is_object()){if(backend=="ilspy"&&it.key()=="method")add("managed_method",it.value(),ptr);else if(it.key()=="function"||it.key()=="constants")add(k->second,it.value(),ptr,item_location(value));walk(it.value(),ptr,depth+1);}
        }
    };
    walk(native,"",0);
    std::string current_namespace;
    auto resolve=[&](const std::string& kind,const Json& n)->Json{auto i=native_ids.find(current_namespace+"|"+kind+":"+scalar(n));return i==native_ids.end()?Json(nullptr):Json(i->second);};
    auto relation=[&](const Json& owner,const std::string& kind,Json from,Json to,Json fromloc,Json toloc,const Json& details){
        Json r{{"kind",kind},{"source_entity",from},{"target_entity",to},{"source_location",fromloc},{"target_location",toloc},{"evidence_id",evidence},{"revision",revision},{"producer",backend},{"artifact_sha256",target.sha256},{"json_pointer",owner["json_pointer"]},{"native",details}};
        r["id"]=id("rel",r);out["relations"].push_back(std::move(r));
    };
    // Native Ghidra function-body ranges connect address-selected query results
    // to their owner without equating its recovered boundaries with XAIR's.
    if(backend=="ghidra"&&native.contains("function")){
        const auto& fn=native["function"];Json owner=nullptr;
        for(const auto& e:out["entities"])if(e["kind"]=="function"&&e["json_pointer"]=="/function"){owner=e;break;}
        if(owner.is_object()&&fn.contains("ranges"))for(const auto& e:out["entities"]){
            if(e["kind"]=="function"||!e["location"].is_object())continue;auto addr=address(e["location"]["address"]);if(!addr)continue;
            bool inside=false;for(const auto& range:fn["ranges"]){auto low=address(range.value("min",Json{})),high=address(range.value("max",Json{}));if(low&&high&&*addr>=*low&&(*addr<*high||(*addr==*high&&range.value("max_inclusive",false)))){inside=true;break;}}
            if(inside)relation(owner,"contains",owner["id"],e["id"],owner["location"],e["location"],{{"method","native Ghidra function-body address ranges"}});
        }
    }
    for(const auto& e:out["entities"]){
        current_namespace=e["native_namespace"].get<std::string>();
        const auto& n=e["native"];const auto kind=e["kind"].get<std::string>();
        if(backend=="wireshark"&&kind=="packet"&&n.contains("stream_refs")&&n["stream_refs"].is_array())
            for(const auto& stream:n["stream_refs"])if(stream.is_object()&&stream.contains("id"))
                relation(e,"native_stream_member",e["id"],resolve("packet_stream",stream["id"]),e["location"],nullptr,stream);
        if(backend=="wireshark"&&kind=="packet"&&n.contains("frame_refs")&&n["frame_refs"].is_array())
            for(const auto& frame:n["frame_refs"])if(frame.is_object()&&frame.contains("target_packet_id")&&frame.contains("target_location")){
                const auto relation_kind=frame.value("kind",std::string{});
                if(relation_kind=="native_tcp_segment_source"||relation_kind=="native_tcp_reassembled_in"||relation_kind=="native_tcp_ack")
                    relation(e,relation_kind,e["id"],resolve("packet",frame["target_packet_id"]),e["location"],location(frame["target_location"]),frame);
            }
        if(kind=="indirect_flow"&&n.contains("target")&&n["target"].is_object()){
            auto destination=location(n["target"]);if(!destination.is_null())relation(e,"static_dispatch_candidate",e["id"],nullptr,e["location"],destination,n);
        }
        if(kind=="cfg_edge"||kind=="xref"||kind=="call"||kind=="exception_relation"||kind=="initializer"||kind=="virtual_slot"){
            Json from=nullptr,to=nullptr,fl=nullptr,tl=nullptr;
            if(n.contains("source"))from=resolve("block",n["source"]);else if(n.contains("node"))from=resolve("block",n["node"]);
            if(n.contains("destination"))to=resolve("block",n["destination"]);
            if(backend=="airece"&&kind=="cfg_edge"&&n.contains("target"))to=resolve("block",n["target"]);
            if(from.is_string()&&locations.contains(from.get<std::string>()))fl=locations[from.get<std::string>()];
            if(to.is_string()&&locations.contains(to.get<std::string>()))tl=locations[to.get<std::string>()];
            if(n.contains("from"))fl=location(n.value("from_location",n["from"]));
            if(n.contains("to"))tl=location(n.value("to_location",n["to"]));
            if(fl.is_null())fl=e["location"];
            if(tl.is_null()){auto raw=n.value("raw_target",n.value("target",Json{}));auto a=address(raw);if(a&&*a!=0)tl=location(raw);}
            if(from.is_null()&&!fl.is_null()){auto i=block_addresses.find(current_namespace+"|"+fl["address"].get<std::string>());if(i!=block_addresses.end())from=i->second;}
            if(to.is_null()&&!tl.is_null()){auto i=block_addresses.find(current_namespace+"|"+tl["address"].get<std::string>());if(i!=block_addresses.end())to=i->second;}
            relation(e,backend=="runtime"?"observed_control_flow":kind,from,to,fl,tl,n);
        }
        if(kind=="operation"){
            if(backend=="ghidra") {
                if(n.contains("inputs"))for(const auto& value:n["inputs"])relation(e,"uses",e["id"],resolve("ssa_value",value),e["location"],nullptr,Json{{"native_value",value}});
                if(n.contains("output")&&!n["output"].is_null())relation(e,"definitions",e["id"],resolve("ssa_value",n["output"]),e["location"],nullptr,Json{{"native_value",n["output"]}});
            }
            for(const auto* field:{"definitions","uses"})if(n.contains(field)&&n[field].is_array())for(const auto& value:n[field])relation(e,field,e["id"],resolve("ssa_value",value),e["location"],nullptr,Json{{"native_value",value}});
            if(n.contains("memory_effects"))for(const auto* effect:{"read","write"})if(n["memory_effects"].value(effect,false))relation(e,std::string(effect)+"_memory",e["id"],nullptr,e["location"],nullptr,n["memory_effects"]);
        }
        if(kind=="function"&&n.contains("blocks")&&n["blocks"].is_array())for(const auto& block:n["blocks"])if(!block.is_object())relation(e,"contains",e["id"],resolve("block",block),e["location"],nullptr,Json{{"native_block",block}});
        for(const auto* field:{"name","signature","type","semantic_completeness","native_verdict","memory_effects","flags","bytes","value","constants","low","high"}){
            if(!n.contains(field))continue;
            Json claim{{"subject",e["id"]},{"predicate",field},{"value",n[field]},{"state","derived"},{"producer",backend},{"revision",revision},{"evidence_id",evidence},{"json_pointer",e["json_pointer"].get<std::string>()+"/"+field},{"location",e["location"]},{"scope",{{"artifact_sha256",target.sha256},{"operation",job["request"]["operation"]}}},{"assumptions",Json::array({"backend-native assertion; not independently validated"})},{"validation","unvalidated"}};
            claim["dependencies"]=Json::array({Json{{"evidence_id",evidence},{"revision",revision}}});
            claim["id"]=id("clm",claim);out["claims"].push_back(std::move(claim));
        }
    }
    return out;
}
}
