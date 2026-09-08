#pragma once
#include "indago/core.hpp"
#include <charconv>
#include <map>
#include <functional>

namespace indago {
inline void project_packet_frame_references(nlohmann::json& packet,const nlohmann::json& layers,
        const std::string& native_pointer,const std::string& capture_hash) {
    using J=nlohmann::json;
    packet["frame_refs"]=J::array();packet["frame_reference_projection_partial"]=false;
    const std::map<std::string,std::string> fields{{"tcp.segment","native_tcp_segment_source"},
        {"tcp.reassembled_in","native_tcp_reassembled_in"},{"tcp.analysis.acks_frame","native_tcp_ack"}};
    std::size_t visited=0;
    auto pointer_key=[](std::string_view key){std::string escaped;for(char c:key)escaped+=c=='~'?"~0":c=='/'?"~1":std::string(1,c);return escaped;};
    auto add=[&](const J& raw,const std::string& pointer,const std::string& kind){
        if(packet["frame_refs"].size()>=64||!raw.is_string()){packet["frame_reference_projection_partial"]=true;return;}
        const auto number=raw.get<std::string>();std::uint32_t frame{};
        const auto parsed=std::from_chars(number.data(),number.data()+number.size(),frame);
        if(parsed.ec!=std::errc{}||parsed.ptr!=number.data()+number.size()||frame==0||number!=std::to_string(frame)){
            packet["frame_reference_projection_partial"]=true;return;
        }
        packet["frame_refs"].push_back({{"kind",kind},{"target_packet_id",capture_hash+":"+number},
            {"target_location",{{"address_space","capture_frame"},{"address",std::uint64_t{frame}}}},
            {"native_pointer",pointer},{"native_frame_number",raw},{"assertion","upstream frame relationship; not independent delivery or reassembly validation"}});
    };
    std::function<void(const J&,const std::string&,unsigned)> visit;
    visit=[&](const J& node,const std::string& pointer,unsigned depth){
        if(++visited>1024||depth>12){packet["frame_reference_projection_partial"]=true;return;}
        if(node.is_object())for(auto it=node.begin();it!=node.end();++it){
            if(visited>=1024){packet["frame_reference_projection_partial"]=true;break;}
            const auto child=pointer+"/"+pointer_key(it.key());
            if(auto field=fields.find(it.key());field!=fields.end()){
                ++visited;
                if(it->is_array()){
                    for(std::size_t i=0;i<std::min<std::size_t>(it->size(),64);++i)add((*it)[i],child+"/"+std::to_string(i),field->second);
                    if(it->size()>64)packet["frame_reference_projection_partial"]=true;
                }else add(*it,child,field->second);
            }else if(!it.key().ends_with("_raw"))visit(*it,child,depth+1);
            else ++visited;
        }
        else if(node.is_array())for(std::size_t i=0;i<node.size();++i){
            if(visited>=1024){packet["frame_reference_projection_partial"]=true;break;}
            visit(node[i],pointer+"/"+std::to_string(i),depth+1);
        }
    };
    visit(layers,native_pointer,0);
}
// Project only explicit upstream stream fields. No endpoint matching, packet
// parsing, TCP state machine, reassembly or process attribution is performed.
inline void project_packet_streams(nlohmann::json& result) {
    using J=nlohmann::json;
    const auto profile=sha256_text(J::array({"indago.wireshark-stream-profile.v1",
        result.at("artifact_sha256"),result.at("provenance"),
        "one-pass offline dissection; name resolution disabled; upstream defaults"}).dump());
    result["stream_profile_id"]=profile;
    result["streams"]=J::array();
    std::map<std::string,std::size_t> streams;
    for(std::size_t i=0;i<result.at("packets").size();++i) {
        auto& packet=result["packets"][i];
        packet["stream_refs"]=J::array();packet["stream_projection_partial"]=false;
        const auto& layers=result.at("native_packets").at(i).at("_source").at("layers");
        project_packet_frame_references(packet,layers,"/native_packets/"+std::to_string(i)+"/_source/layers",result.at("artifact_sha256").get<std::string>());
        for(const std::string transport:{"tcp","udp"}) {
            if(!layers.contains(transport))continue;
            const auto& layer=layers.at(transport);
            // Repeated/nested protocol instances need an explicit upstream layer
            // association. Do not flatten them into an invented single stream.
            if(!layer.is_object()){packet["stream_projection_partial"]=true;continue;}
            const auto field=transport+".stream";
            if(!layer.contains(field))continue;
            const auto& raw=layer.at(field);
            if(!raw.is_string()){packet["stream_projection_partial"]=true;continue;}
            const auto number=raw.get<std::string>();std::uint32_t ordinal{};
            const auto parsed=std::from_chars(number.data(),number.data()+number.size(),ordinal);
            if(parsed.ec!=std::errc{}||parsed.ptr!=number.data()+number.size()||number!=std::to_string(ordinal)){
                packet["stream_projection_partial"]=true;continue;
            }
            const auto id="stream_"+sha256_text(J::array({profile,transport,number}).dump());
            const auto pointer="/native_packets/"+std::to_string(i)+"/_source/layers/"+transport+"/"+field;
            packet["stream_refs"].push_back({{"id",id},{"transport",transport},{"native_ordinal",raw},{"native_pointer",pointer}});
            auto [entry,inserted]=streams.emplace(id,result["streams"].size());
            if(inserted)result["streams"].push_back({{"id",id},{"name",transport+" stream "+number},
                {"transport",transport},{"native_ordinal",raw},{"profile_id",profile},
                {"identity_scope","capture and dissection profile; upstream stream index, not a proven connection incarnation"},
                {"packet_ids",J::array()},{"membership_scope","returned page only"},
                {"complete",false},{"process_attribution",false}});
            result["streams"][entry->second]["packet_ids"].push_back(packet.at("id"));
        }
    }
}
}
