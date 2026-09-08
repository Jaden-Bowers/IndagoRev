#pragma once
#include "../src/packet_streams.hpp"
#include "indago/static_index.hpp"
inline void packet_stream_checks() {
    using namespace indago;using J=nlohmann::json;
    const J packet{{"id","fixture:1"},{"location",{{"address_space","capture_frame"},{"address",std::uint64_t{1}}}}};
    J result{{"artifact_sha256",std::string(64,'a')},{"provenance",{{"version","fixture"},{"build_profile","offline"}}},
        {"packets",J::array({packet})},{"native_packets",J::array({{{"_source",{{"layers",{{"udp",{{"udp.stream","0"}}},{"tcp",{{"tcp.stream","0"}}}}}}}}})}};
    const auto upstream=result["native_packets"];
    project_packet_streams(result);
    if(result["streams"].size()!=2||result["streams"][0]["id"]==result["streams"][1]["id"]||result["native_packets"]!=upstream)
        throw std::runtime_error("Native stream projection conflated transports or changed native evidence");
    const auto stable=result["streams"][0]["id"];
    project_packet_streams(result);if(result["streams"][0]["id"]!=stable)throw std::runtime_error("Stream projection not deterministic");
    TargetRecord target{"fixture","packets",std::string(64,'a'),"",1,""};
    J job{{"revision","rev_fixture"},{"request",{{"operation","packets"}}}};
    const auto index=normalize_static(target,job,"wireshark","evidence_fixture",result);
    if(index["entities"].size()!=3||index["relations"].size()!=2)throw std::runtime_error("Missing packet/stream index relations");
    for(const auto& relation:index["relations"])if(!relation["target_entity"].is_string()||!relation["target_location"].is_null())
        throw std::runtime_error("Native stream link unresolved or assigned an invented address");
    result["provenance"]["build_profile"]="different";project_packet_streams(result);
    if(result["streams"][0]["id"]==stable)throw std::runtime_error("Dissection profiles alias");
    result["provenance"]["build_profile"]="offline";result["artifact_sha256"]=std::string(64,'b');project_packet_streams(result);
    if(result["streams"][0]["id"]==stable)throw std::runtime_error("Different capture streams alias");
    auto& layers=result["native_packets"][0]["_source"]["layers"];
    target.sha256=std::string(64,'b');result["packets"][0]["id"]=target.sha256+":1";
    layers["tcp.segments"]={{"tcp.segment",J::array({"1","9"})},{"tcp.segment_raw",J::array({"not a file mapping"})}};
    project_packet_streams(result);
    if(result["packets"][0]["frame_refs"].size()!=2)throw std::runtime_error("Native reassembly frame references missing");
    for(const auto& ref:result["packets"][0]["frame_refs"])
        if(result.at(J::json_pointer(ref["native_pointer"].get<std::string>()))!=ref["native_frame_number"])
            throw std::runtime_error("Reassembly reference pointer does not resolve to its native source");
    const auto referenced=normalize_static(target,job,"wireshark","evidence_refs",result);
    if(referenced["relations"].size()!=4)throw std::runtime_error("Native frame links not indexed");
    for(const auto& relation:referenced["relations"])if(relation["kind"]=="native_tcp_segment_source")
        if(relation["target_location"]["address_space"]!="capture_frame"||relation["target_location"].contains("file_offset")||
            (relation["native"]["native_frame_number"]=="1"?!relation["target_entity"].is_string():!relation["target_entity"].is_null()))
            throw std::runtime_error("Reassembly frame ordinal became a capture file offset");
    J crowded=J::array();for(unsigned i=1;i<=100;++i)crowded.push_back(std::to_string(i));
    layers["tcp.segments"]["tcp.segment"]=crowded;project_packet_streams(result);
    if(result["packets"][0]["frame_refs"].size()!=64||result["packets"][0]["frame_reference_projection_partial"]!=true)
        throw std::runtime_error("Frame reference projection exceeded its finite bound");
    if(normalize_static(target,job,"wireshark","evidence_bounded",result)["partial"]!=true)
        throw std::runtime_error("Bounded packet projection omission lost in index");
    for(const auto& bad:J::array({"01","4294967296","-1",1,J::array({"0","1"})})){
        result["native_packets"][0]["_source"]["layers"]={{"udp",{{"udp.stream",bad}}}};
        project_packet_streams(result);
        if(!result["streams"].empty()||result["packets"][0]["stream_projection_partial"]!=true)
            throw std::runtime_error("Ambiguous upstream stream identity guessed");
    }
    result["packets"]=J::array();result["native_packets"]=J::array();project_packet_streams(result);
    if(!result["streams"].empty())throw std::runtime_error("Output trimming left stale stream memberships");
}
