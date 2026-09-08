#include "indago/wireshark.hpp"
#include "indago/airece.hpp"
#include "indago/runtime.hpp"
#include "indago/service.hpp"
#include "packet_streams.hpp"
#include <algorithm>
#include <cstdlib>
#include <fstream>

namespace indago {
namespace {
using J=nlohmann::json;
J policy(){return {{"live_capture",false},{"name_resolution",false},{"external_plugins",false},
    {"process_attribution",false},{"security_sandbox",false},{"os_network_isolation",false},
    {"lua_runtime_present",
#ifdef _WIN32
    true
#else
    false
#endif
    },{"lua_scripts_loaded",false},{"memory_limit_enforced",false}};}
}
J wireshark_worker(const J& request){
    J result{{"backend","wireshark"},{"status","failed"},{"policy",policy()},
        {"provenance",{{"version","4.6.8"},{"integration","bundled upstream TShark; offline file dissection"}}}};
    try{
#if INDAGO_HAS_WIRESHARK
        const auto offset=request.at("offset").get<std::int64_t>(),limit=request.at("limit").get<std::int64_t>();
        const auto output=request.at("output_bytes").get<std::int64_t>(),wall=request.at("wall_ms").get<std::int64_t>();
        if(offset<0||offset>4096||limit<1||limit>64||output<4096||output>4194304||wall<1||wall>60000)throw std::runtime_error("Invalid offline packet bounds");
        const fs::path input=request.at("path").get<std::string>();
        if(!input.is_absolute()||!fs::is_regular_file(input)||fs::file_size(input)>16777216)throw std::runtime_error("Offline capture requires a regular snapshot <=16 MiB");
        const auto hash=sha256_file(input);if(request.at("sha256")!=hash)throw std::runtime_error("Capture snapshot identity mismatch");
        std::ifstream file(input,std::ios::binary);unsigned char magic[4]{};file.read(reinterpret_cast<char*>(magic),4);
        const bool pcap=(magic[0]==0xd4&&magic[1]==0xc3&&magic[2]==0xb2&&magic[3]==0xa1)||(magic[0]==0xa1&&magic[1]==0xb2&&magic[2]==0xc3&&magic[3]==0xd4)||
            (magic[0]==0x4d&&magic[1]==0x3c&&magic[2]==0xb2&&magic[3]==0xa1)||(magic[0]==0xa1&&magic[1]==0xb2&&magic[2]==0x3c&&magic[3]==0x4d);
        const bool pcapng=magic[0]==0x0a&&magic[1]==0x0d&&magic[2]==0x0d&&magic[3]==0x0a;
        if(!pcap&&!pcapng)throw std::runtime_error("Offline worker accepts PCAP/PCAPNG only");
        result["artifact_sha256"]=hash;result["capture_format"]=pcap?"pcap":"pcapng";
#ifdef _WIN32
        const auto executable=bundled_engines("network")/"network"/"tshark.exe";
        result["provenance"]["build_profile"]="official Windows package; empty script/plugin profile";
#else
        const auto executable=bundled_engines("network")/"network"/"tshark";
        result["provenance"]["build_profile"]="source-built Linux offline static worker; no Lua/plugins/libpcap; see bundled build-profile.txt for optional features";
#endif
        // This runs only in __wireshark, before constructing service threads.
        // Environment/CWD changes affect this disposable worker, never its parent.
        const auto scratch=fs::temp_directory_path()/make_id("indago_packet_profile");
        if(!fs::create_directory(scratch))throw std::runtime_error("Cannot allocate private packet profile");
        struct Cleanup{fs::path path;~Cleanup(){std::error_code ec;fs::current_path(path.parent_path(),ec);fs::remove_all(path,ec);}}cleanup{scratch};
        const auto plugins=scratch/"plugins";fs::create_directory(plugins);
#ifdef _WIN32
        auto env=[&](const wchar_t* key,const fs::path& value){if(_wputenv_s(key,value.c_str())!=0)throw std::runtime_error("Cannot set private packet worker environment");};
        env(L"WIRESHARK_CONFIG_DIR",scratch);env(L"WIRESHARK_DATA_DIR",scratch);env(L"WIRESHARK_PLUGIN_DIR",plugins);env(L"WIRESHARK_EXTCAP_DIR",scratch/"no-extcap");
        if(_wputenv_s(L"WIRESHARK_RUN_FROM_BUILD_DIRECTORY",L"")!=0)throw std::runtime_error("Cannot clear upstream build-directory override");
#else
        auto env=[&](const char* key,const fs::path& value){if(setenv(key,value.c_str(),1)!=0)throw std::runtime_error("Cannot set private packet worker environment");};
        env("WIRESHARK_CONFIG_DIR",scratch);env("WIRESHARK_DATA_DIR",scratch);env("WIRESHARK_PLUGIN_DIR",plugins);env("WIRESHARK_EXTCAP_DIR",scratch/"no-extcap");
        if(unsetenv("WIRESHARK_RUN_FROM_BUILD_DIRECTORY")!=0)throw std::runtime_error("Cannot clear upstream build-directory override");
#endif
        fs::current_path(scratch);
        NativeProcessOptions options;options.wall_time_ms=wall;options.max_output_bytes=static_cast<std::size_t>(output);
        const auto ceiling=offset+limit+1;
        const auto native=run_native_process(executable,{"-n","-r",input.string(),"-c",std::to_string(ceiling),
            "-Y","frame.number > "+std::to_string(offset),"-o","frame.show_file_off:true","-T","json","--no-duplicate-keys","-x"},options);
        result["native_exit_code"]=native.exit_code;result["upstream_stdout_sha256"]=sha256_text(native.output);
        result["stderr_prefix"]=native.error.substr(0,512);
        result["prefix_frames_bound"]=ceiling;
        if(sha256_file(input)!=hash)throw std::runtime_error("Capture snapshot changed during dissection");
        if(native.timed_out||native.truncated){result["status"]=native.timed_out?"timeout":"partial";result["diagnostic"]="Packet worker wall/output limit reached; no complete JSON document";return result;}
        const auto parsed=J::parse(native.output,nullptr,false);
        if(!parsed.is_array()){result["diagnostic"]="Upstream packet worker returned no valid JSON array";return result;}
        const bool more=parsed.size()>static_cast<std::size_t>(limit);
        result["native_packets"]=J::array();result["packets"]=J::array();
        const auto count=std::min<std::size_t>(parsed.size(),static_cast<std::size_t>(limit));
        for(std::size_t i=0;i<count;++i){
            const auto& layers=parsed.at(i).at("_source").at("layers");const auto& frame=layers.at("frame");
            const auto number=frame.at("frame.number").get<std::string>();
            if(number!=std::to_string(offset+static_cast<std::int64_t>(i)+1))throw std::runtime_error("Unexpected packet ordinal from fixed upstream filter");
            J item{{"id",hash+":"+number},{"name","Frame "+number},{"packet_number",number},
                {"location",{{"address_space","capture_frame"},{"address",offset+i+1}}},
                {"native_pointer","/native_packets/"+std::to_string(i)},
                {"captured_length_native",frame.at("frame.cap_len")},{"original_length_native",frame.at("frame.len")},
                {"timestamp_native",frame.value("frame.time_epoch",J(nullptr))},{"timestamp_resolution_explicit",false},
                {"interface_id_native",frame.value("frame.interface_id",J(nullptr))},{"section_number_native",frame.value("frame.section_number",J(nullptr))},
                {"record_offset_native",frame.value("frame.file_off",J(nullptr))},{"protocols_native",frame.value("frame.protocols",J(nullptr))},
                {"raw_field_offsets","upstream frame/data-source relative; not capture-file byte offsets"},{"process_attribution",false}};
            result["native_packets"].push_back(parsed[i]);result["packets"].push_back(std::move(item));
        }
        auto finish=[&]{const auto returned=result["packets"].size();const bool omitted=returned<count;
            project_packet_streams(result);
            result["page"]={{"offset",offset},{"returned",returned},{"more",more||omitted},{"next_offset",(more||omitted)&&returned?J(offset+returned):J(nullptr)}};
            result["status"]=native.exit_code!=0?(returned?"partial":"failed"):(more||omitted?"partial":"completed");
            result["upstream_completed"]=native.exit_code==0;result["capture_coverage_proven"]=false;
            result["native_verdict"]="upstream offline dissection; no assertion of complete capture or runtime behavior";
        };
        finish();
        while(result.dump().size()>static_cast<std::size_t>(output)-768&&!result["packets"].empty()){
            result["packets"].erase(result["packets"].end()-1);result["native_packets"].erase(result["native_packets"].end()-1);finish();
        }
        if(count&&!result["packets"].size()){result["status"]="partial";result["diagnostic"]="First packet exceeds output budget; increase output_bytes";}
        return result;
#else
        (void)request;throw std::runtime_error("Bundled offline Wireshark worker unavailable on this host");
#endif
    }catch(const std::exception& error){result["status"]="failed";result["diagnostic"]=std::string(error.what()).substr(0,1024);return result;}
}
CommandResult query_wireshark(const TargetRecord& target,const J& request,const fs::path& cancel){
    const auto executable=find_native_worker();if(!executable)throw std::runtime_error("Native packet worker unavailable");
    NativeProcessOptions options;options.cancel_file=cancel;
    options.wall_time_ms=std::min<std::uint64_t>(request.at("budget").at("wall_ms").get<std::uint64_t>(),60000);
    options.max_output_bytes=std::min<std::size_t>(request.at("budget").at("output_bytes").get<std::size_t>(),4194304);
    const J query{{"path",fs::absolute(target.object_path).string()},{"sha256",target.sha256},{"offset",request.at("arguments").value("offset",0)},
        {"limit",std::min<std::size_t>(request.at("budget").at("max_items").get<std::size_t>(),64)},{"wall_ms",options.wall_time_ms},{"output_bytes",options.max_output_bytes}};
    const auto native=run_native_process(*executable,{"__wireshark",query.dump()},options);
    J result{{"backend","wireshark"},{"artifact_sha256",target.sha256}};
    if(native.cancelled||native.timed_out||native.truncated){result["status"]=native.cancelled?"cancelled":native.timed_out?"timeout":"partial";result["diagnostic"]="Offline packet worker cancelled or reached wall/output limit";}
    else if(native.output.empty()){result["status"]="failed";result["diagnostic"]="Offline packet worker returned no document";}
    else {result=J::parse(native.output);const auto state=result.value("status",std::string{});
        if(result.value("backend",std::string{})!="wireshark"||(state!="completed"&&state!="partial"&&state!="failed"&&state!="timeout")||
            ((state=="completed"||state=="partial")&&result.value("artifact_sha256",std::string{})!=target.sha256))throw std::runtime_error("Packet worker identity/status mismatch");
        if(native.exit_code!=result_exit_code(state))throw std::runtime_error("Packet worker exit status mismatch");}
    result["worker"]={{"isolated_process",true},{"exit_code",native.exit_code},{"wall_ms",options.wall_time_ms},{"output_bytes",options.max_output_bytes},{"memory_limit_enforced",false}};
    const auto state=result.at("status").get<std::string>();return {state=="completed"?0:state=="partial"?3:state=="cancelled"?130:1,state,result.dump()};
}
}
