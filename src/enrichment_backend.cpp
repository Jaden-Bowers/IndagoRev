#include "indago/enrichment.hpp"
#include "indago/airece.hpp"
#include "indago/runtime.hpp"
#include <algorithm>
#include <fstream>

namespace indago {
namespace {
using J=nlohmann::json;
std::string escaped(const std::string& value){std::string result;for(char c:value)result+=c=='~'?"~0":c=='/'?"~1":std::string(1,c);return result;}
J capa_location(const J& address){
    if(!address.is_object()||!address.contains("value"))return nullptr;
    auto type=address.value("type",std::string{});const auto& value=address.at("value");
    if(!value.is_number_unsigned()&&(!value.is_number_integer()||value.get<std::int64_t>()<0))return nullptr;
    const auto space=type=="absolute"?"program":type=="relative"?"rva":type=="file"?"file":type=="dn token"?"managed_metadata":"";
    if(!*space)return nullptr;
    return {{"address_space",space},{"address",hex_address(value.get<std::uint64_t>())}};
}
}
CommandResult query_enrichment(const TargetRecord& target,const J& request,const fs::path& cancel){
#if INDAGO_HAS_ENRICHMENT
    if(target.size>16*1024*1024)throw std::runtime_error("Enrichment input exceeds 16 MiB bound");
    const auto backend=request.at("backend").get<std::string>();const auto& args=request.at("arguments");
    if(backend!="capa"&&backend!="floss")throw std::runtime_error("Unknown enrichment backend");
    const auto address=request.value("address",std::string{});
    const auto root=bundled_engines("enrichment")/"enrichment";
#ifdef _WIN32
    const auto executable=root/(backend+".exe");
#else
    const auto executable=root/backend;
#endif
    std::vector<std::string> argv{"--json","--color","never","--quiet"};
    std::string selected;
    if(backend=="capa"){
        selected=args.value("format",std::string{});
        if(selected.empty()){
            std::ifstream file(target.object_path,std::ios::binary);char magic[4]{};file.read(magic,4);
            if(magic[0]=='M'&&magic[1]=='Z')selected="pe";
            else if(magic[0]=='\x7f'&&magic[1]=='E'&&magic[2]=='L'&&magic[3]=='F')selected="elf";
            else throw std::runtime_error("capa requires PE or ELF input; other upstream loaders are not granted");
        }
        argv.insert(argv.end(),{"--format",selected,"--backend",selected=="dotnet"?"dotnet":"vivisect"});
        if(!address.empty())argv.insert(argv.end(),{"--restrict-to-functions",address});
    }else{
        selected=args.value("mode",std::string("static"));
        argv.insert(argv.end(),{"--disable-progress","--language","none","--minimum-length",std::to_string(args.value("minimum_length",4))});
        if(selected!="all")argv.insert(argv.end(),{"--only",selected});
        if(selected!="static")argv.insert(argv.end(),{"--format","pe"});
        if(!address.empty())argv.insert(argv.end(),{"--functions",address});
    }
    argv.insert(argv.end(),{"--",target.object_path.string()});
    NativeProcessOptions options;options.cancel_file=cancel;
    options.wall_time_ms=std::min<std::uint64_t>(request.at("budget").at("wall_ms").get<std::uint64_t>(),60000);
    options.max_output_bytes=std::min<std::size_t>(request.at("budget").at("output_bytes").get<std::size_t>(),4*1024*1024);
    const auto output=run_native_process(executable,argv,options);
    J result{{"backend",backend},{"artifact_sha256",target.sha256},{"status","failed"},
        {"native_exit_code",output.exit_code},{"target_executed",false},{"scope",selected},
        {"provenance",{{"integration","bundled upstream standalone worker"},{"version",backend=="capa"?"9.4.0":"3.1.1"}}},
        {"worker",{{"wall_ms",options.wall_time_ms},{"output_bytes",options.max_output_bytes},{"cancelled",output.cancelled},{"timed_out",output.timed_out},{"output_truncated",output.truncated},{"security_sandbox",false},{"memory_limit_enforced",false}}}};
    if(output.cancelled||output.timed_out||output.truncated||output.exit_code!=0){
        result["status"]=output.cancelled?"cancelled":output.timed_out?"timeout":output.truncated?"partial":"failed";
        result["native_document_complete"]=false;
        result["diagnostic"]=output.cancelled?"Enrichment cancelled":output.timed_out?"Enrichment wall budget exceeded":output.truncated?"Enrichment output budget exceeded":"Upstream enrichment failed";
        result["stdout_prefix"]=output.output.substr(0,2048);result["stderr_prefix"]=output.error.substr(0,2048);
    }else{
        if(sha256_file(target.object_path)!=target.sha256)throw std::runtime_error("Artifact changed during enrichment");
        const auto native=J::parse(output.output);
        if(!native.is_object())throw std::runtime_error("Invalid enrichment document");
        if(backend=="capa"&&(native.at("meta").at("sample").at("sha256")!=target.sha256||native.at("meta").at("flavor")!="static"||native.at("meta").at("version")!="9.4.0"))throw std::runtime_error("capa native provenance mismatch");
        if(backend=="floss"&&!native.at("metadata").at("version").get<std::string>().starts_with("v3.1.1"))throw std::runtime_error("FLOSS native version mismatch");
        result["native_document"]=native;result["native_document_complete"]=true;
        result["upstream_stdout_sha256"]=sha256_text(output.output);
        result["native_document_representation"]="parsed JSON; upstream stdout whitespace not retained";
        result["status"]="completed";result["native_verdict"]="upstream operation completed; findings are not proof of runtime behavior";
        const auto limit=std::min<std::size_t>(request.at("budget").at("max_items").get<std::size_t>(),512);
        std::size_t total=0;J summaries=J::array();
        if(backend=="capa"){
            for(auto it=native.at("rules").begin();it!=native.at("rules").end();++it){
                ++total;if(summaries.size()>=limit)continue;
                const auto& rule=it.value();const auto& meta=rule.at("meta");
                J item{{"name",meta.at("name")},{"namespace",meta.value("namespace",std::string{})},
                    {"native_pointer","/native_document/rules/"+escaped(it.key())},
                    {"match_count",rule.at("matches").size()},{"native_verdict","capability_rule_match"},
                    {"behavior_proven",false},{"source_locations",J::array()}};
                for(const auto& match:rule.at("matches")){if(item["source_locations"].size()>=8)break;if(match.is_array()&&!match.empty()){auto location=capa_location(match[0]);if(!location.is_null())item["source_locations"].push_back(location);}}
                item["locations_complete"]=item["source_locations"].size()==rule.at("matches").size();
                summaries.push_back(std::move(item));
            }
            result["capabilities"]=std::move(summaries);
        }else{
            for(const auto* kind:{"static_strings","stack_strings","tight_strings","decoded_strings","language_strings","language_strings_missed"}){
                if(!native.at("strings").contains(kind))continue;
                const auto& strings=native.at("strings").at(kind);if(!strings.is_array())continue;
                for(std::size_t i=0;i<strings.size();++i){++total;if(summaries.size()>=limit)continue;const auto& entry=strings[i];
                    const auto& text=entry.at("string").get_ref<const std::string&>();
                    J item{{"name",text.size()<=512?text:std::string{}},{"text_omitted",text.size()>512},{"text_sha256",sha256_text(text)},
                        {"category",kind},{"native_pointer","/native_document/strings/"+std::string(kind)+"/"+std::to_string(i)},
                        {"encoding",entry.value("encoding",std::string{})},{"behavior_proven",false}};
                    // Only static string offsets are file-byte locations. Stack,
                    // decoded and language-specific positions retain native fields.
                    if(std::string_view(kind)=="static_strings"&&entry.contains("offset")&&entry.at("offset").is_number_unsigned()){
                        item["location"]={{"address_space","file"},{"address",hex_address(entry.at("offset").get<std::uint64_t>())}};item["location_role"]="file_bytes";
                    }else if(std::string_view(kind)=="stack_strings"||std::string_view(kind)=="tight_strings"||std::string_view(kind)=="decoded_strings"){
                        const auto field=std::string_view(kind)=="decoded_strings"?"decoded_at":"program_counter";
                        if(entry.contains(field)&&entry.at(field).is_number_unsigned()&&entry.at(field).get<std::uint64_t>()!=0){
                            item["location"]={{"address_space","program"},{"address",hex_address(entry.at(field).get<std::uint64_t>())}};
                            item["location_role"]="emulated_recovery_site; not string storage address";
                        }
                    }
                    summaries.push_back(std::move(item));
                }
            }
            result["strings"]=std::move(summaries);
        }
        result["finding_count"]=total;result["summary_truncated"]=total>limit;
        if(total>limit)result["status"]="partial";
        if(!output.error.empty())result["stderr_prefix"]=output.error.substr(0,2048);
    }
    auto serialized=result.dump(-1,' ',false,J::error_handler_t::replace);
    if(serialized.size()>options.max_output_bytes){
        // Keep the full native document when it fits by dropping the projection.
        result.erase("capabilities");result.erase("strings");result["summary_omitted"]=true;
        if(result["status"]=="completed")result["status"]="partial";
        serialized=result.dump(-1,' ',false,J::error_handler_t::replace);
        if(serialized.size()>options.max_output_bytes){
            result.erase("native_document");result["native_document_retained"]=false;
            result["diagnostic"]="Native document plus provenance exceeded output budget; retry with a larger budget";
            serialized=result.dump(-1,' ',false,J::error_handler_t::replace);
        }
    }
    if(serialized.size()>options.max_output_bytes){result.erase("stdout_prefix");result.erase("stderr_prefix");serialized=result.dump();}
    const auto state=result.at("status").get<std::string>();
    return {state=="completed"?0:state=="partial"?3:state=="cancelled"?130:1,state,serialized};
#else
    (void)target;(void)request;(void)cancel;
    return {1,"failed",J{{"status","failed"},{"diagnostic","Bundled enrichment workers unavailable; run tools/bundle-enrichment.ps1 and rebuild"}}.dump()};
#endif
}
}
