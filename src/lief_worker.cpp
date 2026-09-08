#include "indago/lief.hpp"
#include <algorithm>
#include <fstream>
#include <functional>
#include <set>
#if INDAGO_HAS_LIEF
#include <LIEF/PE.hpp>
#include <LIEF/ELF.hpp>
#include <LIEF/logging.hpp>
#endif

namespace indago {
namespace {
using J=nlohmann::json;
constexpr std::size_t input_bound=16*1024*1024;
// Text fields in malformed binaries need not be UTF-8. Preserve their bytes as
// hex rather than replacing invalid characters and silently changing identities.
void name_field(J& item, const std::string& value, const char* key="name") {
    if(value.size()>512){item[std::string(key)+"_omitted"]=true;item[std::string(key)+"_sha256"]=sha256_text(value);return;}
    try { (void)J(value).dump();item[key]=value; }
    catch(const J::type_error&) {
        std::string hex;constexpr char digits[]="0123456789abcdef";
        for(unsigned char c:value){hex+=digits[c>>4];hex+=digits[c&15];}
        item[std::string(key)+"_bytes_hex"]=hex;
    }
}
}
J lief_worker(const J& request) {
    J result{{"backend","lief"},{"status","failed"},{"target_executed",false},
        {"provenance",{{"version","1.0.0"},{"integration","statically linked C++ SDK; same-executable worker"}}}};
    try {
#if INDAGO_HAS_LIEF
        const auto operation=request.at("operation").get<std::string>();
        if(!std::set<std::string>{"inventory","sections","resources","notes","libraries"}.contains(operation))throw std::runtime_error("Unsupported LIEF operation");
        const auto offset=request.at("offset").get<std::int64_t>();
        const auto limit=request.at("limit").get<std::int64_t>();
        const auto output=request.at("output_bytes").get<std::int64_t>();
        if(offset<0||offset>65536||limit<1||limit>128||output<4096||output>1048576)throw std::runtime_error("Invalid LIEF bounds");
        std::ifstream file(request.at("path").get<std::string>(),std::ios::binary);
        if(!file)throw std::runtime_error("Cannot open LIEF snapshot");
        std::vector<std::uint8_t> data(input_bound+1);
        file.read(reinterpret_cast<char*>(data.data()),static_cast<std::streamsize>(data.size()));
        const auto count=file.gcount();
        if(file.bad()||count<4||count>static_cast<std::streamsize>(input_bound))throw std::runtime_error("LIEF snapshot must be 4 bytes..16 MiB");
        data.resize(static_cast<std::size_t>(count));
        const auto hash=sha256_text(std::string_view(reinterpret_cast<const char*>(data.data()),data.size()));
        if(request.at("sha256")!=hash)throw std::runtime_error("LIEF snapshot identity mismatch");
        result["artifact_sha256"]=hash;result["operation"]=operation;
        LIEF::logging::disable();
        std::unique_ptr<LIEF::PE::Binary> pe;
        std::unique_ptr<LIEF::ELF::Binary> elf;
        if(data[0]=='M'&&data[1]=='Z'){
            LIEF::PE::ParserConfig config;
            config.parse_signature=false;config.parse_exports=false;config.parse_reloc=false;
            config.parse_imports=operation=="libraries";config.parse_rsrc=operation=="resources";
            pe=LIEF::PE::Parser::parse(data,config);
        }else if(data[0]==0x7f&&data[1]=='E'&&data[2]=='L'&&data[3]=='F'){
            LIEF::ELF::ParserConfig config;
            config.parse_relocations=false;config.parse_dyn_symbols=false;
            config.parse_symtab_symbols=false;config.parse_symbol_versions=false;
            config.parse_notes=operation=="notes";config.parse_overlay=false;
            elf=LIEF::ELF::Parser::parse(data,config);
        }else throw std::runtime_error("LIEF worker accepts PE or ELF only");
        if(!pe&&!elf)throw std::runtime_error("LIEF could not parse the snapshot");
        const LIEF::Binary& binary=pe?static_cast<const LIEF::Binary&>(*pe):static_cast<const LIEF::Binary&>(*elf);
        result["format"]=pe?"PE":"ELF";
        result["parser_completeness"]="not asserted: upstream may recover a partial parse without a completeness verdict";
        result["native_verdict"]="metadata recovered by LIEF; not a loader acceptance or runtime behavior verdict";
        result["status"]="completed";
        if(operation=="inventory"){
            result["inventory"]={{"size",data.size()},{"entrypoint",binary.entrypoint()},
                {"section_count",binary.sections().size()},{"signature_verification_performed",false}};
            if(pe){result["inventory"]["machine"]=static_cast<unsigned>(pe->header().machine());result["inventory"]["optional_header_magic"]=static_cast<unsigned>(pe->type());result["inventory"]["image_base"]=pe->optional_header().imagebase();}
            else {result["inventory"]["machine"]=static_cast<unsigned>(elf->header().machine_type());result["inventory"]["elf_class"]=static_cast<unsigned>(elf->header().identity_class());result["inventory"]["file_type"]=static_cast<unsigned>(elf->header().file_type());}
            return result;
        }
        J items=J::array();std::size_t seen=0;bool scan_complete=true;
        auto emit=[&](J item){
            const auto ordinal=seen++;
            if(ordinal<static_cast<std::size_t>(offset)||items.size()>=static_cast<std::size_t>(limit))return;
            item["native_ordinal"]=ordinal;items.push_back(std::move(item));
        };
        auto range=[&](std::uint64_t start,std::uint64_t size){return start<=data.size()&&size<=data.size()-start;};
        if(operation=="sections"){
            auto section=[&](const auto& s,bool has_file_bytes,J extra){
                name_field(extra,s.name());extra["file_offset"]=s.offset();extra["declared_size"]=s.size();extra["virtual_address_native"]=s.virtual_address();
                extra["file_backed"]=has_file_bytes;extra["file_range_valid"]=has_file_bytes&&range(s.offset(),s.size());
                if(extra["file_range_valid"]==true)extra["location"]={{"address_space","file"},{"address",s.offset()}};
                emit(std::move(extra));
            };
            if(pe)for(const auto& s:pe->sections())section(s,true,{{"characteristics",s.characteristics()},{"virtual_size",s.virtual_size()},{"virtual_address_space","rva"}});
            else for(const auto& s:elf->sections())section(s,s.type()!=LIEF::ELF::Section::TYPE::NOBITS,{{"type",static_cast<unsigned>(s.type())},{"flags",s.flags()},{"virtual_address_space","elf_link_time"}});
        }else if(operation=="libraries"){
            for(const auto& library:binary.imported_libraries()){J item;name_field(item,library);item["resolution_performed"]=false;emit(std::move(item));}
        }else if(operation=="notes"){
            if(!elf)throw std::runtime_error("notes is an ELF operation");
            for(const auto& note:elf->notes()){
                const auto bytes=note.description();J item{{"native_type",note.original_type()},{"description_size",bytes.size()},
                    {"description_sha256",sha256_text(std::string_view(reinterpret_cast<const char*>(bytes.data()),bytes.size()))}};
                name_field(item,note.name());name_field(item,note.section_name(),"section_name");
                if(bytes.size()<=256){std::string hex;constexpr char digits[]="0123456789abcdef";for(auto c:bytes){hex+=digits[c>>4];hex+=digits[c&15];}item["description_hex"]=hex;}
                else item["description_omitted"]=true;
                emit(std::move(item));
            }
        }else if(operation=="resources"){
            if(!pe)throw std::runtime_error("resources is a PE operation");
            std::size_t nodes=0;
            std::function<void(const LIEF::PE::ResourceNode&,J,unsigned)> visit;
            visit=[&](const auto& node,J path,unsigned depth){
                if(nodes>=65536||depth>32){scan_complete=false;return;}++nodes;
                J key{{"id",node.id()},{"named",node.has_name()}};if(node.has_name())name_field(key,node.utf8_name());
                if(depth)path.push_back(std::move(key));
                if(const auto* leaf=node.template cast<LIEF::PE::ResourceData>()){
                    const auto content=leaf->content();const auto start=leaf->offset();
                    const bool verified=range(start,content.size())&&std::equal(content.begin(),content.end(),data.begin()+start);
                    J item{{"path",path},{"code_page",leaf->code_page()},{"file_offset",start},{"size",content.size()},
                        {"content_sha256",sha256_text(std::string_view(reinterpret_cast<const char*>(content.data()),content.size()))},
                        {"file_range_verified",verified},{"content_omitted",true}};
                    if(verified)item["location"]={{"address_space","file"},{"address",start}};
                    emit(std::move(item));
                }
                for(const auto& child:node.childs()){if(nodes>=65536){scan_complete=false;break;}visit(child,path,depth+1);}
            };
            if(pe->resources())visit(*pe->resources(),J::array(),0);
            result["resource_nodes_scanned"]=nodes;
        }
        result[operation]=std::move(items);
        auto finish=[&]{const auto delivered=result[operation].size();const auto next=static_cast<std::size_t>(offset)+delivered;
            result["page"]={{"offset",offset},{"returned",delivered},{"parsed_items_scanned",seen},{"scan_complete",scan_complete},
                {"next_offset",next<seen&&delivered?J(next):J(nullptr)},{"more",next<seen||!scan_complete}};
            result["status"]=(next<seen||!scan_complete)?"partial":"completed";
        };
        finish();
        while(result.dump().size()>static_cast<std::size_t>(output)-1024&&!result[operation].empty()){
            result[operation].erase(result[operation].end()-1);finish();result["output_limited"]=true;
        }
        if(result.value("output_limited",false)&&result[operation].empty()){
            result["status"]="partial";result["diagnostic"]="First selected item exceeds output budget; increase output_bytes";
        }
        return result;
#else
        (void)request;throw std::runtime_error("LIEF static SDK unavailable; stage tools/bootstrap-lief.ps1 and rebuild");
#endif
    }catch(const std::exception& error){result["status"]="failed";result["diagnostic"]=std::string(error.what()).substr(0,1024);return result;}
}
}
