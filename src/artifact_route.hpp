#pragma once
#include "indago/core.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>

namespace indago {
inline nlohmann::json artifact_route_hint(std::string name) {
    using J=nlohmann::json;
    auto ext=fs::path(name).extension().string();
    std::transform(ext.begin(),ext.end(),ext.begin(),[](unsigned char c){return static_cast<char>(std::tolower(c));});
    static const std::map<std::string,std::pair<std::string,std::string>> formats{
      {".exe",{"pe_candidate","xair/ilspy inventory"}},{".dll",{"pe_candidate","xair/ilspy inventory"}},
      {".so",{"elf_candidate","xair inventory"}},
      {".pcap",{"capture","wireshark packets"}},{".pcapng",{"capture","wireshark packets"}},
      {".py",{"python","artifact read; bounded helper reconstruction"}},
      {".js",{"javascript","artifact read; bounded helper reconstruction"}},{".html",{"web_document","artifact read"}},
      {".php",{"php","artifact read; dedicated PHP execution adapter required"}},
      {".apk",{"android_package","ilspy artifact; transform container_member; Ghidra Dalvik"}},
      {".jar",{"java_archive","ilspy artifact; transform container_member; Ghidra JVM"}},
      {".class",{"jvm_class_candidate","ghidra functions/decompile; validate JVM loader"}},
      {".dex",{"dex_candidate","ghidra functions/decompile; validate Dalvik loader"}},
      {".tpk",{"tizen_package","bounded archive preparation; inspect embedded assemblies/native code"}},
      {".pdf",{"pdf","ilspy artifact PDF pages/objects"}},{".doc",{"office_document","ilspy artifact OLE streams; macro semantics via bounded helper"}},
      {".xls",{"office_document","ilspy artifact OLE streams; formula semantics require reconstruction"}},
      {".wasm",{"wasm","ilspy artifact WABT validation/disassembly"}},{".v",{"verilog","artifact read; bounded HDL simulation adapter required"}},
      {".yara",{"yara_constraints","artifact read; bounded solver/helper reconstruction"}},
      {".nes",{"nes_rom","dedicated 6502/NES adapter required"}},{".hex",{"intel_hex_candidate","confirm record checksums and architecture before routing"}},
      {".img",{"disk_image","identify filesystem and machine before emulation"}},{".dsk",{"disk_image","identify filesystem and machine before emulation"}},
      {".vmdk",{"virtual_disk","bounded disk adapter required"}},{".tap",{"tape_image","identify tape format and machine before emulation"}},
      {".xnb",{"game_resource","dedicated XNB reader required"}},
      {".zip",{"archive","bounded archive preparation"}},{".tar",{"archive","bounded archive preparation"}},
      {".pdb",{"debug_symbols","confirm portable/native PDB and matching module identity"}},
      {".dylib",{"macho_candidate","LIEF/architecture support must be checked"}}};
    auto i=formats.find(ext);
    return {{"kind",i==formats.end()?"unclassified":i->second.first},
      {"route",i==formats.end()?"artifact read; classify bytes before selecting an engine":i->second.second},
      {"basis","filename_hint_only"},{"semantic_support_confirmed",false},{"execution_authorized",false}};
}
inline nlohmann::json artifact_route(const TargetRecord &target) {
    using J=nlohmann::json;
    std::ifstream file(target.object_path,std::ios::binary);if(!file)throw std::runtime_error("artifact unreadable");
    std::string bytes(65536,'\0');file.read(bytes.data(),bytes.size());bytes.resize(static_cast<size_t>(file.gcount()));
    auto out=artifact_route_hint(target.display_name);out["schema"]="indago.artifact-route.v1";
    out["artifact_sha256"]=target.sha256;out["prefix_bytes"]=bytes.size();out["prefix_sha256"]=sha256_text(bytes);
    auto magic=[&](std::string_view value){return bytes.starts_with(value);};
    std::string kind,route;
    if(magic(std::string_view("\x7f" "ELF",4))){kind="elf";route="xair inventory; verify machine support";}
    else if(magic("MZ")){kind="pe_candidate";route="xair inventory; ilspy inventory if managed";
      auto u32=[&](size_t p)->uint32_t{if(p>bytes.size()||bytes.size()-p<4)throw std::runtime_error("truncated PE header");return static_cast<unsigned char>(bytes[p])|(uint32_t(static_cast<unsigned char>(bytes[p+1]))<<8)|(uint32_t(static_cast<unsigned char>(bytes[p+2]))<<16)|(uint32_t(static_cast<unsigned char>(bytes[p+3]))<<24);};
      try{size_t pe=u32(0x3c);if(pe+26<=bytes.size()&&bytes.compare(pe,4,std::string("PE\0\0",4))==0){kind="pe";auto optional=pe+24;bool plus=(u32(optional)&0xffff)==0x20b;auto count=optional+(plus?108:92);auto clr=optional+(plus?112:96)+14*8;
        if(u32(count)>14&&u32(clr)&&u32(clr+4)>=72){kind="managed_pe";route="ilspy inventory/references/methods; explicit imported dependencies";}}}catch(const std::exception&){out["header_status"]="partial";}
    }
    else if(magic("%PDF-")){kind="pdf";route="ilspy artifact PDF pages/objects; do not execute active content";}
    else if(magic(std::string_view("\0asm",4))){kind="wasm";route="ilspy artifact WABT validation/disassembly";}
    else if(magic(std::string_view("dex\n",4))){kind="dex";route="ghidra functions/decompile (Dalvik)";}
    else if(magic(std::string_view("\xca\xfe\xba\xbe",4))){kind="class_or_fat_macho_candidate";route="Ghidra loader validation required; magic alone is ambiguous";}
    else if(magic(std::string_view("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",8))){kind="ole_container";route="ilspy artifact structured streams; never execute macros automatically";}
    else if(magic(std::string_view("PK\x03\x04",4))){kind="zip_container";route="bounded archive preparation; classify children; APK/JAR identity not confirmed by ZIP signature";}
    else if(magic(std::string_view("\xd4\xc3\xb2\xa1",4))||magic(std::string_view("\xa1\xb2\xc3\xd4",4))||magic(std::string_view("\x0a\x0d\x0d\x0a",4))){kind="capture";route="wireshark packets";}
    if(!kind.empty()){out["kind"]=kind;out["route"]=route;out["basis"]="bounded_signature_probe; parser validation still required";}
    if(sha256_file(target.object_path)!=target.sha256)throw std::runtime_error("Artifact changed during routing");
    out["automatic_execution"]=false;return out;
}
}
