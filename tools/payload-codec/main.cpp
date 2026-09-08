#include "indago/core.hpp"
#include "../../src/payload_codec.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <random>
#include <vector>
using namespace indago;
using J=nlohmann::json;
int main(int argc,char** argv){try{
    if(argc!=3)throw std::runtime_error("Usage: indago_payload_pack INPUT CACHE_DIRECTORY");
    const fs::path input=fs::absolute(argv[1]),cache=fs::absolute(argv[2]);
    if(!fs::is_regular_file(input)||fs::is_symlink(input))throw std::runtime_error("Regular source payload required");
    const auto size=fs::file_size(input);const auto hash=sha256_file(input);
    if(size<1048576||size>536870912){std::cout<<J{{"status","raw"},{"raw_sha256",hash},{"raw_bytes",size},{"reason","outside selected packing size range"}}.dump();return 0;}
    fs::create_directories(cache);
    const auto scratch=cache/("pack_"+std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())+"_"+std::to_string(std::random_device{}()));
    if(!fs::create_directory(scratch))throw std::runtime_error("Cannot create private packing directory");
    struct Cleanup{fs::path path;~Cleanup(){std::error_code ignored;fs::remove_all(path,ignored);}}cleanup{scratch};
    const auto destination=cache/(hash+".zst"),metadata=cache/(hash+".json");
    const auto packed=scratch/"payload.zst",decoded=scratch/"roundtrip.raw";
    if(!fs::exists(destination)){
        std::unique_ptr<ZSTD_CCtx,decltype(&ZSTD_freeCCtx)> context(ZSTD_createCCtx(),ZSTD_freeCCtx);
        auto require=[](std::size_t status){if(ZSTD_isError(status))throw std::runtime_error(ZSTD_getErrorName(status));};
        if(!context)throw std::runtime_error("Cannot initialize payload compressor");
        require(ZSTD_CCtx_setParameter(context.get(),ZSTD_c_compressionLevel,3));
        require(ZSTD_CCtx_setParameter(context.get(),ZSTD_c_windowLog,23));
        require(ZSTD_CCtx_setParameter(context.get(),ZSTD_c_checksumFlag,1));
        require(ZSTD_CCtx_setPledgedSrcSize(context.get(),size));
        std::ifstream source(input,std::ios::binary);std::ofstream output(packed,std::ios::binary);
        if(!source||!output)throw std::runtime_error("Cannot open payload packing streams");
        std::array<char,131072> read{},write{};
        while(true){
            source.read(read.data(),read.size());if(source.bad()||(source.fail()&&!source.eof()))throw std::runtime_error("Source payload read failed");
            ZSTD_inBuffer in{read.data(),static_cast<std::size_t>(source.gcount()),0};const auto mode=source.eof()?ZSTD_e_end:ZSTD_e_continue;
            std::size_t remaining=1;
            do{ZSTD_outBuffer out{write.data(),write.size(),0};remaining=ZSTD_compressStream2(context.get(),&out,&in,mode);require(remaining);
                output.write(write.data(),static_cast<std::streamsize>(out.pos));if(!output)throw std::runtime_error("Packed payload write failed");
            }while(in.pos<in.size||(mode==ZSTD_e_end&&remaining));
            if(mode==ZSTD_e_end)break;
        }
        output.close();if(!output)throw std::runtime_error("Packed payload close failed");
    }
    const auto candidate=fs::exists(destination)?destination:packed;
    const auto stored_size=fs::file_size(candidate);
    if(stored_size>=size-size/20){std::cout<<J{{"status","raw"},{"raw_sha256",hash},{"raw_bytes",size},{"reason","less than five percent savings"}}.dump();return 0;}
    if(fs::is_symlink(candidate)||stored_size>536870912)throw std::runtime_error("Invalid packed candidate");
    std::vector<unsigned char> bytes(static_cast<std::size_t>(stored_size));std::ifstream stored(candidate,std::ios::binary);
    stored.read(reinterpret_cast<char*>(bytes.data()),static_cast<std::streamsize>(bytes.size()));if(!stored)throw std::runtime_error("Packed candidate read failed");
    {std::ofstream output(decoded,std::ios::binary);payload::decode(output,bytes,size,true);output.close();if(!output)throw std::runtime_error("Roundtrip close failed");}
    if(sha256_file(decoded)!=hash||sha256_file(input)!=hash)throw std::runtime_error("Packed payload roundtrip/source identity mismatch");
    const J manifest{{"schema","indago.packed-payload.v1"},{"codec","zstd"},{"codec_version",ZSTD_versionString()},
        {"raw_sha256",hash},{"raw_bytes",size},{"stored_sha256",sha256_file(candidate)},{"stored_bytes",stored_size},{"roundtrip_verified",true}};
    if(candidate==packed){std::error_code error;fs::create_hard_link(packed,destination,error);if(error&&(!fs::is_regular_file(destination)||sha256_file(destination)!=manifest["stored_sha256"].get<std::string>()))throw std::runtime_error("Packed payload publication conflict");}
    if(fs::exists(metadata)){std::ifstream prior(metadata);if(J::parse(prior)!=manifest)throw std::runtime_error("Packed metadata conflict");}
    else{const auto temp=scratch/"metadata.json";{std::ofstream output(temp);output<<manifest.dump(2);output.close();if(!output)throw std::runtime_error("Packed metadata write failed");}
        std::error_code error;fs::create_hard_link(temp,metadata,error);if(error){std::ifstream prior(metadata);if(!prior||J::parse(prior)!=manifest)throw std::runtime_error("Packed metadata publication conflict");}}
    std::cout<<J{{"status","packed"},{"manifest",manifest}}.dump();return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<'\n';return 1;}}
