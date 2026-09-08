#include "../src/payload_codec.hpp"
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
using Bytes=std::vector<unsigned char>;
Bytes compress(const std::string& raw){
    std::unique_ptr<ZSTD_CCtx,decltype(&ZSTD_freeCCtx)> context(ZSTD_createCCtx(),ZSTD_freeCCtx);
    ZSTD_CCtx_setParameter(context.get(),ZSTD_c_checksumFlag,1);
    Bytes result(ZSTD_compressBound(raw.size()));
    const auto size=ZSTD_compress2(context.get(),result.data(),result.size(),raw.data(),raw.size());
    if(ZSTD_isError(size))throw std::runtime_error("Test frame encoding failed");result.resize(size);return result;
}
template<class F>void rejects(F f){try{f();}catch(const std::exception&){return;}throw std::runtime_error("Invalid payload accepted");}
int main(){try{
    for(const auto& raw:{std::string{},std::string("small\0binary",12),std::string(1024*1024,'x')}){
        const auto packed=compress(raw);std::ostringstream decoded;
        indago::payload::decode(decoded,packed,raw.size(),true);
        if(decoded.str()!=raw)throw std::runtime_error("Lossless round trip failed");
        std::ostringstream direct;indago::payload::decode(direct,{reinterpret_cast<const unsigned char*>(raw.data()),raw.size()},raw.size(),false);
        if(direct.str()!=raw)throw std::runtime_error("Raw representation changed");
        rejects([&]{std::ostringstream out;indago::payload::decode(out,packed,raw.size()+1,true);});
        auto trailing=packed;trailing.push_back(0);rejects([&]{std::ostringstream out;indago::payload::decode(out,trailing,raw.size(),true);});
        auto truncated=packed;truncated.pop_back();rejects([&]{std::ostringstream out;indago::payload::decode(out,truncated,raw.size(),true);});
        auto corrupt=packed;corrupt.back()^=0x80;rejects([&]{std::ostringstream out;indago::payload::decode(out,corrupt,raw.size(),true);});
        auto multiple=packed;multiple.insert(multiple.end(),packed.begin(),packed.end());rejects([&]{std::ostringstream out;indago::payload::decode(out,multiple,raw.size(),true);});
    }
    rejects([]{std::ostringstream out;indago::payload::decode(out,{},1,false);});
    std::unique_ptr<ZSTD_CCtx,decltype(&ZSTD_freeCCtx)> context(ZSTD_createCCtx(),ZSTD_freeCCtx);
    const std::string wide(16777216,'w');Bytes encoded(ZSTD_compressBound(wide.size()));
    ZSTD_CCtx_setParameter(context.get(),ZSTD_c_windowLog,24);
    auto n=ZSTD_compress2(context.get(),encoded.data(),encoded.size(),wide.data(),wide.size());
    if(ZSTD_isError(n))throw std::runtime_error("Wide test frame encoding failed");encoded.resize(n);
    rejects([&]{std::ostringstream out;indago::payload::decode(out,encoded,wide.size(),true);});
    ZSTD_CCtx_reset(context.get(),ZSTD_reset_session_and_parameters);ZSTD_CCtx_setParameter(context.get(),ZSTD_c_contentSizeFlag,0);
    encoded.resize(ZSTD_compressBound(wide.size()));n=ZSTD_compress2(context.get(),encoded.data(),encoded.size(),wide.data(),wide.size());
    if(ZSTD_isError(n))throw std::runtime_error("Unknown-size test frame encoding failed");encoded.resize(n);
    rejects([&]{std::ostringstream out;indago::payload::decode(out,encoded,wide.size(),true);});
    std::cout<<"{\"status\":\"passed\",\"codec\":\"zstd\",\"lossless\":true,\"corruption_rejected\":true}";
    return 0;
}catch(const std::exception& error){std::cerr<<error.what();return 1;}}
