#pragma once
#include <zstd.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <ostream>
#include <span>
#include <stdexcept>

namespace indago::payload {
// Storage codec only. Callers must additionally verify the original raw SHA-256
// before publishing the decoded file. Memory is bounded by an 8 MiB Zstd window
// and a 128 KiB output buffer, independently of the uncompressed file's size.
inline void decode(std::ostream& output,std::span<const unsigned char> stored,
                   std::uint64_t expected_bytes,bool compressed) {
    if(!compressed){
        if(stored.size()!=expected_bytes)throw std::runtime_error("Raw payload size mismatch");
        if(!stored.empty())output.write(reinterpret_cast<const char*>(stored.data()),static_cast<std::streamsize>(stored.size()));
        if(!output)throw std::runtime_error("Raw payload write failed");
        return;
    }
    if(stored.empty()||expected_bytes>536870912)throw std::runtime_error("Compressed payload size outside supported bounds");
    const auto declared=ZSTD_getFrameContentSize(stored.data(),stored.size());
    if(declared==ZSTD_CONTENTSIZE_ERROR||declared==ZSTD_CONTENTSIZE_UNKNOWN||declared!=expected_bytes)
        throw std::runtime_error("Compressed payload frame size mismatch");
    if(ZSTD_getDictID_fromFrame(stored.data(),stored.size())!=0)throw std::runtime_error("Payload dictionaries are unsupported");
    const auto frame_bytes=ZSTD_findFrameCompressedSize(stored.data(),stored.size());
    if(ZSTD_isError(frame_bytes)||frame_bytes!=stored.size())throw std::runtime_error("Payload requires exactly one complete Zstd frame");
    std::unique_ptr<ZSTD_DCtx,decltype(&ZSTD_freeDCtx)> context(ZSTD_createDCtx(),ZSTD_freeDCtx);
    if(!context||ZSTD_isError(ZSTD_DCtx_setParameter(context.get(),ZSTD_d_windowLogMax,23)))throw std::runtime_error("Cannot initialize bounded payload decoder");
    std::array<unsigned char,131072> buffer{};std::uint64_t written=0;
    ZSTD_inBuffer input{stored.data(),stored.size(),0};std::size_t remaining=1;
    while(remaining){
        ZSTD_outBuffer chunk{buffer.data(),buffer.size(),0};const auto before=input.pos;
        remaining=ZSTD_decompressStream(context.get(),&chunk,&input);
        if(ZSTD_isError(remaining)||chunk.pos>expected_bytes-written)throw std::runtime_error("Corrupt or oversized compressed payload");
        output.write(reinterpret_cast<const char*>(buffer.data()),static_cast<std::streamsize>(chunk.pos));
        if(!output)throw std::runtime_error("Decoded payload write failed");
        written+=chunk.pos;
        if(remaining&&input.pos==before&&!chunk.pos)throw std::runtime_error("Incomplete compressed payload");
    }
    if(input.pos!=input.size||written!=expected_bytes)throw std::runtime_error("Decoded payload length mismatch");
}
}
