#include "indago/core.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace indago {
namespace {

constexpr std::array<std::uint32_t, 64> constants{
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

constexpr std::uint32_t rotate_right(std::uint32_t value, unsigned count) {
    return (value >> count) | (value << (32U - count));
}

class Sha256 {
public:
    void update(const std::uint8_t* data, std::size_t length) {
        total_bytes_ += length;
        while (length != 0) {
            const auto count = std::min(length, block_.size() - buffered_);
            std::copy_n(data, count, block_.begin() + static_cast<std::ptrdiff_t>(buffered_));
            buffered_ += count;
            data += count;
            length -= count;
            if (buffered_ == block_.size()) {
                transform(block_.data());
                buffered_ = 0;
            }
        }
    }

    std::array<std::uint8_t, 32> finish() {
        const std::uint64_t bit_length = total_bytes_ * 8U;
        block_[buffered_++] = 0x80;
        if (buffered_ > 56) {
            std::fill(block_.begin() + static_cast<std::ptrdiff_t>(buffered_), block_.end(), std::uint8_t{0});
            transform(block_.data());
            buffered_ = 0;
        }
        std::fill(block_.begin() + static_cast<std::ptrdiff_t>(buffered_), block_.begin() + 56, std::uint8_t{0});
        for (unsigned i = 0; i < 8; ++i) block_[63 - i] = static_cast<std::uint8_t>(bit_length >> (i * 8U));
        transform(block_.data());
        std::array<std::uint8_t, 32> result{};
        for (std::size_t i = 0; i < state_.size(); ++i) {
            for (unsigned j = 0; j < 4; ++j) result[i * 4 + j] = static_cast<std::uint8_t>(state_[i] >> (24U - j * 8U));
        }
        return result;
    }

private:
    void transform(const std::uint8_t* data) {
        std::array<std::uint32_t, 64> words{};
        for (std::size_t i = 0; i < 16; ++i) {
            words[i] = (static_cast<std::uint32_t>(data[i*4]) << 24U) |
                       (static_cast<std::uint32_t>(data[i*4+1]) << 16U) |
                       (static_cast<std::uint32_t>(data[i*4+2]) << 8U) | data[i*4+3];
        }
        for (std::size_t i = 16; i < 64; ++i) {
            const auto s0 = rotate_right(words[i-15],7) ^ rotate_right(words[i-15],18) ^ (words[i-15] >> 3U);
            const auto s1 = rotate_right(words[i-2],17) ^ rotate_right(words[i-2],19) ^ (words[i-2] >> 10U);
            words[i] = words[i-16] + s0 + words[i-7] + s1;
        }
        auto [a,b,c,d,e,f,g,h] = state_;
        for (std::size_t i = 0; i < 64; ++i) {
            const auto s1 = rotate_right(e,6) ^ rotate_right(e,11) ^ rotate_right(e,25);
            const auto choice = (e & f) ^ (~e & g);
            const auto temp1 = h + s1 + choice + constants[i] + words[i];
            const auto s0 = rotate_right(a,2) ^ rotate_right(a,13) ^ rotate_right(a,22);
            const auto majority = (a & b) ^ (a & c) ^ (b & c);
            const auto temp2 = s0 + majority;
            h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2;
        }
        state_[0]+=a; state_[1]+=b; state_[2]+=c; state_[3]+=d;
        state_[4]+=e; state_[5]+=f; state_[6]+=g; state_[7]+=h;
    }

    std::array<std::uint32_t,8> state_{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                                       0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    std::array<std::uint8_t,64> block_{};
    std::size_t buffered_{};
    std::uint64_t total_bytes_{};
};

} // namespace

std::string sha256_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("cannot open file for hashing: " + path.string());
    Sha256 hasher;
    // Keep the streaming buffer comfortably below the default Windows stack.
    std::array<std::uint8_t, 64 * 1024> buffer{};
    while (input) {
        input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        hasher.update(buffer.data(), static_cast<std::size_t>(input.gcount()));
    }
    const auto digest = hasher.finish();
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto byte : digest) output << std::setw(2) << static_cast<unsigned>(byte);
    return output.str();
}
std::string sha256_text(std::string_view text) {
    Sha256 hasher;hasher.update(reinterpret_cast<const std::uint8_t*>(text.data()),text.size());
    std::ostringstream output;output<<std::hex<<std::setfill('0');for(auto byte:hasher.finish())output<<std::setw(2)<<static_cast<unsigned>(byte);return output.str();
}

} // namespace indago
