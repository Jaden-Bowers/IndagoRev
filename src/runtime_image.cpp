#include "indago/runtime.hpp"
#include <charconv>
#include <fstream>
#include <limits>

namespace indago {
std::uint64_t runtime_number(const RuntimeJson &v) {
  if (v.is_number_unsigned())
    return v.get<std::uint64_t>();
  if (v.is_number_integer() && v.get<std::int64_t>() >= 0)
    return v.get<std::uint64_t>();
  if (!v.is_string())
    throw std::runtime_error(
        "expected unsigned integer or hexadecimal address");
  auto s = v.get<std::string>();
  int base = 10;
  if (s.starts_with("0x")) {
    s.erase(0, 2);
    base = 16;
  }
  std::uint64_t n{};
  auto r = std::from_chars(s.data(), s.data() + s.size(), n, base);
  if (s.empty() || r.ec != std::errc{} || r.ptr != s.data() + s.size())
    throw std::runtime_error("invalid runtime integer");
  return n;
}
RuntimeJson runtime_image(const fs::path &file) {
  std::ifstream in(file, std::ios::binary);
  if (!in)
    throw std::runtime_error("cannot read module image: " + file.string());
  const auto size = fs::file_size(file);
  auto read = [&](std::uint64_t at, unsigned bytes) {
    if (at > size || bytes > size - at)
      throw std::runtime_error("truncated image header");
    in.clear();
    in.seekg(static_cast<std::streamoff>(at));
    unsigned char b[8]{};
    in.read(reinterpret_cast<char *>(b), bytes);
    if (!in)
      throw std::runtime_error("image read failed");
    std::uint64_t n = 0;
    for (unsigned i = 0; i < bytes; ++i)
      n |= std::uint64_t(b[i]) << (8 * i);
    return n;
  };
  RuntimeJson j;
  auto magic = read(0, 4);
  if ((magic & 65535) == 0x5a4d) {
    auto pe = read(0x3c, 4);
    if (read(pe, 4) != 0x4550)
      throw std::runtime_error("invalid PE signature");
    auto machine = read(pe + 4, 2);
    auto opt = pe + 24;
    bool x64 = read(opt, 2) == 0x20b;
    if (machine != 0x14c && machine != 0x8664)
      throw std::runtime_error("runtime supports only x86/x64");
    auto base = read(opt + (x64 ? 24 : 28), x64 ? 8 : 4);
    j = {{"format", "PE"},
         {"arch", x64 ? "x64" : "x86"},
         {"image_base", hex_address(base)},
         {"entry", hex_address(base + read(opt + 16, 4))},
         {"image_size", read(opt + 56, 4)},
         {"segments", RuntimeJson::array()}};
  } else if (magic == 0x464c457f) {
    auto cls = read(4, 1);
    if ((cls != 1 && cls != 2) || read(5, 1) != 1)
      throw std::runtime_error("unsupported ELF encoding");
    auto machine = read(18, 2);
    if (machine != 3 && machine != 62)
      throw std::runtime_error("runtime supports only x86/x64");
    bool x64 = cls == 2;
    auto ph = read(x64 ? 32 : 28, x64 ? 8 : 4), n = read(x64 ? 56 : 44, 2),
         stride = read(x64 ? 54 : 42, 2);
    if (n > 1024)
      throw std::runtime_error("ELF header budget exceeded");
    auto base = UINT64_MAX, end = std::uint64_t{};
    RuntimeJson segments = RuntimeJson::array();
    for (std::uint64_t i = 0; i < n; ++i) {
      auto p = ph + i * stride;
      if (read(p, 4) != 1)
        continue;
      auto off = read(p + (x64 ? 8 : 4), x64 ? 8 : 4),
           va = read(p + (x64 ? 16 : 8), x64 ? 8 : 4),
           mem = read(p + (x64 ? 40 : 20), x64 ? 8 : 4);
      if (mem > UINT64_MAX - va)
        throw std::runtime_error("ELF range overflow");
      base = std::min(base, va & ~std::uint64_t(4095));
      end = std::max(end, va + mem);
      segments.push_back({{"va", hex_address(va)},
                          {"file_offset", hex_address(off)},
                          {"mem_size", mem}});
    }
    if (base == UINT64_MAX)
      throw std::runtime_error("ELF has no load segments");
    j = {{"format", "ELF"},
         {"arch", x64 ? "x64" : "x86"},
         {"image_base", hex_address(base)},
         {"entry", hex_address(read(24, x64 ? 8 : 4))},
         {"image_size", end - base},
         {"segments", segments}};
  } else
    throw std::runtime_error("runtime requires PE or ELF");
  return j;
}
} // namespace indago
