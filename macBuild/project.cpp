#include "project.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <unistd.h>

namespace macbuild {
namespace {
// Read integers explicitly: a universal Mach-O header is big-endian, while
// the supported ARM64 slice is little-endian. Host byte order is irrelevant.
std::uint64_t Number(const Bytes& b, std::size_t at, unsigned count, bool big) {
  if (at > b.size() || count > b.size() - at)
    throw std::runtime_error("Truncated Mach-O header.");
  std::uint64_t value = 0;
  for (unsigned i = 0; i < count; ++i)
    value |= std::uint64_t(b[at + i]) << (8 * (big ? count - 1 - i : i));
  return value;
}
void CheckThin(const Bytes& b, std::size_t start, std::size_t size) {
  if (size < 32 || start > b.size() || size > b.size() - start)
    throw std::runtime_error("Invalid Mach-O slice bounds.");
  if (Number(b, start, 4, false) != 0xfeedfacf ||
      Number(b, start + 4, 4, false) != 0x0100000c)
    throw std::runtime_error("Select an ARM64 Mach-O file; x64, PE and ELF are unsupported.");
  // arm64e adds pointer-authentication ABI behavior. Do not claim it is already
  // qualified simply because it shares ARM64's CPU type.
  if ((Number(b, start + 8, 4, false) & 0x00ffffff) != 0)
    throw std::runtime_error("This milestone supports generic arm64, not arm64e.");
  const auto kind = Number(b, start + 12, 4, false);
  if (kind != 2 && kind != 6 && kind != 8)
    throw std::runtime_error("Expected a Mach-O executable, dynamic library or bundle.");
  const auto count = Number(b, start + 16, 4, false);
  const auto length = Number(b, start + 20, 4, false);
  if (length > size - 32 || count > length / 8)
    throw std::runtime_error("Invalid Mach-O load-command table.");
  std::size_t cursor = start + 32;
  for (std::uint64_t i = 0; i < count; ++i) {
    if (cursor > start + 32 + length || start + 32 + length - cursor < 8)
      throw std::runtime_error("Truncated Mach-O load command.");
    const auto commandSize = Number(b, cursor + 4, 4, false);
    if (commandSize < 8 || commandSize % 8 || commandSize > start + 32 + length - cursor)
      throw std::runtime_error("Invalid Mach-O load-command size.");
    cursor += commandSize;
  }
  if (cursor != start + 32 + length)
    throw std::runtime_error("Mach-O load-command count does not match its size.");
}
} // namespace

Bytes ReadBytes(const fs::path& file, std::size_t limit) {
  if (!fs::is_regular_file(file) || fs::file_size(file) > limit)
    throw std::runtime_error("Expected a regular file within the size limit: " + file.string());
  std::ifstream stream(file, std::ios::binary);
  Bytes bytes(static_cast<std::size_t>(fs::file_size(file)));
  if (!stream.read(reinterpret_cast<char*>(bytes.data()), bytes.size()))
    throw std::runtime_error("Could not read file: " + file.string());
  if (stream.peek() != std::char_traits<char>::eof())
    throw std::runtime_error("File changed size while being read.");
  return bytes;
}

std::string Sha256(const Bytes& bytes) {
  unsigned char hash[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256(bytes.data(), static_cast<CC_LONG>(bytes.size()), hash);
  std::ostringstream out;
  for (auto value : hash) out << std::hex << std::setw(2) << std::setfill('0') << int(value);
  return out.str();
}

Slice Arm64Slice(const Bytes& bytes) {
  const auto magic = Number(bytes, 0, 4, true);
  if (magic != 0xcafebabe && magic != 0xcafebabf) {
    CheckThin(bytes, 0, bytes.size());
    return {0, bytes.size(), false};
  }
  const auto count = Number(bytes, 4, 4, true);
  const std::size_t stride = magic == 0xcafebabf ? 32 : 20;
  if (!count || count > 64 || count > (bytes.size() - 8) / stride)
    throw std::runtime_error("Invalid universal Mach-O slice table.");
  Slice selected{};
  std::vector<Slice> slices;
  for (std::size_t i = 0; i < count; ++i) {
    const auto at = 8 + i * stride;
    const auto offset = Number(bytes, at + 8, stride == 32 ? 8 : 4, true);
    const auto size = Number(bytes, at + (stride == 32 ? 16 : 12), stride == 32 ? 8 : 4, true);
    const auto align = Number(bytes, at + (stride == 32 ? 24 : 16), 4, true);
    if (!size || offset < 8 + count * stride || offset > bytes.size() ||
        size > bytes.size() - offset || align > 31 || offset % (std::uint64_t(1) << align))
      throw std::runtime_error("Invalid universal slice extent/alignment.");
    for (auto other : slices)
      if (offset < other.offset + other.size && other.offset < offset + size)
        throw std::runtime_error("Overlapping universal slices.");
    slices.push_back({static_cast<std::size_t>(offset), static_cast<std::size_t>(size), true});
    if (Number(bytes, at, 4, true) == 0x0100000c &&
        (Number(bytes, at + 4, 4, true) & 0x00ffffff) == 0) {
      if (selected.size) throw std::runtime_error("Ambiguous ARM64 slices.");
      CheckThin(bytes, offset, size);
      selected = slices.back();
    }
  }
  if (!selected.size) throw std::runtime_error("No supported ARM64 slice in this file.");
  return selected;
}

void WriteAtomic(const fs::path& destination, const std::string& text) {
  fs::create_directories(destination.parent_path());
  // mkstemp avoids clobbering another writer's temporary file. Rename publishes
  // the complete document in one step, so a reader never sees half-written JSON.
  auto name = destination.string() + ".XXXXXX";
  int fd = mkstemp(name.data());
  if (fd < 0) throw std::runtime_error("Could not create a temporary project file.");
  std::size_t done = 0;
  while (done < text.size()) {
    auto count = write(fd, text.data() + done, text.size() - done);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) { close(fd); unlink(name.c_str()); throw std::runtime_error("Project write failed."); }
    done += count;
  }
  const bool flushed = fsync(fd) == 0;
  const bool closed = close(fd) == 0;
  if (!flushed || !closed || rename(name.c_str(), destination.c_str()) != 0) {
    unlink(name.c_str()); throw std::runtime_error("Could not publish project file.");
  }
}

Project Import(const fs::path& file, const fs::path& workspace) {
  const auto original = ReadBytes(file);
  const auto slice = Arm64Slice(original);
  const auto hash = Sha256(original);
  Project p{fs::absolute(workspace) / hash, {}};
  if (fs::exists(p.directory / "project.json")) return LoadProject(p.directory);
  Bytes selected(original.begin() + slice.offset, original.begin() + slice.offset + slice.size);
  p.metadata = {{"schema", "indago.mac-project.v1"}, {"name", file.filename().string()},
      {"architecture", "arm64"}, {"format", "Mach-O"}, {"sha256", hash},
      {"slice_sha256", Sha256(selected)}, {"slice_offset", slice.offset},
      {"slice_size", slice.size}, {"universal", slice.universal}, {"target_executed", false}};
  WriteAtomic(p.directory / "original.bin", std::string(original.begin(), original.end()));
  WriteAtomic(p.directory / "arm64.macho", std::string(selected.begin(), selected.end()));
  WriteAtomic(p.directory / "notes.md", "# Analysis notes\n\n");
  WriteAtomic(p.directory / "project.json", p.metadata.dump(2));
  return p;
}

Project LoadProject(const fs::path& directory) {
  auto data = ReadBytes(directory / "project.json", 65536);
  Project p{fs::absolute(directory), Json::parse(data)};
  if (p.metadata.at("schema") != "indago.mac-project.v1" || p.metadata.at("architecture") != "arm64")
    throw std::runtime_error("Unsupported project schema or architecture.");
  const auto original = ReadBytes(directory / "original.bin");
  const auto slice = Arm64Slice(original);
  const auto selected = ReadBytes(directory / "arm64.macho");
  if (Sha256(original) != p.metadata.at("sha256").get<std::string>() ||
      Sha256(selected) != p.metadata.at("slice_sha256").get<std::string>() ||
      slice.offset != p.metadata.at("slice_offset") || slice.size != p.metadata.at("slice_size") ||
      selected != Bytes(original.begin() + slice.offset, original.begin() + slice.offset + slice.size))
    throw std::runtime_error("Project input integrity check failed.");
  return p;
}

} // namespace macbuild
