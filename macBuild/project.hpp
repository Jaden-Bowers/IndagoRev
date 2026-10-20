#pragma once
#include "json.hpp"
#include <filesystem>
#include <string>
#include <vector>

// This small milestone uses files rather than the x64 core's engine-dependent
// database. Each project directory is named by the original input's SHA-256.
namespace macbuild {
namespace fs = std::filesystem;
using Json = nlohmann::json;
using Bytes = std::vector<unsigned char>;
struct Slice {
  std::size_t offset, size;
  bool universal;
};
struct Project {
  fs::path directory;
  Json metadata;
};
// Bounded, in-memory reader for small documents/tools, not imported binaries.
Bytes ReadBytes(const fs::path& file, std::size_t limit = 64 * 1024 * 1024);
std::string Sha256(const Bytes& bytes);
Slice Arm64Slice(const Bytes& bytes);
void WriteAtomic(const fs::path& destination, const std::string& text);
Project Import(const fs::path& file, const fs::path& workspace);
Project LoadProject(const fs::path& directory);
Json Capabilities();
} // namespace macbuild
