#pragma once
#include "project.hpp"
#include <array>
#include <span>

namespace macbuild {
// Large binaries stay on disk. Header parsing caches a small page; hashing and
// copying use fixed-size chunks. Memory use does not grow with the input size.
class BinaryFile {
public:
  explicit BinaryFile(const fs::path& path);
  ~BinaryFile();
  BinaryFile(const BinaryFile&) = delete;
  BinaryFile& operator=(const BinaryFile&) = delete;
  std::size_t size() const { return length; }
  unsigned char operator[](std::size_t offset) const;
  void Read(std::size_t offset, std::span<unsigned char> destination) const;
  std::string Hash(std::size_t offset, std::size_t count) const;
  // Publish only a complete copy whose digest matches the expected input.
  void CopyAtomic(const fs::path& destination, std::size_t offset,
                  std::size_t count, const std::string& expectedHash) const;
private:
  int descriptor = -1;
  std::size_t length = 0;
  mutable std::array<unsigned char, 65536> page{};
  mutable std::size_t pageStart = 0, pageSize = 0;
  std::string Transfer(std::size_t offset, std::size_t count, int output) const;
};
Slice Arm64Slice(const BinaryFile& file);
} // namespace macbuild
