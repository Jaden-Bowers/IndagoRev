#include "file_io.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <algorithm>
#include <cerrno>
#include <fcntl.h>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace macbuild {
BinaryFile::BinaryFile(const fs::path& path) {
  // Inspect the opened descriptor, so replacing the pathname cannot redirect
  // later reads to a different file. O_NONBLOCK lets us reject pipes promptly.
  descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (descriptor < 0) throw std::runtime_error("Could not open binary: " + path.string());
  struct stat info{};
  if (fstat(descriptor, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 0 ||
      static_cast<std::uintmax_t>(info.st_size) > std::numeric_limits<std::size_t>::max()) {
    close(descriptor);
    throw std::runtime_error("Expected a readable regular binary file: " + path.string());
  }
  length = static_cast<std::size_t>(info.st_size);
}

BinaryFile::~BinaryFile() { close(descriptor); }

void BinaryFile::Read(std::size_t offset, std::span<unsigned char> destination) const {
  if (offset > length || destination.size() > length - offset)
    throw std::runtime_error("Binary read is outside the file bounds.");
  while (!destination.empty()) {
    const auto count = pread(descriptor, destination.data(), destination.size(), offset);
    if (count < 0 && errno == EINTR) continue;
    if (count <= 0) throw std::runtime_error("Binary read failed or the file was truncated.");
    offset += count;
    destination = destination.subspan(count);
  }
}

unsigned char BinaryFile::operator[](std::size_t offset) const {
  if (offset >= length) throw std::runtime_error("Truncated binary header.");
  if (!pageSize || offset < pageStart || offset - pageStart >= pageSize) {
    pageStart = offset - offset % page.size();
    pageSize = std::min(page.size(), length - pageStart);
    Read(pageStart, std::span(page).first(pageSize));
  }
  return page[offset - pageStart];
}

std::string BinaryFile::Transfer(std::size_t offset, std::size_t count, int output) const {
  if (offset > length || count > length - offset)
    throw std::runtime_error("Binary range is outside the file bounds.");
  CC_SHA256_CTX digest;
  CC_SHA256_Init(&digest);
  // CC_SHA256_Update accepts a 32-bit length, so chunking also avoids truncating
  // the hash length for files larger than 4 GiB.
  Bytes buffer(1024 * 1024);
  while (count) {
    const auto amount = std::min(count, buffer.size());
    Read(offset, std::span(buffer).first(amount));
    CC_SHA256_Update(&digest, buffer.data(), static_cast<CC_LONG>(amount));
    if (output >= 0) {
      std::size_t done = 0;
      while (done < amount) {
        const auto written = write(output, buffer.data() + done, amount - done);
        if (written < 0 && errno == EINTR) continue;
        if (written <= 0) throw std::runtime_error("Binary copy failed; check available disk space.");
        done += written;
      }
    }
    offset += amount;
    count -= amount;
  }
  struct stat info{};
  if (fstat(descriptor, &info) != 0 || info.st_size < 0 ||
      static_cast<std::uintmax_t>(info.st_size) != length)
    throw std::runtime_error("Binary changed size while being read.");
  unsigned char hash[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256_Final(hash, &digest);
  std::ostringstream text;
  for (auto value : hash) text << std::hex << std::setw(2) << std::setfill('0') << int(value);
  return text.str();
}

std::string BinaryFile::Hash(std::size_t offset, std::size_t count) const {
  return Transfer(offset, count, -1);
}

void BinaryFile::CopyAtomic(const fs::path& destination, std::size_t offset,
                            std::size_t count, const std::string& expectedHash) const {
  fs::create_directories(destination.parent_path());
  auto temporary = destination.string() + ".XXXXXX";
  int output = mkstemp(temporary.data());
  if (output < 0) throw std::runtime_error("Could not create a temporary binary copy.");
  try {
    if (Transfer(offset, count, output) != expectedHash)
      throw std::runtime_error("Binary changed during import; please try again.");
    if (fsync(output) != 0) throw std::runtime_error("Could not flush binary copy.");
    const auto closed = close(output);
    output = -1;
    if (closed != 0 || rename(temporary.c_str(), destination.c_str()) != 0)
      throw std::runtime_error("Could not publish binary copy.");
  } catch (...) {
    if (output >= 0) close(output);
    unlink(temporary.c_str());
    throw;
  }
}
} // namespace macbuild
