#pragma once
#include "indago/core.hpp"
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>
#endif

namespace indago {
// Shared by metadata/content publishers. Retention takes the exclusive side;
// a busy lease fails explicitly rather than racing an in-flight publication.
class StorageLease {
#ifdef _WIN32
  HANDLE handle_ = INVALID_HANDLE_VALUE;
  OVERLAPPED overlap_{};
#else
  int handle_ = -1;
#endif
public:
  explicit StorageLease(const fs::path &root, bool exclusive = false) {
    auto path = root / "storage.lease";
#ifdef _WIN32
    handle_ = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                          OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (handle_ == INVALID_HANDLE_VALUE)
      throw std::runtime_error("storage lease unavailable");
    if (!LockFileEx(handle_,
                    LOCKFILE_FAIL_IMMEDIATELY |
                        (exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0),
                    0, 1, 0, &overlap_)) {
      CloseHandle(handle_);
      handle_ = INVALID_HANDLE_VALUE;
      throw std::runtime_error(
          "storage busy: publication/retention lease conflict");
    }
#else
    handle_ = open(path.c_str(), O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    if (handle_ < 0)
      throw std::runtime_error("storage lease unavailable");
    if (flock(handle_, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB) != 0) {
      close(handle_);
      handle_ = -1;
      throw std::runtime_error(
          "storage busy: publication/retention lease conflict");
    }
#endif
  }
  StorageLease(const StorageLease &) = delete;
  ~StorageLease() {
#ifdef _WIN32
    if (handle_ != INVALID_HANDLE_VALUE) {
      UnlockFileEx(handle_, 0, 1, 0, &overlap_);
      CloseHandle(handle_);
    }
#else
    if (handle_ >= 0) {
      flock(handle_, LOCK_UN);
      close(handle_);
    }
#endif
  }
};
} // namespace indago
